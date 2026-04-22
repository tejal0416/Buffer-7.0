from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Iterable
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy import func
from sqlalchemy.orm import Session

from ir_agent.config import AppConfig
from ir_agent.models import AuditLog, Event, Incident, IncidentEvent
from ir_agent.scoring import score_incident, score_incidents_anomaly
from ir_agent.ueba import compute_ueba
from ir_agent.utils import UnionFind, utcnow


def _link_by_entity(
    uf: UnionFind,
    *,
    entity_to_events: dict[str, list[Event]],
    link_window: timedelta,
) -> None:
    for _entity_value, evts in entity_to_events.items():
        if len(evts) < 2:
            continue
        evts.sort(key=lambda e: e.ts)
        prev = evts[0]
        for cur in evts[1:]:
            if (cur.ts - prev.ts) <= link_window:
                uf.union(prev.id, cur.id)
            prev = cur


def _distinct(values: Iterable[str | None]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        if not v:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def rebuild_incidents(
    db: Session,
    cfg: AppConfig,
    *,
    lookback_minutes: int | None = None,
    rebuild_all: bool = True,
) -> tuple[int, int]:
    # For a full rebuild (demo/ops), include all events unless a lookback override was explicitly provided.
    if rebuild_all and lookback_minutes is None:
        since_ts = datetime(1970, 1, 1, tzinfo=timezone.utc)
    else:
        lookback = lookback_minutes if lookback_minutes is not None else cfg.correlation.lookback_minutes
        since_ts = utcnow() - timedelta(minutes=int(lookback))

    if rebuild_all:
        db.execute(delete(IncidentEvent))
        db.execute(delete(Incident))
        db.flush()

    events = list(db.execute(select(Event).where(Event.ts >= since_ts).order_by(Event.ts.asc())).scalars())

    if not events:
        db.add(AuditLog(action="correlate", data={"events": 0, "incidents": 0}))
        total = 0
        if not rebuild_all:
            total = int(db.execute(select(func.count(Incident.id))).scalar_one())
        return 0, total

    uf = UnionFind.from_items([e.id for e in events])
    link_window = timedelta(minutes=cfg.correlation.link_window_minutes)

    by_host: dict[str, list[Event]] = defaultdict(list)
    by_user: dict[str, list[Event]] = defaultdict(list)
    by_ip: dict[str, list[Event]] = defaultdict(list)

    for e in events:
        if e.host:
            by_host[e.host].append(e)
        if e.username:
            by_user[e.username].append(e)
        if e.ip:
            by_ip[e.ip].append(e)

    _link_by_entity(uf, entity_to_events=by_host, link_window=link_window)
    _link_by_entity(uf, entity_to_events=by_user, link_window=link_window)
    _link_by_entity(uf, entity_to_events=by_ip, link_window=link_window)

    components: dict[int, list[Event]] = defaultdict(list)
    for e in events:
        components[uf.find(e.id)].append(e)

    clusters = [evts for evts in components.values() if len(evts) >= cfg.correlation.min_events_per_incident]
    if not clusters:
        db.add(AuditLog(action="correlate", data={"events": len(events), "incidents": 0}))
        return 0, 0

    # First pass: score clusters and drop obvious noise (minimizes analyst fatigue).
    candidates: list[tuple[list[Event], dict]] = []
    for evts in clusters:
        s = score_incident(evts, cfg)
        has_rule_hits = bool((s.get("evidence") or {}).get("rule_hits"))
        if (not has_rule_hits) and float(s.get("fidelity_score") or 0.0) < 15.0:
            continue
        candidates.append((evts, s))

    if not candidates:
        db.add(AuditLog(action="correlate", data={"events": len(events), "incidents": 0, "note": "noise_filtered"}))
        return 0, 0

    # UEBA across users/hosts using tsfresh + PyOD (offline).
    ueba = compute_ueba(db, since_ts=since_ts, bucket_seconds=300)

    anomaly_scores = score_incidents_anomaly([s["features"] for _evts, s in candidates])

    created = 0
    for (evts, base_score), anomaly in zip(candidates, anomaly_scores, strict=True):
        evts.sort(key=lambda e: e.ts)

        sources = _distinct([e.source for e in evts])
        entities = {
            "hosts": _distinct([e.host for e in evts]),
            "users": _distinct([e.username for e in evts]),
            "ips": _distinct([e.ip for e in evts]),
            "processes": _distinct([e.process for e in evts]),
        }

        # Decide incident type/title based on rules (deterministic).
        incident_type = base_score["incident_type"]
        title = base_score["title"]

        fidelity = base_score["fidelity_score"]
        confidence = base_score["confidence_score"]
        coverage = base_score["coverage_score"]

        # UEBA: entity-level anomaly across the environment (0..1)
        ueba_scores = []
        for u in entities["users"]:
            ueba_scores.append(float(ueba.user_scores.get(u, 0.0)))
        for h in entities["hosts"]:
            ueba_scores.append(float(ueba.host_scores.get(h, 0.0)))
        ueba_score = max(ueba_scores) if ueba_scores else 0.0

        # Blend in anomaly (0..1) as a booster; keep deterministic base as primary.
        fidelity = min(100.0, fidelity + (20.0 * anomaly))
        confidence = min(1.0, confidence + (0.10 * anomaly))

        # Blend in UEBA anomaly as an additional prioritization signal.
        fidelity = min(100.0, fidelity + (15.0 * ueba_score))
        confidence = min(1.0, confidence + (0.10 * ueba_score))

        incident_id = str(uuid4())
        inc = Incident(
            id=incident_id,
            start_ts=evts[0].ts,
            end_ts=evts[-1].ts,
            title=title,
            incident_type=incident_type,
            status="open",
            fidelity_score=float(fidelity),
            confidence_score=float(confidence),
            coverage_score=float(coverage),
            entities=entities,
            sources=sources,
            evidence={
                **base_score["evidence"],
                "anomaly_score": float(anomaly),
                "ueba_score": float(ueba_score),
                "ueba_meta": ueba.meta,
            },
        )
        db.add(inc)
        db.flush()

        for e in evts:
            db.add(IncidentEvent(incident_id=incident_id, event_id=e.id))

        created += 1

    db.add(AuditLog(action="correlate", data={"events": len(events), "incidents": created}))
    total = int(db.execute(select(func.count(Incident.id))).scalar_one())
    return created, total
