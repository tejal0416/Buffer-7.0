from __future__ import annotations

import os
from collections import Counter, defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, load_only

from ir_agent.config import AppConfig, load_config
from ir_agent.correlate import rebuild_incidents
from ir_agent.db import get_db, init_db
from ir_agent.ingest import insert_event
from ir_agent.investigate import investigate_incident
from ir_agent.models import AuditLog, Event, Incident, IncidentEvent, TelemetryStatus
from ir_agent.playbook import generate_playbook
from ir_agent.schema import (
    CorrelateRequest,
    CorrelateResponse,
    EventOut,
    IncidentDetail,
    IncidentSummary,
    IngestBatchResponse,
    IngestEvent,
    IngestRaw,
    IngestResponse,
    PlaybookResponse,
)
from ir_agent.parse_raw import parse_raw
from ir_agent.embeddings import embed_text
from ir_agent.runbooks import list_templates


def _load_app_config() -> AppConfig:
    path = os.environ.get("APP_CONFIG", "config/config.yml")
    return load_config(path)


CFG = _load_app_config()

app = FastAPI(title="IRIS THE SMART CYBER SUIT, the local guard", version="0.1.0")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def ui_index(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    incidents = list_incidents(limit=50, db=db)
    return templates.TemplateResponse("index.html", {"request": request, "incidents": incidents})


@app.get("/charts/incidents/by-type")
def chart_incidents_by_type(db: Session = Depends(get_db)) -> dict:
    rows = list(db.execute(select(Incident.incident_type, Incident.start_ts)))

    by_type: Counter[str] = Counter()
    daily_by_type: dict[str, Counter[str]] = defaultdict(Counter)

    for incident_type, start_ts in rows:
        normalized_type = str(incident_type or "unknown")
        by_type[normalized_type] += 1

        if isinstance(start_ts, datetime):
            d = start_ts.date().isoformat()
            daily_by_type[normalized_type][d] += 1

    labels = [t for t, _ in by_type.most_common()]
    counts = [by_type[t] for t in labels]

    today = datetime.now(timezone.utc).date()
    last_7_days = [(today - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]

    weekly_breakdown: dict[str, dict] = {}
    for t in labels:
        values = [int(daily_by_type[t].get(day, 0)) for day in last_7_days]
        weekly_breakdown[t] = {
            "dates": last_7_days,
            "counts": values,
        }

    return {
        "labels": labels,
        "counts": counts,
        "weekly_breakdown": weekly_breakdown,
    }


@app.post("/ingest", response_model=IngestResponse)
def ingest(e: IngestEvent, db: Session = Depends(get_db)) -> IngestResponse:
    event_id = insert_event(db, e)
    db.add(AuditLog(action="ingest", data={"event_id": event_id, "source": e.source, "event_type": e.event_type}))
    db.commit()
    return IngestResponse(event_id=event_id)


@app.post("/ingest/raw", response_model=IngestResponse)
def ingest_raw(e: IngestRaw, db: Session = Depends(get_db)) -> IngestResponse:
    normalized = parse_raw(e)
    event_id = insert_event(db, normalized)
    db.add(
        AuditLog(
            action="ingest_raw",
            data={"event_id": event_id, "source": normalized.source, "event_type": normalized.event_type},
        )
    )
    db.commit()
    return IngestResponse(event_id=event_id)


@app.post("/ingest/batch", response_model=IngestBatchResponse)
def ingest_batch(events: list[IngestEvent], db: Session = Depends(get_db)) -> IngestBatchResponse:
    event_ids: list[int] = []
    for e in events:
        event_ids.append(insert_event(db, e))
    db.add(AuditLog(action="ingest_batch", data={"inserted": len(event_ids)}))
    db.commit()
    return IngestBatchResponse(inserted=len(event_ids), event_ids=event_ids)


@app.post("/correlate", response_model=CorrelateResponse)
def correlate(req: CorrelateRequest, db: Session = Depends(get_db)) -> CorrelateResponse:
    created, total = rebuild_incidents(
        db,
        CFG,
        lookback_minutes=req.lookback_minutes,
        rebuild_all=req.rebuild_all,
    )
    db.commit()
    return CorrelateResponse(incidents_created=created, incidents_total=total)


def _to_incident_summary(inc: Incident, event_count: int) -> IncidentSummary:
    entities = inc.entities if isinstance(inc.entities, dict) else {}
    return IncidentSummary(
        id=inc.id,
        title=inc.title,
        incident_type=inc.incident_type,
        status=inc.status,
        start_ts=inc.start_ts,  # type: ignore[arg-type]
        end_ts=inc.end_ts,  # type: ignore[arg-type]
        fidelity_score=float(inc.fidelity_score),
        confidence_score=float(inc.confidence_score),
        coverage_score=float(inc.coverage_score),
        event_count=int(event_count),
        sources=list(inc.sources or []),
        entities={
            "hosts": list(entities.get("hosts") or []),
            "users": list(entities.get("users") or []),
            "ips": list(entities.get("ips") or []),
            "processes": list(entities.get("processes") or []),
        },
    )


@app.get("/incidents", response_model=list[IncidentSummary])
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[IncidentSummary]:
    incidents = list(
        db.execute(select(Incident).order_by(Incident.fidelity_score.desc()).limit(int(limit))).scalars()
    )
    out: list[IncidentSummary] = []
    for inc in incidents:
        cnt = db.execute(select(IncidentEvent).where(IncidentEvent.incident_id == inc.id)).scalars().all()
        out.append(_to_incident_summary(inc, event_count=len(cnt)))
    return out


def _to_event_out(e: Event) -> EventOut:
    return EventOut(
        id=e.id,
        timestamp=e.ts,  # type: ignore[arg-type]
        source=e.source,
        event_type=e.event_type,
        severity=int(e.severity),
        host=e.host,
        user=e.username,
        ip=e.ip,
        process=e.process,
        message=e.message,
        raw=dict(e.raw or {}),
    )


def _event_select_without_embedding():
    return select(Event).options(
        load_only(
            Event.id,
            Event.ts,
            Event.source,
            Event.event_type,
            Event.severity,
            Event.host,
            Event.username,
            Event.ip,
            Event.process,
            Event.message,
            Event.raw,
        )
    )


@app.get("/incidents/{incident_id}", response_model=IncidentDetail)
def incident_detail(incident_id: str, db: Session = Depends(get_db)) -> IncidentDetail:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    event_ids = [
        row.event_id
        for row in db.execute(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)).scalars()
    ]
    events = []
    if event_ids:
        events = list(
            db.execute(_event_select_without_embedding().where(Event.id.in_(event_ids)).order_by(Event.ts.asc())).scalars()
        )

    summary = _to_incident_summary(inc, event_count=len(event_ids))
    return IncidentDetail(**summary.model_dump(), evidence=dict(inc.evidence or {}), events=[_to_event_out(e) for e in events])


@app.get("/ui/incidents/{incident_id}", response_class=HTMLResponse)
def ui_incident(request: Request, incident_id: str, db: Session = Depends(get_db)) -> HTMLResponse:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    event_ids = [
        row.event_id
        for row in db.execute(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)).scalars()
    ]
    events = []
    if event_ids:
        events = list(
            db.execute(_event_select_without_embedding().where(Event.id.in_(event_ids)).order_by(Event.ts.asc())).scalars()
        )

    # Generate runbook (do not require LLM). Persist for audit.
    pb = generate_playbook(inc, events, CFG, mode="runbook")
    inc.playbook = pb
    inc.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(action="playbook_ui", data={"incident_id": incident_id, "generated_by": pb.get("generated_by")}))

    inv = investigate_incident(inc, events, CFG)
    db.add(AuditLog(action="investigate_ui", data={"incident_id": incident_id, "status": inv.status}))
    db.commit()

    summary = _to_incident_summary(inc, event_count=len(event_ids))
    return templates.TemplateResponse(
        "incident.html",
        {
            "request": request,
            "incident": summary.model_dump(),
            "events": [_to_event_out(e).model_dump() for e in events],
            "evidence_json": __import__("json").dumps(dict(inc.evidence or {}), indent=2)[:8000],
            "playbook": {
                "runbook": pb.get("runbook") or {},
                "steps": pb.get("steps") or [],
            },
            "investigation": {
                "status": inv.status,
                "confidence": inv.confidence,
                "missing_sources": inv.missing_sources,
                "checks": inv.checks,
                "next_queries": inv.next_queries,
                "narrative": inv.narrative,
            },
        },
    )


@app.get("/events/search", response_model=list[EventOut])
def search_events(
    q: str = Query(..., min_length=1, description="Natural language query (offline)."),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[EventOut]:
    qvec = embed_text(q)
    try:
        # pgvector path
        stmt = _event_select_without_embedding().order_by(Event.embedding.cosine_distance(qvec)).limit(int(limit))  # type: ignore[attr-defined]
        events = list(db.execute(stmt).scalars())
        return [_to_event_out(e) for e in events]
    except Exception:
        # Fallback: naive substring match on message/event_type/source
        qq = f"%{q.lower()}%"
        stmt = (
            _event_select_without_embedding()
            .where(
                (Event.message.ilike(qq))  # type: ignore[attr-defined]
                | (Event.event_type.ilike(qq))  # type: ignore[attr-defined]
                | (Event.source.ilike(qq))  # type: ignore[attr-defined]
            )
            .order_by(Event.ts.desc())
            .limit(int(limit))
        )
        events = list(db.execute(stmt).scalars())
        return [_to_event_out(e) for e in events]


@app.post("/incidents/{incident_id}/playbook", response_model=PlaybookResponse)
def incident_playbook(
    incident_id: str,
    mode: str = Query("runbook", description="runbook|ollama"),
    db: Session = Depends(get_db),
) -> PlaybookResponse:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    event_ids = [
        row.event_id
        for row in db.execute(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)).scalars()
    ]
    events = []
    if event_ids:
        events = list(
            db.execute(_event_select_without_embedding().where(Event.id.in_(event_ids)).order_by(Event.ts.asc())).scalars()
        )

    pb = generate_playbook(inc, events, CFG, mode="ollama" if mode == "ollama" else "runbook")
    inc.playbook = pb
    inc.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(action="playbook", data={"incident_id": incident_id, "mode": mode, "generated_by": pb.get("generated_by")}))
    db.commit()

    missing_sources = list((pb.get("incident") or {}).get("missing_sources") or pb.get("missing_sources") or [])
    steps = []
    for s in pb.get("steps") or []:
        procedure = str(s.get("procedure") or "")
        objective = str(s.get("objective") or "")
        description = procedure or objective or str(s.get("description") or "")
        steps.append(
            {
                "step": int(s.get("step") or 0),
                "id": (str(s.get("id") or "") or None),
                "title": str(s.get("title") or ""),
                "description": description,
                "objective": objective or None,
                "procedure": procedure or None,
                "validation": (str(s.get("validation") or "") or None),
                "rollback": (str(s.get("rollback") or "") or None),
                "evidence_event_ids": list(s.get("evidence_event_ids") or []),
            }
        )

    return PlaybookResponse(
        incident_id=incident_id,
        incident_type=inc.incident_type,
        generated_by=str(pb.get("generated_by") or "runbook_template"),
        missing_sources=missing_sources,
        steps=steps,
        runbook=pb.get("runbook"),
    )


@app.post("/incidents/{incident_id}/investigate")
def investigate(incident_id: str, db: Session = Depends(get_db)) -> dict:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    event_ids = [
        row.event_id
        for row in db.execute(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)).scalars()
    ]
    events = []
    if event_ids:
        events = list(
            db.execute(_event_select_without_embedding().where(Event.id.in_(event_ids)).order_by(Event.ts.asc())).scalars()
        )

    rep = investigate_incident(inc, events, CFG)
    db.add(
        AuditLog(
            action="investigate",
            data={"incident_id": incident_id, "status": rep.status, "confidence": rep.confidence, "missing": rep.missing_sources},
        )
    )
    db.commit()
    return {
        "incident_id": incident_id,
        "status": rep.status,
        "confidence": rep.confidence,
        "missing_sources": rep.missing_sources,
        "checks": rep.checks,
        "next_queries": rep.next_queries,
        "narrative": rep.narrative,
    }


@app.get("/runbooks")
def runbooks() -> list[dict[str, str]]:
    out = []
    for t in list_templates():
        out.append({"id": t.id, "name": t.name, "version": t.version, "path": str(t.path)})
    return out


@app.get("/status/external-devices")
def external_devices_status(db: Session = Depends(get_db)) -> dict:
    rows = list(db.execute(_event_select_without_embedding().order_by(Event.ts.desc()).limit(250)).scalars())
    devices: list[dict[str, str]] = []

    seen: set[str] = set()
    for e in rows:
        message = str(e.message or "")
        process = str(e.process or "")
        event_type = str(e.event_type or "")
        text = " ".join([message, process, event_type]).lower()

        if "onedrive" in text:
            key = f"onedrive:{e.host or '-'}:{e.username or '-'}"
            if key not in seen:
                seen.add(key)
                devices.append(
                    {
                        "name": "OneDrive",
                        "host": str(e.host or "-"),
                        "user": str(e.username or "-"),
                        "detail": message[:140] if message else "Cloud sync client activity detected.",
                    }
                )

        usb_keywords = ("usb", "pendrive", "flash drive", "mass storage", "removable")
        if any(k in text for k in usb_keywords):
            key = f"usb:{e.host or '-'}:{e.username or '-'}:{e.ts}"
            if key not in seen:
                seen.add(key)
                devices.append(
                    {
                        "name": "USB Device",
                        "host": str(e.host or "-"),
                        "user": str(e.username or "-"),
                        "detail": message[:140] if message else "Removable storage activity detected.",
                    }
                )

        if len(devices) >= 10:
            break

    return {
        "has_devices": bool(devices),
        "devices": devices,
    }


@app.get("/status/telemetry-health")
def telemetry_health(
    lookback_hours: int = Query(24, ge=1, le=168),
    heartbeat_drop_minutes: int = Query(90, ge=5, le=1440),
    high_risk_severity: int = Query(70, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=int(lookback_hours))
    drop_cutoff = now - timedelta(minutes=int(heartbeat_drop_minutes))
    expected_sources = ["edr", "iam", "net", "siem"]

    rows = list(
        db.execute(
            select(
                Event.host,
                Event.username,
                Event.source,
                Event.event_type,
                Event.severity,
                Event.message,
                Event.ts,
            ).where(Event.ts >= cutoff)
        )
    )

    hosts_seen: set[str] = set()
    edr_hosts: set[str] = set()
    iam_users: set[str] = set()
    high_risk_users: set[str] = set()
    latest_by_host_source: dict[str, dict[str, datetime]] = defaultdict(dict)

    risky_keywords = ("malware", "virus", "ransom", "trojan", "suspicious", "c2", "credential", "abuse")

    for host, user, source, event_type, severity, message, ts in rows:
        src = str(source or "").lower()
        host_s = str(host or "").strip()
        user_s = str(user or "").strip()
        type_s = str(event_type or "").lower()
        msg_s = str(message or "").lower()
        sev = int(severity or 0)

        if host_s:
            hosts_seen.add(host_s)
            current = latest_by_host_source[host_s].get(src)
            if isinstance(ts, datetime) and (current is None or ts > current):
                latest_by_host_source[host_s][src] = ts

        if src == "edr" and host_s:
            edr_hosts.add(host_s)
        if src == "iam" and user_s:
            iam_users.add(user_s)

        is_keyword_risk = any(k in type_s or k in msg_s for k in risky_keywords)
        if user_s and (sev >= int(high_risk_severity) or is_keyword_risk):
            high_risk_users.add(user_s)

    hosts_without_edr = sorted(hosts_seen - edr_hosts)
    users_missing_identity_logs = sorted(high_risk_users - iam_users)

    drop_rows = list(
        db.execute(select(TelemetryStatus).where(TelemetryStatus.last_seen_ts < drop_cutoff).order_by(TelemetryStatus.last_seen_ts.asc())).scalars()
    )
    heartbeat_drops = [
        {
            "source": str(r.source),
            "host": str(r.host or "-"),
            "last_seen_ts": (
                r.last_seen_ts.isoformat() if isinstance(r.last_seen_ts, datetime) else str(r.last_seen_ts)
            ),
        }
        for r in drop_rows
    ]

    hosts = sorted(hosts_seen)
    heatmap_rows: list[dict] = []
    host_scores: list[float] = []

    for host in hosts:
        source_cells: dict[str, dict[str, str]] = {}
        host_score = 0.0
        for src in expected_sources:
            last_seen = latest_by_host_source.get(host, {}).get(src)
            if last_seen is None:
                state = "missing"
                score_value = 0.0
                last_seen_out = "-"
            elif last_seen < drop_cutoff:
                state = "degraded"
                score_value = 0.5
                last_seen_out = last_seen.isoformat()
            else:
                state = "healthy"
                score_value = 1.0
                last_seen_out = last_seen.isoformat()

            source_cells[src] = {"state": state, "last_seen_ts": last_seen_out}
            host_score += score_value

        host_pct = (host_score / max(len(expected_sources), 1)) * 100.0
        host_scores.append(host_pct)
        heatmap_rows.append({"host": host, "sources": source_cells, "health_score_pct": round(host_pct, 1)})

    overall_health = round(sum(host_scores) / len(host_scores), 1) if host_scores else 100.0

    return {
        "generated_at": now.isoformat(),
        "lookback_hours": int(lookback_hours),
        "heartbeat_drop_minutes": int(heartbeat_drop_minutes),
        "expected_sources": expected_sources,
        "overall_health_score_pct": overall_health,
        "blind_spots": {
            "hosts_without_edr": hosts_without_edr,
            "users_missing_identity_logs": users_missing_identity_logs,
            "heartbeat_drops": heartbeat_drops,
        },
        "heatmap": heatmap_rows,
    }

