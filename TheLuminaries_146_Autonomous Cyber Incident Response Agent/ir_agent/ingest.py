from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ir_agent.embeddings import canonical_event_text, embed_text
from ir_agent.models import Event, EventEntity, TelemetryStatus
from ir_agent.schema import IngestEvent


def _as_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def extract_entities(e: IngestEvent) -> list[tuple[str, str]]:
    entities: list[tuple[str, str]] = []

    if e.host:
        entities.append(("host", e.host))
    if e.user:
        entities.append(("user", e.user))
    if e.ip:
        entities.append(("ip", e.ip))
    if e.process:
        entities.append(("process", e.process))

    raw = e.raw or {}

    domain = _as_str(raw.get("domain"))
    if not domain:
        url = _as_str(raw.get("url")) or _as_str(raw.get("uri"))
        if url:
            try:
                domain = urlparse(url).hostname
            except Exception:
                domain = None
    if domain:
        entities.append(("domain", domain))

    # Deduplicate
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for t, v in entities:
        key = (t, v)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def insert_event(db: Session, e: IngestEvent) -> int:
    raw_payload = dict(e.raw or {})
    text = canonical_event_text(e.source, e.event_type, e.message, raw_payload)
    embedding = embed_text(text)

    evt = Event(
        ts=e.timestamp,
        source=e.source.lower().strip(),
        event_type=e.event_type.lower().strip(),
        severity=int(e.severity or 0),
        host=_as_str(e.host),
        username=_as_str(e.user),
        ip=_as_str(e.ip),
        process=_as_str(e.process),
        message=_as_str(e.message),
        raw=raw_payload,
        embedding=embedding,
    )
    db.add(evt)
    db.flush()  # assigns id

    for etype, evalue in extract_entities(e):
        db.add(EventEntity(event_id=evt.id, entity_type=etype, entity_value=evalue))

    # Telemetry heartbeat (source+host); missing host is tracked under empty string.
    host_key = evt.host or ""
    pk = (evt.source, host_key)
    ts: datetime = evt.ts

    row = db.get(TelemetryStatus, pk)
    if row is None:
        db.add(TelemetryStatus(source=evt.source, host=host_key, last_seen_ts=ts))
    else:
        row.last_seen_ts = ts

    return evt.id
