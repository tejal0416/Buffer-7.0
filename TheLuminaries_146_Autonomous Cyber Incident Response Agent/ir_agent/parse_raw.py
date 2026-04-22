from __future__ import annotations

import re
from typing import Any

from ir_agent.schema import IngestEvent, IngestRaw


_KV_RE = re.compile(r"(?P<k>[A-Za-z_][A-Za-z0-9_\-]*)=(?P<v>[^\\s]+)")


def _infer_event_type(message: str) -> str:
    m = message.lower()
    if "invalid password" in m or "auth failed" in m or "login failed" in m:
        return "auth_failed"
    if "login success" in m or "authenticated" in m or "auth success" in m:
        return "auth_success"
    if "powershell" in m and ("encodedcommand" in m or "-enc" in m):
        return "process_start"
    if "process start" in m or "process_create" in m or "process start" in m:
        return "process_start"
    if "dns" in m and "query" in m:
        return "dns_query"
    if "http" in m and ("get" in m or "post" in m):
        return "http_request"
    if "siem alert" in m or "alert" in m:
        return "siem_alert"
    return "raw_log"


def parse_raw(raw: IngestRaw) -> IngestEvent:
    # Extract k=v tokens and map common keys to normalized fields.
    message = raw.message.strip()
    meta: dict[str, Any] = dict(raw.meta or {})
    meta.setdefault("raw_message", message)

    kv = {m.group("k").lower(): m.group("v") for m in _KV_RE.finditer(message)}

    host = kv.get("host") or kv.get("hostname")
    user = kv.get("user") or kv.get("username")
    ip = kv.get("ip") or kv.get("src_ip") or kv.get("source_ip")
    process = kv.get("process") or kv.get("proc")
    event_type = kv.get("event_type") or kv.get("type") or _infer_event_type(message)

    # Common IOC fields
    if "domain" in kv:
        meta.setdefault("domain", kv.get("domain"))
    if "url" in kv:
        meta.setdefault("url", kv.get("url"))

    return IngestEvent(
        timestamp=raw.timestamp,
        source=raw.source,
        event_type=event_type,
        severity=raw.severity,
        host=host,
        user=user,
        ip=ip,
        process=process,
        message=message,
        raw=meta,
    )

