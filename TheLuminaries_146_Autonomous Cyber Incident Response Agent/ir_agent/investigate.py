from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from ir_agent.config import AppConfig
from ir_agent.models import Event, Incident


@dataclass(frozen=True)
class InvestigationReport:
    status: str
    confidence: float
    missing_sources: list[str]
    checks: list[dict[str, Any]]
    next_queries: list[dict[str, Any]]
    narrative: str | None


def _missing_sources(cfg: AppConfig, present: list[str]) -> list[str]:
    expected = [s.lower() for s in (cfg.expected_sources or [])]
    present_set = {s.lower() for s in present}
    return [s for s in expected if s not in present_set]


def _ollama_enabled() -> bool:
    return bool((os.environ.get("OLLAMA_BASE_URL") or "").strip())


def _ollama_generate(prompt: str) -> str:
    base_url = (os.environ.get("OLLAMA_BASE_URL") or "").rstrip("/")
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
    payload = {"model": model, "prompt": prompt, "stream": False}
    req = Request(
        url=f"{base_url}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return str(data.get("response") or "")


def investigate_incident(incident: Incident, events: list[Event], cfg: AppConfig) -> InvestigationReport:
    sources_present = list(incident.sources or [])
    missing = _missing_sources(cfg, sources_present)

    ev_by_type: dict[str, list[Event]] = {}
    for e in events:
        ev_by_type.setdefault(e.event_type.lower(), []).append(e)

    rule_hits = ((incident.evidence or {}).get("rule_hits") or []) if isinstance(incident.evidence, dict) else []
    rule_ids = {str(r.get("rule_id")) for r in rule_hits if isinstance(r, dict)}

    checks: list[dict[str, Any]] = []
    next_queries: list[dict[str, Any]] = []

    # Deterministic validation logic by incident type
    status = "hypothesis"
    confidence = float(incident.confidence_score)

    if incident.incident_type == "credential_abuse":
        burst = len(ev_by_type.get("auth_failed", [])) >= cfg.scoring.auth_failed_burst_threshold
        has_success = len(ev_by_type.get("auth_success", [])) > 0
        checks.append(
            {
                "check": "auth_failed_burst",
                "passed": burst,
                "details": f"auth_failed_count={len(ev_by_type.get('auth_failed', []))}",
                "evidence_event_ids": [e.id for e in ev_by_type.get("auth_failed", [])][:20],
            }
        )
        checks.append(
            {
                "check": "auth_success_after_failures",
                "passed": has_success,
                "details": f"auth_success_count={len(ev_by_type.get('auth_success', []))}",
                "evidence_event_ids": [e.id for e in ev_by_type.get("auth_success", [])][:20],
            }
        )
        if burst and has_success:
            status = "confirmed"
            confidence = min(1.0, confidence + 0.10)
        next_queries.append({"query": "Find other users targeted from the same IPs", "type": "sql_hint"})

    elif incident.incident_type in ("malware_execution", "command_and_control"):
        has_susp_proc = "R002" in rule_ids or len(ev_by_type.get("process_start", [])) > 0
        has_net = len(ev_by_type.get("dns_query", [])) + len(ev_by_type.get("http_request", [])) + len(
            ev_by_type.get("net_connection", [])
        ) > 0
        checks.append(
            {
                "check": "suspicious_process_present",
                "passed": has_susp_proc,
                "details": f"process_events={len(ev_by_type.get('process_start', []))}",
                "evidence_event_ids": [e.id for e in ev_by_type.get("process_start", [])][:20],
            }
        )
        checks.append(
            {
                "check": "outbound_network_present",
                "passed": has_net,
                "details": "dns/http/net events present" if has_net else "no network telemetry in incident",
                "evidence_event_ids": (
                    [e.id for e in ev_by_type.get("dns_query", [])][:10]
                    + [e.id for e in ev_by_type.get("http_request", [])][:10]
                    + [e.id for e in ev_by_type.get("net_connection", [])][:10]
                ),
            }
        )
        if has_susp_proc and has_net:
            status = "confirmed"
            confidence = min(1.0, confidence + 0.10)
        next_queries.append({"query": "Search for same domain/IP contacted by other hosts", "type": "sql_hint"})
        next_queries.append({"query": "Search for same suspicious process across hosts", "type": "sql_hint"})

    else:
        # Generic
        checks.append(
            {
                "check": "cross_source_corroboration",
                "passed": len(sources_present) >= 2,
                "details": f"sources_present={sources_present}",
                "evidence_event_ids": [e.id for e in events][:20],
            }
        )

    # Missing telemetry lowers confidence, but does not auto-dismiss.
    if missing:
        confidence = max(0.0, confidence - 0.10)
        next_queries.append({"query": f"Restore missing telemetry sources: {missing}", "type": "ops"})

    narrative = None
    if _ollama_enabled():
        try:
            prompt = (
                "You are an offline SOC assistant. Summarize the incident for an analyst. "
                "Only use the provided evidence. Do not invent facts.\n\n"
                f"Incident type: {incident.incident_type}\n"
                f"Title: {incident.title}\n"
                f"Scores: fidelity={incident.fidelity_score}, confidence={incident.confidence_score}, coverage={incident.coverage_score}\n"
                f"Sources present: {sources_present}\n"
                f"Missing sources: {missing}\n"
                f"Rule hits: {json.dumps(rule_hits)}\n"
                f"Events (limited): {json.dumps([{'id': e.id, 'ts': str(e.ts), 'source': e.source, 'type': e.event_type, 'msg': e.message} for e in events[:30]])}\n"
            )
            narrative = _ollama_generate(prompt)[:8000]
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
            narrative = None

    return InvestigationReport(
        status=status,
        confidence=float(confidence),
        missing_sources=missing,
        checks=checks,
        next_queries=next_queries,
        narrative=narrative,
    )

