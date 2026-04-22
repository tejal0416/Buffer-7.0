from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Template

from ir_agent.models import Event, Incident


@dataclass(frozen=True)
class RunbookTemplate:
    path: Path
    raw: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.raw.get("id") or self.path.stem)

    @property
    def name(self) -> str:
        return str(self.raw.get("name") or self.id)

    @property
    def version(self) -> str:
        return str(self.raw.get("version") or "1.0")

    @property
    def incident_types(self) -> list[str]:
        v = self.raw.get("incident_types") or []
        return [str(x) for x in v] if isinstance(v, list) else []


def _runbook_dir() -> Path:
    d = os.environ.get("RUNBOOK_DIR", "runbooks")
    return Path(d).resolve()


def list_templates() -> list[RunbookTemplate]:
    d = _runbook_dir()
    if not d.exists():
        return []
    out: list[RunbookTemplate] = []
    for p in sorted(d.glob("*.yml")) + sorted(d.glob("*.yaml")):
        try:
            raw = yaml.safe_load(p.read_text()) or {}
        except Exception:
            continue
        if isinstance(raw, dict):
            out.append(RunbookTemplate(path=p, raw=raw))
    return out


def choose_template(incident_type: str) -> RunbookTemplate | None:
    incident_type = (incident_type or "").strip().lower()
    for t in list_templates():
        if incident_type in [x.lower() for x in t.incident_types]:
            return t
    # default fallback
    for t in list_templates():
        if "suspicious_activity" in [x.lower() for x in t.incident_types]:
            return t
    return None


def _fmt_list(xs: list[str]) -> str:
    xs = [x for x in xs if x]
    if not xs:
        return "-"
    if len(xs) <= 4:
        return ", ".join(xs)
    return ", ".join(xs[:4]) + f" (+{len(xs) - 4} more)"


def _extract_domains(events: list[Event]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for e in events:
        dom = str((e.raw or {}).get("domain") or "").strip().lower()
        if not dom:
            url = str((e.raw or {}).get("url") or "").strip().lower()
            if "://" in url:
                # naive domain extraction; good enough for demo
                dom = url.split("://", 1)[1].split("/", 1)[0]
        if not dom:
            continue
        if dom in seen:
            continue
        seen.add(dom)
        out.append(dom)
    return out


def _evidence_for_step(step: dict[str, Any], events: list[Event]) -> list[int]:
    ev = step.get("evidence") or {}
    event_types = ev.get("event_types") or []
    limit = int(ev.get("limit") or 25)
    if not event_types:
        return [e.id for e in events[:limit]]
    wanted = {str(x).lower() for x in event_types}
    return [e.id for e in events if e.event_type.lower() in wanted][:limit]


def render_runbook(
    template: RunbookTemplate,
    incident: Incident,
    events: list[Event],
    *,
    missing_sources: list[str],
) -> dict[str, Any]:
    entities = incident.entities if isinstance(incident.entities, dict) else {}
    hosts = list(entities.get("hosts") or [])
    users = list(entities.get("users") or [])
    ips = list(entities.get("ips") or [])
    processes = list(entities.get("processes") or [])
    domains = _extract_domains(events)

    ctx = {
        "incident_id": incident.id,
        "title": incident.title,
        "incident_type": incident.incident_type,
        "start_ts": str(incident.start_ts),
        "end_ts": str(incident.end_ts),
        "sources_present": list(incident.sources or []),
        "missing_sources": missing_sources,
        "hosts": hosts,
        "users": users,
        "ips": ips,
        "processes": processes,
        "domains": domains,
        "primary_host": hosts[0] if hosts else "-",
        "primary_user": users[0] if users else "-",
        "hosts_fmt": _fmt_list(hosts),
        "users_fmt": _fmt_list(users),
        "ips_fmt": _fmt_list(ips),
        "processes_fmt": _fmt_list(processes),
        "domains_fmt": _fmt_list(domains),
        "scores": {
            "fidelity": float(incident.fidelity_score),
            "confidence": float(incident.confidence_score),
            "coverage": float(incident.coverage_score),
        },
        "evidence": dict(incident.evidence or {}),
    }

    raw = template.raw
    defaults = raw.get("defaults") or {}
    steps = raw.get("steps") or []

    rendered_steps: list[dict[str, Any]] = []
    for i, s in enumerate(steps, start=1):
        if not isinstance(s, dict):
            continue

        def _render(value: Any) -> Any:
            if isinstance(value, str):
                return Template(value).render(**ctx)
            return value

        step_obj = {
            "step": i,
            "id": str(s.get("id") or f"step_{i}"),
            "title": _render(s.get("title") or f"Step {i}"),
            "objective": _render(s.get("objective") or ""),
            "procedure": _render(s.get("procedure") or ""),
            "validation": _render(s.get("validation") or ""),
            "rollback": _render(s.get("rollback") or ""),
            "evidence_event_ids": _evidence_for_step(s, events),
        }
        rendered_steps.append(step_obj)

    return {
        "runbook": {
            "id": template.id,
            "name": template.name,
            "version": template.version,
            "owner_role": str(defaults.get("owner_role") or "SOC Analyst"),
            "severity_guidance": str(defaults.get("severity_guidance") or ""),
        },
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "incident_type": incident.incident_type,
            "start_ts": str(incident.start_ts),
            "end_ts": str(incident.end_ts),
            "sources_present": list(incident.sources or []),
            "missing_sources": missing_sources,
            "scores": ctx["scores"],
        },
        "steps": rendered_steps,
    }

