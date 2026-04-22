from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from ir_agent.config import AppConfig
from ir_agent.models import Event, Incident
from ir_agent.runbooks import choose_template, render_runbook


def _missing_sources(cfg: AppConfig, present: list[str]) -> list[str]:
    expected = [s.lower() for s in (cfg.expected_sources or [])]
    present_set = {s.lower() for s in present}
    return [s for s in expected if s not in present_set]


@dataclass(frozen=True)
class OllamaConfig:
    base_url: str
    model: str


def _ollama_config_from_env() -> OllamaConfig | None:
    base_url = (os.environ.get("OLLAMA_BASE_URL") or "").rstrip("/")
    if not base_url:
        return None
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
    return OllamaConfig(base_url=base_url, model=model)


def _ollama_generate(cfg: OllamaConfig, prompt: str) -> str:
    payload = {"model": cfg.model, "prompt": prompt, "stream": False}
    req = Request(
        url=f"{cfg.base_url}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return str(data.get("response") or "")


def _rewrite_runbook_with_ollama(rb: dict[str, Any]) -> dict[str, Any]:
    # Guardrail: evidence ids and structure remain unchanged; only text fields get rewritten.
    ocfg = _ollama_config_from_env()
    if ocfg is None:
        return rb

    try:
        prompt = (
            "You are an offline SOC incident response assistant. Rewrite the runbook step text to be concise and "
            "actionable. Do not invent evidence or add steps. Do not remove any step. Return JSON only with the same "
            "shape as the input.\n\n"
            f"INPUT JSON:\n{json.dumps(rb)}\n"
        )
        out = _ollama_generate(ocfg, prompt)
        # Best-effort parse; if it fails, keep original.
        parsed = json.loads(out)
        if isinstance(parsed, dict) and isinstance(parsed.get("steps"), list):
            # Preserve evidence ids from original.
            for i, s in enumerate(parsed["steps"]):
                if i < len(rb.get("steps") or []):
                    s["evidence_event_ids"] = (rb["steps"][i] or {}).get("evidence_event_ids", [])
            parsed.setdefault("runbook", rb.get("runbook"))
            parsed.setdefault("incident", rb.get("incident"))
            return parsed
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        pass
    return rb


def generate_playbook(
    incident: Incident,
    events: list[Event],
    cfg: AppConfig,
    *,
    mode: str = "runbook",
) -> dict[str, Any]:
    mode = (mode or "runbook").lower().strip()
    missing = _missing_sources(cfg, list(incident.sources or []))

    tmpl = choose_template(incident.incident_type)
    if tmpl is None:
        # Should not happen if runbooks/suspicious_activity.yml exists; still, fail safe.
        tmpl = choose_template("suspicious_activity")

    rb = render_runbook(tmpl, incident, events, missing_sources=missing) if tmpl is not None else {}
    rb["generated_by"] = "runbook_template"

    if mode == "ollama":
        rb2 = _rewrite_runbook_with_ollama(rb)
        rb2["generated_by"] = "ollama+runbook_template"
        return rb2

    return rb

