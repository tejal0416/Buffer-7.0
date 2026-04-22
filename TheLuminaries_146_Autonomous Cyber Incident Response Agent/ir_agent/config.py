from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class CorrelationConfig:
    lookback_minutes: int = 360
    link_window_minutes: int = 15
    min_events_per_incident: int = 2


@dataclass(frozen=True)
class ScoringConfig:
    auth_failed_burst_threshold: int = 5
    suspicious_process_names: list[str] = field(
        default_factory=lambda: ["powershell.exe", "cmd.exe", "wscript.exe", "rundll32.exe"]
    )
    suspicious_domains: list[str] = field(default_factory=lambda: ["evil.example", "c2.bad"])


@dataclass(frozen=True)
class AppConfig:
    expected_sources: list[str] = field(default_factory=lambda: ["siem", "edr", "iam", "net"])
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)


def _deep_get(d: dict[str, Any], keys: list[str]) -> Any | None:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def load_config(path: str | Path) -> AppConfig:
    p = Path(path)
    if not p.exists():
        return AppConfig()

    raw = yaml.safe_load(p.read_text()) or {}
    if not isinstance(raw, dict):
        return AppConfig()

    expected_sources = _deep_get(raw, ["app", "expected_sources"]) or AppConfig().expected_sources
    corr = CorrelationConfig(
        lookback_minutes=int(
            (_deep_get(raw, ["app", "correlation", "lookback_minutes"]) or CorrelationConfig().lookback_minutes)
        ),
        link_window_minutes=int(
            (
                _deep_get(raw, ["app", "correlation", "link_window_minutes"])
                or CorrelationConfig().link_window_minutes
            )
        ),
        min_events_per_incident=int(
            (
                _deep_get(raw, ["app", "correlation", "min_events_per_incident"])
                or CorrelationConfig().min_events_per_incident
            )
        ),
    )
    scoring = ScoringConfig(
        auth_failed_burst_threshold=int(
            (
                _deep_get(raw, ["app", "scoring", "auth_failed_burst_threshold"])
                or ScoringConfig().auth_failed_burst_threshold
            )
        ),
        suspicious_process_names=list(
            _deep_get(raw, ["app", "scoring", "suspicious_process_names"]) or ScoringConfig().suspicious_process_names
        ),
        suspicious_domains=list(
            _deep_get(raw, ["app", "scoring", "suspicious_domains"]) or ScoringConfig().suspicious_domains
        ),
    )

    return AppConfig(expected_sources=list(expected_sources), correlation=corr, scoring=scoring)

