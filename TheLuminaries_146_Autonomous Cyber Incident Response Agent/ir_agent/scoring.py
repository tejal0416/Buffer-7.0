from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Any

from ir_agent.config import AppConfig
from ir_agent.models import Event


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    name: str
    score: int
    evidence_event_ids: list[int]


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _distinct_str(values: list[str | None]) -> list[str]:
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


def score_incident(events: list[Event], cfg: AppConfig) -> dict[str, Any]:
    # Feature extraction (transparent, deterministic).
    sources = _distinct_str([e.source for e in events])
    users = _distinct_str([e.username for e in events])
    hosts = _distinct_str([e.host for e in events])
    ips = _distinct_str([e.ip for e in events])

    auth_failed = [e for e in events if e.event_type == "auth_failed"]
    auth_success = [e for e in events if e.event_type == "auth_success"]
    proc_starts = [e for e in events if e.event_type in ("process_start", "process_create")]

    suspicious_proc_names = {p.lower() for p in cfg.scoring.suspicious_process_names}
    suspicious_proc = [
        e
        for e in proc_starts
        if (e.process or "").lower() in suspicious_proc_names or "encodedcommand" in ((e.message or "").lower())
    ]

    suspicious_domains = {d.lower() for d in cfg.scoring.suspicious_domains}
    domain_hits = [
        e
        for e in events
        if (str((e.raw or {}).get("domain") or "").lower() in suspicious_domains)
        or (str((e.raw or {}).get("url") or "").lower().find("evil.example") != -1)
    ]

    features = {
        "event_count": len(events),
        "distinct_sources": len(sources),
        "distinct_users": len(users),
        "distinct_hosts": len(hosts),
        "distinct_ips": len(ips),
        "auth_failed_count": len(auth_failed),
        "auth_success_count": len(auth_success),
        "process_start_count": len(proc_starts),
        "suspicious_process_count": len(suspicious_proc),
        "suspicious_domain_count": len(domain_hits),
    }

    # Rules (high precision). Keep the list small in MVP; add more as needed.
    rule_hits: list[RuleHit] = []

    if len(auth_failed) >= cfg.scoring.auth_failed_burst_threshold and users:
        rule_hits.append(
            RuleHit(
                rule_id="R001",
                name="Auth failure burst (possible brute force / credential stuffing)",
                score=40,
                evidence_event_ids=[e.id for e in auth_failed[:20]],
            )
        )

    if suspicious_proc:
        rule_hits.append(
            RuleHit(
                rule_id="R002",
                name="Suspicious process execution (possible malware / living-off-the-land)",
                score=50,
                evidence_event_ids=[e.id for e in suspicious_proc[:20]],
            )
        )

    if domain_hits:
        rule_hits.append(
            RuleHit(
                rule_id="R003",
                name="Suspicious domain contacted (possible C2 / phishing)",
                score=40,
                evidence_event_ids=[e.id for e in domain_hits[:20]],
            )
        )

    # Decide incident type/title deterministically.
    incident_type = "suspicious_activity"
    title = "Suspicious activity"
    if any(h.rule_id == "R001" for h in rule_hits):
        incident_type = "credential_abuse"
        title = f"Credential abuse suspected for user {users[0]}" if users else "Credential abuse suspected"
    if any(h.rule_id == "R002" for h in rule_hits):
        incident_type = "malware_execution"
        title = f"Suspicious process execution on host {hosts[0]}" if hosts else "Suspicious process execution"
    if any(h.rule_id == "R003" for h in rule_hits) and incident_type == "suspicious_activity":
        incident_type = "command_and_control"
        title = f"Suspicious domain contact from host {hosts[0]}" if hosts else "Suspicious domain contact"

    # Coverage and confidence.
    expected = [s.lower() for s in (cfg.expected_sources or [])]
    expected_set = set(expected)
    sources_set = set(sources)
    coverage = 1.0 if not expected else (len(sources_set.intersection(expected_set)) / max(1, len(expected_set)))

    rule_total = sum(h.score for h in rule_hits)
    corroboration = _clamp((len(sources) - 1) * 5.0, 0.0, 15.0)
    volume = _clamp(float(len(events)), 0.0, 10.0)

    fidelity = _clamp(rule_total + corroboration + volume, 0.0, 100.0)
    confidence = _clamp((0.20 + 0.15 * len(sources) + 0.10 * len(rule_hits)) * coverage, 0.0, 1.0)

    evidence = {
        "rule_hits": [
            {
                "rule_id": h.rule_id,
                "name": h.name,
                "score": h.score,
                "evidence_event_ids": h.evidence_event_ids,
            }
            for h in rule_hits
        ],
        "features": features,
        "sources_present": sources,
    }

    return {
        "incident_type": incident_type,
        "title": title,
        "fidelity_score": float(fidelity),
        "confidence_score": float(confidence),
        "coverage_score": float(coverage),
        "features": features,
        "evidence": evidence,
    }


def score_incidents_anomaly(features_list: list[dict[str, Any]]) -> list[float]:
    # Unsupervised "anomaly-ness" across incidents. Works even with cold start and no history.
    # Robust z-score (median/MAD) over a handful of numeric features.
    if not features_list:
        return []
    if len(features_list) < 2:
        return [0.0 for _ in features_list]

    keys = [
        "auth_failed_count",
        "distinct_ips",
        "suspicious_process_count",
        "suspicious_domain_count",
        "event_count",
        "distinct_sources",
    ]

    values_by_key: dict[str, list[float]] = {k: [] for k in keys}
    for f in features_list:
        for k in keys:
            values_by_key[k].append(float(f.get(k, 0.0)))

    med_by_key = {k: median(vs) for k, vs in values_by_key.items()}
    mad_by_key = {}
    for k, vs in values_by_key.items():
        med = med_by_key[k]
        abs_dev = [abs(x - med) for x in vs]
        mad = median(abs_dev) if abs_dev else 0.0
        mad_by_key[k] = mad if mad > 0 else 1.0

    raw_scores: list[float] = []
    for f in features_list:
        z_sum = 0.0
        for k in keys:
            x = float(f.get(k, 0.0))
            z_sum += abs(x - med_by_key[k]) / mad_by_key[k]
        raw_scores.append(z_sum / max(1, len(keys)))

    max_raw = max(raw_scores) if raw_scores else 0.0
    if max_raw <= 0:
        return [0.0 for _ in raw_scores]
    return [float(_clamp(s / max_raw, 0.0, 1.0)) for s in raw_scores]
