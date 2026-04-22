from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _request(method: str, url: str, body: object | None = None) -> object:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(url=url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    base_url = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
    examples_path = Path(__file__).resolve().parent.parent / "examples" / "events.jsonl"

    print(f"[demo] API: {base_url}")
    print(f"[demo] Events: {examples_path}")

    # Wait for API health.
    deadline = time.time() + 60
    while True:
        try:
            _request("GET", f"{base_url}/health")
            break
        except (URLError, HTTPError):
            if time.time() > deadline:
                raise SystemExit("API not reachable on /health")
            time.sleep(1)

    # Load events.
    events = []
    for line in examples_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))

    print(f"[demo] Ingesting {len(events)} events ...")
    res = _request("POST", f"{base_url}/ingest/batch", events)
    print("[demo] Ingest result:", json.dumps(res, indent=2))

    print("[demo] Correlating incidents ...")
    res = _request("POST", f"{base_url}/correlate", {"rebuild_all": True})
    print("[demo] Correlate result:", json.dumps(res, indent=2))

    incidents = _request("GET", f"{base_url}/incidents?limit=20")
    print("[demo] Incidents:")
    for inc in incidents:
        print(
            f"  - {inc['id']} | {inc['incident_type']} | fidelity={inc['fidelity_score']:.1f} "
            f"conf={inc['confidence_score']:.2f} cov={inc['coverage_score']:.2f} events={inc['event_count']}"
        )

    if not incidents:
        print("[demo] No incidents created. Try lowering min_events_per_incident in config/config.yml")
        return

    top_id = incidents[0]["id"]
    detail = _request("GET", f"{base_url}/incidents/{top_id}")
    print("\n[demo] Top incident detail (evidence excerpt):")
    print(json.dumps(detail.get("evidence", {}), indent=2)[:3000])

    inv = _request("POST", f"{base_url}/incidents/{top_id}/investigate")
    print("\n[demo] Investigation:")
    print(json.dumps(inv, indent=2)[:4000])

    playbook = _request("POST", f"{base_url}/incidents/{top_id}/playbook?mode=runbook")
    print("\n[demo] Playbook:")
    print(json.dumps(playbook, indent=2)[:6000])


if __name__ == "__main__":
    main()
