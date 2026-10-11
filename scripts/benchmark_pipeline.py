"""Measure a bounded synthetic batch through ingestion, detection and search visibility."""

import argparse
import json
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
from dotenv import dotenv_values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=1000)
    args = parser.parse_args()
    if not 1 <= args.events <= 10000:
        raise SystemExit("Use 1–10000 synthetic events for the bounded local benchmark")
    root = Path(__file__).resolve().parents[1]
    config = dotenv_values(root / ".env")
    source = "benchmark-" + uuid4().hex
    started = time.monotonic()
    latencies = []
    with httpx.Client(base_url="http://localhost:8000/api/v1/", timeout=30) as client:
        login = client.post(
            "auth/login",
            json={"username": config["BOOTSTRAP_USERNAME"], "password": config["BOOTSTRAP_PASSWORD"]},
        )
        login.raise_for_status()
        client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
        for offset in range(0, args.events, 100):
            batch = [
                {
                    "source": source,
                    "collector": "synthetic-benchmark",
                    "source_sequence": str(i),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "raw_event": {
                        "message": "Synthetic authorized activity",
                        "host": "BENCH-HOST",
                        "event_category": "application",
                    },
                }
                for i in range(offset, min(offset + 100, args.events))
            ]
            request_start = time.monotonic()
            response = client.post("events/ingest", json={"events": batch})
            response.raise_for_status()
            latencies.append(time.monotonic() - request_start)
        accepted_seconds = time.monotonic() - started
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            response = client.post(
                "events/search", json={"filters": [{"field": "source", "value": source}], "limit": 1}
            )
            response.raise_for_status()
            if response.json()["total"] == args.events:
                break
            time.sleep(3)
        else:
            raise RuntimeError("Synthetic events did not become searchable within 180 seconds")
        elapsed = time.monotonic() - started
        report = {
            "events": args.events,
            "source": source,
            "acceptance_seconds": accepted_seconds,
            "end_to_end_seconds": elapsed,
            "end_to_end_events_per_second": args.events / elapsed,
            "batch_latency_median_seconds": statistics.median(latencies),
            "batch_latency_max_seconds": max(latencies),
            "scope": "single local synthetic run, not a sustained capacity or SLA claim",
        }
        target = root / "local-data"
        target.mkdir(exist_ok=True)
        (target / "pipeline-benchmark.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
