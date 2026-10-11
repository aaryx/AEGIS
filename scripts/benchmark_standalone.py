"""Measure standalone end-to-end pipeline ingestion, detection, and worker throughput.

Reports: Events, elapsed time, throughput (EPS), p50/p95/p99 latency, and database accounting.
"""

import argparse
import json
import statistics
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from aegis.config import Settings
from aegis.db import Base, Organization, database
from aegis.pipeline import ingest, seed_rules
from aegis.schemas import EventInput
from aegis.storage import LocalStorage
from aegis.worker import process_once


def main():
    parser = argparse.ArgumentParser(description="Standalone AEGIS Pipeline Benchmark")
    parser.add_argument("--events", type=int, default=1000, help="Total synthetic events (default: 1000)")
    parser.add_argument("--batch-size", type=int, default=100, help="Ingestion batch size (default: 100)")
    args = parser.parse_args()

    print(f"[*] Starting AEGIS Pipeline Benchmark with {args.events} events (batch size: {args.batch_size})...")

    with tempfile.TemporaryDirectory(prefix="aegis-bench-") as temp_dir:
        db_path = Path(temp_dir) / "bench.db"
        settings = Settings(
            environment="testing",
            database_url=f"sqlite:///{db_path}",
            audit_secret="bench-secret-audit-integrity-key-32chars",  # noqa: S106
            _env_file=None,
        )

        engine, session_factory = database(settings.database_url)
        storage = LocalStorage(session_factory)
        Base.metadata.create_all(engine)

        with session_factory.begin() as db:
            org = Organization(name="Benchmark Organization")
            db.add(org)
            db.flush()
            org_id = org.id
            seed_rules(db, org_id)

        try:
            # 1. Benchmark Ingestion
            source_id = f"bench-source-{uuid4().hex[:8]}"
            ingest_latencies: list[float] = []
            ingest_start = time.perf_counter()

            for offset in range(0, args.events, args.batch_size):
                chunk_size = min(args.batch_size, args.events - offset)
                events = [
                    EventInput(
                        source=source_id,
                        source_type="json",
                        collector="synthetic-bench",
                        source_sequence=str(offset + i),
                        timestamp=datetime.now(UTC),
                        raw_event={
                            "message": f"Benchmark synthetic event payload {offset + i}",
                            "host": f"BENCH-SRV-{i % 5}",
                            "source_ip": f"10.0.0.{(offset + i) % 250 + 1}",
                            "username": f"user_{(offset + i) % 20}",
                            "event_category": "authentication",
                            "action": "logon",
                            "outcome": "success" if (i % 3 != 0) else "failure",
                        },
                    )
                    for i in range(chunk_size)
                ]

                t0 = time.perf_counter()
                with session_factory.begin() as db:
                    ingest(db, settings, org_id, events, source_id)
                t1 = time.perf_counter()
                ingest_latencies.append(t1 - t0)

            ingest_elapsed = time.perf_counter() - ingest_start

            # 2. Benchmark Detection Worker Processing
            worker_start = time.perf_counter()
            total_processed = 0
            worker_passes = 0
            while True:
                processed = process_once(settings, session_factory, storage)
                if processed == 0:
                    break
                total_processed += processed
                worker_passes += 1
            worker_elapsed = time.perf_counter() - worker_start
        finally:
            engine.dispose()

        total_elapsed = ingest_elapsed + worker_elapsed

        sorted_latencies = sorted(ingest_latencies)
        p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)]
        p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
        p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]

        report = {
            "total_events": args.events,
            "batch_size": args.batch_size,
            "batches_submitted": len(ingest_latencies),
            "ingest_elapsed_seconds": round(ingest_elapsed, 4),
            "ingest_events_per_second": round(args.events / ingest_elapsed, 2),
            "worker_elapsed_seconds": round(worker_elapsed, 4),
            "worker_events_per_second": round(total_processed / max(0.0001, worker_elapsed), 2),
            "worker_passes": worker_passes,
            "total_pipeline_seconds": round(total_elapsed, 4),
            "end_to_end_events_per_second": round(args.events / total_elapsed, 2),
            "ingest_batch_latency_p50_seconds": round(p50, 4),
            "ingest_batch_latency_p95_seconds": round(p95, 4),
            "ingest_batch_latency_p99_seconds": round(p99, 4),
            "ingest_batch_latency_mean_seconds": round(statistics.mean(ingest_latencies), 4),
            "ingest_batch_latency_max_seconds": round(max(ingest_latencies), 4),
            "database_engine": "SQLite (isolated test engine)",
            "worker_claimed_events": total_processed,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        print("\n=== AEGIS PERFORMANCE BENCHMARK RESULTS ===")
        print(json.dumps(report, indent=2))

        output_path = Path("local-data") / "standalone-benchmark.json"
        output_path.parent.mkdir(exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
