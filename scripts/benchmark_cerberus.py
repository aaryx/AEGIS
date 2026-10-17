"""Disposable SQLite baseline; JSON stdout, no production configuration or services."""

import json
import platform
import secrets
import statistics
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import event, func, select

from aegis.config import Settings
from aegis.db import Base, EventRecord, Organization, database
from aegis.pipeline import ingest, seed_rules
from aegis.schemas import EventInput
from aegis.storage import LocalStorage
from aegis.ueba import analyze, config
from aegis.worker import process_once


def measure(size):
    with tempfile.TemporaryDirectory(prefix="cerberus-bench-") as directory:
        settings = Settings(
            environment="testing",
            database_url=f"sqlite:///{Path(directory) / 'bench.db'}",
            audit_secret=secrets.token_urlsafe(32),
            _env_file=None,
        )
        engine, sessions = database(settings.database_url)
        try:
            Base.metadata.create_all(engine)
            with sessions.begin() as db:
                org = Organization(name="Disposable benchmark")
                db.add(org)
                db.flush()
                org_id = org.id
                seed_rules(db, org_id)
            queries = 0

            def count(*args):
                nonlocal queries
                queries += 1

            event.listen(engine, "after_cursor_execute", count)
            end = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
            rows = [
                EventInput(
                    source="benchmark",
                    source_sequence=str(i),
                    timestamp=end - timedelta(minutes=i + 1),
                    raw_event={
                        "username": f"user-{i % 20}",
                        "host": f"host-{i % 5}",
                        "event_category": "authentication",
                        "outcome": "success",
                    },
                )
                for i in range(size)
            ]
            tracemalloc.start()
            cpu = time.process_time()
            started = time.perf_counter()
            latencies = []
            for offset in range(0, size, 50):
                batch_start = time.perf_counter()
                with sessions.begin() as db:
                    result = ingest(db, settings, org_id, rows[offset : offset + 50], "benchmark")
                    assert len(result["accepted"]) == len(rows[offset : offset + 50])
                latencies.append(time.perf_counter() - batch_start)
            ingestion_seconds = time.perf_counter() - started
            started = time.perf_counter()
            storage = LocalStorage(sessions)
            for _ in range(size // settings.worker_batch_size + 2):
                if not process_once(settings, sessions, storage):
                    break
            worker_seconds = time.perf_counter() - started
            started = time.perf_counter()
            with sessions.begin() as db:
                ueba_result = analyze(db, org_id, end, config(settings))
            ueba_seconds = time.perf_counter() - started
            with sessions() as db:
                processed = db.scalar(
                    select(func.count()).select_from(EventRecord).where(EventRecord.state == "PROCESSED")
                )
                assert processed == size
            cpu_seconds = time.process_time() - cpu
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            ordered = sorted(latencies)
            return {
                "events": size,
                "batch_size": 50,
                "processed": processed,
                "ingestion_seconds": ingestion_seconds,
                "ingestion_eps": size / ingestion_seconds,
                "batch_p50_seconds": statistics.median(latencies),
                "batch_p95_seconds": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
                "worker_seconds": worker_seconds,
                "worker_eps": size / worker_seconds,
                "ueba_seconds": ueba_seconds,
                "ueba_result": ueba_result,
                "sql_statements": queries,
                "cpu_seconds": cpu_seconds,
                "python_peak_bytes": peak,
            }
        finally:
            engine.dispose()


if __name__ == "__main__":
    measure(100)  # One discarded warm-up; each measured repetition gets a fresh DB.
    print(
        json.dumps(
            {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "method": "SQLite WAL; 34 seeded rules; one worker; tracemalloc enabled; 1 warm-up; 3 repetitions",
                "results": [measure(size) for size in (100, 500) for _ in range(3)],
            },
            indent=2,
        )
    )
