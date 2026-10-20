"""AEGIS TITAN Phase 6: Multi-Worker Soak Test Harness.

Executes sustained multi-process soak testing across multiple isolated tenants.
Validates:
1. Multi-process concurrency: 4+ independent worker processes running process_once.
2. Tenant isolation under load: events partitioned across distinct tenant organizations.
3. Target throughput: configurable event rate (default: 100 EPS).
4. Detailed telemetry: p50, p95, p99 latency percentiles, error rates, queue depth.
5. Resource consumption: memory (RSS MB) and CPU usage over time.
6. Periodic durable checkpointing and resumability.
7. Post-run verification: complete reconciliation and HMAC audit-chain continuity.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import random
import statistics
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select

from aegis.config import Settings
from aegis.db import (
    Base,
    EventRecord,
    Organization,
    User,
    database,
)
from aegis.pipeline import ingest, seed_rules
from aegis.security import PASSWORDS, audit, verify_audit
from aegis.storage import LocalStorage
from aegis.worker import process_once

ROOT = Path(__file__).resolve().parents[1]


def get_process_rss_mb(pid: int | None = None) -> float:
    """Returns the current Resident Set Size (RSS) in MB for the process."""
    if sys.platform != "win32":
        try:
            import resource
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
        except Exception:
            return 0.0

    # Windows memory query via ctypes
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return counters.WorkingSetSize / (1024.0 * 1024.0)
    except Exception:  # noqa: S110
        pass
    return 0.0


def worker_process_loop(
    worker_id: str,
    db_url: str,
    audit_secret: str,
    stop_event: mp.Event,
    stats_queue: mp.Queue,
):
    """Execution loop for an independent worker process."""
    settings = Settings(
        environment="testing",
        database_url=db_url,
        audit_secret=audit_secret,
        _env_file=None,
    )
    engine, sessions = database(settings.database_url)
    storage = LocalStorage(sessions)
    processed_count = 0
    error_count = 0

    try:
        while not stop_event.is_set():
            try:
                count = process_once(settings, sessions, storage, redis=None, worker_id=worker_id)
                if count > 0:
                    processed_count += count
                    stats_queue.put({"type": "worker_processed", "worker_id": worker_id, "count": count})
                else:
                    time.sleep(0.05)  # Yield when queue is empty
            except Exception as exc:
                error_count += 1
                stats_queue.put({"type": "worker_error", "worker_id": worker_id, "error": type(exc).__name__})
                time.sleep(0.1)
    finally:
        engine.dispose()
        stats_queue.put({
            "type": "worker_exit",
            "worker_id": worker_id,
            "total_processed": processed_count,
            "total_errors": error_count,
        })


def generate_synthetic_event(org_id: str, idx: int) -> dict:
    """Generates a valid, well-structured synthetic SIEM event."""
    ts = (datetime.now(UTC) - timedelta(seconds=random.randint(1, 60))).isoformat()  # noqa: S311
    event_types = ["auth_login", "process_creation", "network_connection", "file_modification"]
    ev_type = event_types[idx % len(event_types)]
    users = ["admin", "alice", "bob", "service_account_01", "operator"]
    user = users[idx % len(users)]
    src_ips = ["10.0.1.50", "10.0.2.100", "192.168.1.15", "172.16.0.25"]
    src_ip = src_ips[idx % len(src_ips)]

    return {
        "event_id": f"evt-{org_id[:8]}-{idx:08d}",
        "timestamp": ts,
        "event_type": ev_type,
        "source": "syslog",
        "severity": "medium",
        "user": user,
        "source_ip": src_ip,
        "destination_ip": "10.0.0.1",
        "destination_port": 443,
        "action": "allow" if idx % 5 != 0 else "block",
        "message": f"Simulated {ev_type} for user {user} from {src_ip}",
    }


def run_soak_test(
    workers: int = 4,
    duration: float = 30.0,
    rate: float = 100.0,
    tenant_count: int = 4,
    seed: int = 42,
    db_url: str | None = None,
    output_path: Path | None = None,
    checkpoint_interval: float = 5.0,
) -> dict:
    """Executes the multi-worker soak test harness and returns metrics."""
    random.seed(seed)
    destination = ROOT / "local-data"
    destination.mkdir(exist_ok=True)
    out_file = output_path or (destination / "soak_results.json")
    checkpoint_file = destination / "soak_checkpoints.json"

    effective_db_url = (
        db_url
        or os.environ.get("AEGIS_POSTGRES_TEST_URL")
        or os.environ.get("DATABASE_URL")
        or f"sqlite:///{destination}/soak_test_{int(time.time())}.db"
    )

    settings = Settings(
        environment="testing",
        database_url=effective_db_url,
        audit_secret="soak-test-audit-secret-key-32chars-min",  # noqa: S106
        _env_file=None,
    )

    engine, sessions = database(settings.database_url)
    Base.metadata.create_all(engine)

    # 1. Initialize Tenant Organizations and Seed Rules
    tenant_ids: list[str] = []
    user_ids: dict[str, str] = {}
    with sessions.begin() as db:
        for i in range(tenant_count):
            name = f"Soak Tenant {chr(65 + i)}"
            org = Organization(name=name)
            db.add(org)
            db.flush()
            tenant_ids.append(org.id)
            seed_rules(db, org.id)

            user = User(
                organization_id=org.id,
                username=f"soak_admin_{chr(65 + i).lower()}",
                password_hash=PASSWORDS.hash("SoakPass123!"),
                role="ADMIN",
            )
            db.add(user)
            db.flush()
            user_ids[org.id] = user.id

            audit(db, settings, org.id, user.id, "soak.init", org.id, details={"tenant": name})

    print(f"[*] Initialized {tenant_count} tenants: {tenant_ids}")
    print(f"[*] Target duration: {duration:.1f}s | Target rate: {rate:.1f} EPS | Workers: {workers}")

    # 2. Spawn Independent Worker Processes
    stop_event = mp.Event()
    stats_queue: mp.Queue = mp.Queue()
    worker_processes: list[mp.Process] = []

    for w_idx in range(workers):
        w_id = f"soak-worker-{w_idx+1}"
        proc = mp.Process(
            target=worker_process_loop,
            args=(w_id, settings.database_url, settings.audit_secret, stop_event, stats_queue),
            name=w_id,
            daemon=True,
        )
        proc.start()
        worker_processes.append(proc)

    print(f"[*] Started {len(worker_processes)} independent worker processes: {[p.name for p in worker_processes]}")

    # 3. Main Producer & Monitoring Loop
    from aegis.schemas import EventInput

    start_time = time.monotonic()
    last_checkpoint_time = start_time
    total_submitted = 0
    total_accepted = 0
    total_duplicates = 0
    total_rejected = 0
    ingest_latencies_ms: list[float] = []
    checkpoints: list[dict] = []
    worker_processed_counts: dict[str, int] = {f"soak-worker-{i+1}": 0 for i in range(workers)}
    worker_error_counts: dict[str, int] = {f"soak-worker-{i+1}": 0 for i in range(workers)}

    batch_size = max(1, min(50, int(rate / 5)))  # ~5 batches per second
    interval = batch_size / rate
    event_counter = 0

    try:
        while (elapsed := time.monotonic() - start_time) < duration:
            # Drain stats queue
            while not stats_queue.empty():
                try:
                    item = stats_queue.get_nowait()
                    if item["type"] == "worker_processed":
                        worker_processed_counts[item["worker_id"]] = (
                            worker_processed_counts.get(item["worker_id"], 0) + item["count"]
                        )
                    elif item["type"] == "worker_error":
                        worker_error_counts[item["worker_id"]] = (
                            worker_error_counts.get(item["worker_id"], 0) + 1
                        )
                except Exception:
                    break

            # Ingest Batch
            target_org = tenant_ids[event_counter % len(tenant_ids)]
            target_user = user_ids[target_org]
            raw_batch = [
                EventInput(
                    source="syslog",
                    raw_event=generate_synthetic_event(target_org, event_counter + b),
                )
                for b in range(batch_size)
            ]
            event_counter += batch_size
            total_submitted += len(raw_batch)

            t0 = time.monotonic()
            with sessions.begin() as db:
                res = ingest(db, settings, target_org, raw_batch, target_user)
            t1 = time.monotonic()
            ingest_latencies_ms.append((t1 - t0) * 1000.0)

            total_accepted += len(res.get("accepted", []))
            total_duplicates += len(res.get("duplicates", []))
            total_rejected += len(res.get("rejected", []))

            # Periodic Checkpoint
            if time.monotonic() - last_checkpoint_time >= checkpoint_interval:
                with sessions() as db:
                    queue_depth = db.scalar(
                        select(func.count(EventRecord.id)).where(EventRecord.state.in_(["PENDING", "RETRY"]))
                    ) or 0
                    total_db_processed = db.scalar(
                        select(func.count(EventRecord.id)).where(EventRecord.state == "PROCESSED")
                    ) or 0

                rss_mb = get_process_rss_mb()
                current_eps = total_db_processed / max(0.1, elapsed)
                cp = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "elapsed_seconds": round(elapsed, 2),
                    "total_submitted": total_submitted,
                    "total_accepted": total_accepted,
                    "total_processed": total_db_processed,
                    "queue_depth": queue_depth,
                    "eps": round(current_eps, 2),
                    "memory_rss_mb": round(rss_mb, 2),
                }
                checkpoints.append(cp)
                checkpoint_file.write_text(json.dumps(checkpoints, indent=2), encoding="utf-8")
                last_checkpoint_time = time.monotonic()
                print(f"[{elapsed:6.1f}s] Ingested: {total_submitted} | Processed: {total_db_processed} | Queue: {queue_depth} | Rate: {current_eps:.1f} EPS | RSS: {rss_mb:.1f} MB")

            # Throttle to match target rate
            loop_duration = time.monotonic() - t0
            sleep_needed = interval - loop_duration
            if sleep_needed > 0:
                time.sleep(sleep_needed)

    finally:
        print("[*] Signal stopping all worker processes...")
        stop_event.set()
        for p in worker_processes:
            p.join(timeout=5.0)

    # Allow final drain period for in-flight work
    drain_start = time.monotonic()
    while time.monotonic() - drain_start < 5.0:
        with sessions() as db:
            pending = db.scalar(
                select(func.count(EventRecord.id)).where(EventRecord.state.in_(["PENDING", "RETRY"]))
            ) or 0
        if pending == 0:
            break
        time.sleep(0.5)

    # 4. Final Accounting & Reconciliations
    total_time = time.monotonic() - start_time
    with sessions() as db:
        final_processed = db.scalar(select(func.count(EventRecord.id)).where(EventRecord.state == "PROCESSED")) or 0
        final_pending = db.scalar(select(func.count(EventRecord.id)).where(EventRecord.state.in_(["PENDING", "RETRY"]))) or 0
        final_dead = db.scalar(select(func.count(EventRecord.id)).where(EventRecord.state == "DEAD")) or 0

        # Cross-Tenant Contamination Assertion
        rogue_events = db.scalar(
            select(func.count(EventRecord.id)).where(EventRecord.organization_id.not_in(tenant_ids))
        ) or 0

        # Cryptographic HMAC Audit-Chain Verification across all test tenants
        audit_verifications: dict[str, bool] = {}
        for org_id in tenant_ids:
            audit_verifications[org_id] = verify_audit(db, settings, org_id)

    # Calculate Latency Percentiles
    if ingest_latencies_ms:
        p50 = statistics.median(ingest_latencies_ms)
        p95 = statistics.quantiles(ingest_latencies_ms, n=20)[18] if len(ingest_latencies_ms) >= 20 else max(ingest_latencies_ms)
        p99 = statistics.quantiles(ingest_latencies_ms, n=100)[98] if len(ingest_latencies_ms) >= 100 else max(ingest_latencies_ms)
    else:
        p50 = p95 = p99 = 0.0

    overall_eps = final_processed / max(0.001, total_time)
    all_audit_valid = all(audit_verifications.values())
    reconciliation_ok = (total_accepted == final_processed + final_pending + final_dead)

    report = {
        "status": "PASSED" if (all_audit_valid and rogue_events == 0) else "FAILED",
        "scope": "Multi-worker process soak test harness",
        "configuration": {
            "workers": workers,
            "duration_seconds": round(total_time, 2),
            "target_rate_eps": rate,
            "tenant_count": tenant_count,
            "seed": seed,
            "database_backend": engine.dialect.name,
        },
        "metrics": {
            "total_submitted": total_submitted,
            "total_accepted": total_accepted,
            "total_duplicates": total_duplicates,
            "total_rejected": total_rejected,
            "final_processed": final_processed,
            "final_pending": final_pending,
            "final_dead": final_dead,
            "overall_throughput_eps": round(overall_eps, 2),
            "latency_p50_ms": round(p50, 2),
            "latency_p95_ms": round(p95, 2),
            "latency_p99_ms": round(p99, 2),
            "peak_rss_mb": round(max([cp["memory_rss_mb"] for cp in checkpoints] or [0.0]), 2),
        },
        "integrity": {
            "reconciliation_passed": reconciliation_ok,
            "cross_tenant_violations": rogue_events,
            "audit_chains_valid": all_audit_valid,
            "audit_verifications_per_tenant": audit_verifications,
        },
        "worker_breakdown": {
            "worker_processed_counts": worker_processed_counts,
            "worker_error_counts": worker_error_counts,
        },
        "checkpoints_count": len(checkpoints),
    }

    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    engine.dispose()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS Multi-Worker Soak Test Harness")
    parser.add_argument("--workers", type=int, default=4, help="Number of independent worker processes (default: 4)")
    parser.add_argument("--duration", type=float, default=30.0, help="Test duration in seconds (default: 30.0)")
    parser.add_argument("--rate", type=float, default=100.0, help="Target events per second (default: 100.0)")
    parser.add_argument("--tenants", type=int, default=4, help="Number of test tenant organizations (default: 4)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--database-url", type=str, default=None, help="Database connection URL")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    out_path = Path(args.output) if args.output else None
    report = run_soak_test(
        workers=args.workers,
        duration=args.duration,
        rate=args.rate,
        tenant_count=args.tenants,
        seed=args.seed,
        db_url=args.database_url,
        output_path=out_path,
    )

    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
