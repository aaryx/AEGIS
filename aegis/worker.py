import logging
import os
import signal
import threading
import time

from redis import Redis
from sqlalchemy import delete, select

from aegis.config import get_settings
from aegis.db import EventRecord, SearchJob, WindowState, WorkerHeartbeat, database
from aegis.pipeline import detect_batch
from aegis.storage import LocalStorage, OpenSearchStorage

logger = logging.getLogger("aegis.worker")


def heartbeat(db, worker_id, processed=0):
    row = db.get(WorkerHeartbeat, worker_id)
    if not row:
        row = WorkerHeartbeat(id=worker_id, processed=0)
        db.add(row)
    row.last_seen = time.time()
    row.processed += processed


def project_once(settings, sessions, storage) -> int:
    """Idempotent search outbox. Never rolls back completed detections."""
    with sessions.begin() as db:
        jobs = list(
            db.scalars(
                select(SearchJob)
                .where(SearchJob.state.in_(["PENDING", "RETRY"]), SearchJob.available_at <= time.time())
                .order_by(SearchJob.available_at, SearchJob.event_id)
                .with_for_update(skip_locked=True)
                .limit(settings.worker_batch_size)
            )
        )
        if not jobs:
            return 0
        records = {
            row.id: row
            for row in db.scalars(
                select(EventRecord).where(EventRecord.id.in_([job.event_id for job in jobs]))
            )
        }
        by_org: dict[str, list] = {}
        for job in jobs:
            by_org.setdefault(job.organization_id, []).append(job)
        indexed = 0
        for org, group in by_org.items():
            try:
                storage.index(org, [records[job.event_id].payload for job in group])
            except Exception as exc:
                logger.error(
                    "search_projection_failed",
                    extra={"error_type": type(exc).__name__, "event_count": len(group)},
                )
                for job in group:
                    job.attempts += 1
                    job.state = "DEAD" if job.attempts >= settings.worker_max_attempts else "RETRY"
                    job.available_at = time.time() + min(300, 2**job.attempts)
                    job.last_error = type(exc).__name__
            else:
                for job in group:
                    job.state, job.last_error = "INDEXED", None
                indexed += len(group)
        return indexed


def process_once(settings, sessions, storage, redis=None, worker_id="local") -> int:
    processed = 0
    with sessions.begin() as db:
        records = list(
            db.scalars(
                select(EventRecord)
                .where(
                    EventRecord.state.in_(["PENDING", "RETRY"]),
                    EventRecord.available_at <= time.time(),
                )
                .order_by(EventRecord.available_at, EventRecord.timestamp, EventRecord.created_at, EventRecord.id)
                .with_for_update(skip_locked=True)
                .limit(settings.worker_batch_size)
            )
        )
        if records:
            by_org: dict[str, list[EventRecord]] = {}
            for rec in records:
                by_org.setdefault(rec.organization_id, []).append(rec)
            for _org_id, org_records in by_org.items():
                try:
                    with db.begin_nested():
                        detect_batch(db, settings, org_records, redis=redis)
                    processed += len(org_records)
                except Exception:
                    # A poison event must not exhaust the retries of valid sibling events.
                    for record in org_records:
                        try:
                            with db.begin_nested():
                                detect_batch(db, settings, [record], redis=redis)
                            processed += 1
                        except Exception as exc:
                            record.attempts += 1
                            record.state = "DEAD" if record.attempts >= settings.worker_max_attempts else "RETRY"
                            record.available_at = time.time() + min(300, 2**record.attempts)
                            record.last_error = type(exc).__name__
                            logger.error(
                                "event_processing_failed",
                                extra={"error_type": type(exc).__name__, "event_count": 1},
                            )
        heartbeat(db, worker_id, processed)
        db.execute(delete(WindowState).where(WindowState.expires < time.time()))
    project_once(settings, sessions, storage)
    return processed


def main():
    from aegis.observability import configure_logging

    configure_logging()
    settings = get_settings()
    engine, sessions = database(settings.database_url)
    redis = (
        Redis.from_url(settings.redis_url, socket_timeout=3, socket_connect_timeout=3)
        if settings.redis_url
        else None
    )
    storage = OpenSearchStorage(settings) if settings.opensearch_url else LocalStorage(sessions)
    worker_id = f"{os.environ.get('HOSTNAME', 'local')}-{os.getpid()}"
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    try:
        while not stopped.is_set():
            try:
                count = process_once(settings, sessions, storage, redis, worker_id)
            except Exception as exc:
                logger.error("worker_iteration_failed", extra={"error_type": type(exc).__name__})
                stopped.wait(5)
            else:
                if not count:
                    stopped.wait(2)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
