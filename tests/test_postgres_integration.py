"""PostgreSQL integration and concurrency reliability test suite.

Executes directly against a real PostgreSQL 17.9 instance.
Validates:
- Real PostgreSQL dialect-specific atomic upserts (ON CONFLICT DO NOTHING).
- Multi-session concurrent rate-limiting without unique-key errors.
- Multi-session concurrent audit writes, sequence allocation, and hash-chain determinism.
- Multi-session concurrent detection-window state appends without lost updates.
- Transaction rollback isolation and retry behavior.
- Worker restart resilience and idempotent duplicate event handling.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from aegis.config import Settings
from aegis.db import (
    AuditHead,
    AuditLog,
    Base,
    EventRecord,
    Organization,
    WindowState,
)
from aegis.detection import SQLState
from aegis.pipeline import ingest, seed_rules
from aegis.schemas import EventInput
from aegis.security import audit, rate_limit, verify_audit
from aegis.storage import LocalStorage
from aegis.worker import process_once

POSTGRES_TEST_URL = os.environ.get("AEGIS_POSTGRES_TEST_URL")


@pytest.fixture(scope="module")
def pg_engine():
    """Verify connectivity to isolated PostgreSQL test instance."""
    if not POSTGRES_TEST_URL:
        pytest.skip("AEGIS_POSTGRES_TEST_URL environment variable not configured")
    try:
        engine = create_engine(POSTGRES_TEST_URL, pool_pre_ping=True, connect_args={"connect_timeout": 3})
        with engine.connect() as conn:
            val = conn.execute(text("SELECT 1")).scalar()
            if val != 1:
                pytest.skip("PostgreSQL test instance not responsive")
    except Exception as exc:
        pytest.skip(f"PostgreSQL test instance unavailable at {POSTGRES_TEST_URL}: {exc}")

    # Ensure schema tables exist
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def pg_session_factory(pg_engine):
    return sessionmaker(bind=pg_engine, expire_on_commit=False)


@pytest.fixture
def pg_system(pg_engine, pg_session_factory):
    settings = Settings(
        environment="testing",
        database_url=POSTGRES_TEST_URL,
        audit_secret="pg-test-audit-integrity-key-32chars-min",
        _env_file=None,
    )
    with pg_session_factory.begin() as db:
        org = Organization(name=f"PG-Test-Org-{uuid4().hex[:8]}")
        db.add(org)
        db.flush()
        org_id = org.id
        seed_rules(db, org_id)

    return {
        "engine": pg_engine,
        "sessions": pg_session_factory,
        "settings": settings,
        "org": org_id,
    }


# ==============================================================================
# 1. CONCURRENT RATE LIMITING (POSTGRESQL ON CONFLICT DO NOTHING)
# ==============================================================================


def test_postgres_concurrent_rate_limiting(pg_system):
    """Verify that concurrent first-time requests to the PostgreSQL fallback rate limiter

    do NOT produce duplicate-key IntegrityError or InFailedSqlTransaction exceptions.
    """
    session_factory = pg_system["sessions"]
    bucket_key = f"pg_rate_test_{uuid4().hex}"
    num_threads = 10

    dummy_request = MagicMock()
    dummy_request.app.state.sessions = session_factory
    dummy_request.app.state.redis = None

    exceptions = []

    def worker_request(thread_id: int):
        try:
            rate_limit(dummy_request, bucket_key, maximum=100, seconds=60)
            return True
        except Exception as exc:
            exceptions.append(exc)
            return False

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker_request, i) for i in range(num_threads)]
        results = [f.result() for f in futures]

    assert len(exceptions) == 0, f"Exceptions occurred during concurrent rate limit: {exceptions}"
    assert all(results)


# ==============================================================================
# 2. CONCURRENT AUDIT-CHAIN WRITES & SEQUENCE ALLOCATION
# ==============================================================================


def test_postgres_concurrent_audit_writes_and_chain_integrity(pg_system):
    """Verify that concurrent audit log writes sequence correctly via AuditHead row locks

    and produce a completely verifiable HMAC-SHA256 hash chain without gaps or deadlocks.
    """
    settings = pg_system["settings"]
    session_factory = pg_system["sessions"]
    org_id = pg_system["org"]
    num_threads = 10

    def audit_worker(worker_id: int):
        with session_factory.begin() as db:
            audit(
                db,
                settings,
                org_id,
                actor=f"pg_worker_{worker_id}",
                action=f"action_{worker_id}",
                resource_id=f"res_{worker_id}",
                details={"worker": worker_id},
            )

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(audit_worker, i) for i in range(num_threads)]
        for f in futures:
            f.result()

    # Verify that AuditHead sequence_number matches exactly num_threads
    with session_factory() as db:
        head = db.get(AuditHead, org_id)
        assert head is not None
        assert head.sequence_number == num_threads

        # Verify entire HMAC hash chain across all concurrent records
        records = list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.organization_id == org_id)
                .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            )
        )
        assert len(records) == num_threads
        assert verify_audit(db, settings, org_id) is True


# ==============================================================================
# 3. CONCURRENT DETECTION WINDOW APPENDS (ROW-LEVEL LOCKING)
# ==============================================================================


def test_postgres_concurrent_detection_window_appends(pg_system):
    """Verify that multi-session concurrent updates to WindowState do not lose updates

    when using PostgreSQL SELECT ... FOR UPDATE row locking.
    """
    session_factory = pg_system["sessions"]
    window_key = f"pg_win_{uuid4().hex}"
    num_threads = 10

    def append_worker(worker_id: int):
        with session_factory.begin() as db:
            state = SQLState(db)
            event_item = {
                "event_id": f"evt-{worker_id}",
                "timestamp": datetime.now(UTC).isoformat(),
                "weight": worker_id * 10,
            }
            state.append(window_key, event_item, window=120)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(append_worker, i) for i in range(num_threads)]
        for f in futures:
            f.result()

    # Verify that 100% of event entries were preserved without lost updates
    with session_factory() as db:
        row = db.get(WindowState, window_key)
        assert row is not None
        appended_ids = {item["event_id"] for item in row.data}
        expected_ids = {f"evt-{i}" for i in range(num_threads)}
        assert appended_ids == expected_ids
        assert len(row.data) == num_threads


# ==============================================================================
# 4. TRANSACTION ROLLBACK ISOLATION AND RETRY BEHAVIOR
# ==============================================================================


def test_postgres_transaction_rollback_and_retry_behavior(pg_system):
    """Verify that an aborted transaction rolls back completely and a clean retry

    succeeds without poisoning subsequent queries or connections in the pool.
    """
    session_factory = pg_system["sessions"]
    test_key = f"rollback_test_{uuid4().hex[:8]}"

    # 1. Execute an intentionally aborted transaction
    try:
        with session_factory.begin() as db:
            db.add(WindowState(key=test_key, data=[1], expires=999999.0))
            db.flush()
            # Trigger deliberate exception
            raise RuntimeError("Deliberate abort to test rollback")
    except RuntimeError:
        pass

    # 2. Verify that the uncommitted row was rolled back
    with session_factory() as db:
        assert db.get(WindowState, test_key) is None

    # 3. Clean transaction retry succeeds on recycled connection
    with session_factory.begin() as db:
        db.add(WindowState(key=test_key, data=[42], expires=999999.0))

    with session_factory() as db:
        row = db.get(WindowState, test_key)
        assert row is not None
        assert row.data == [42]


# ==============================================================================
# 5. WORKER RESTART AND IDEMPOTENT DUPLICATE EVENT INGESTION
# ==============================================================================


def test_postgres_worker_restart_and_duplicate_event_handling(pg_system):
    """Verify that ingesting identical duplicate events into PostgreSQL does not create

    duplicate alert states or corrupt correlation state across worker passes.
    """
    settings = pg_system["settings"]
    session_factory = pg_system["sessions"]
    org_id = pg_system["org"]
    storage = LocalStorage(session_factory)
    source_id = f"pg-dup-src-{uuid4().hex[:6]}"

    event = EventInput(
        source=source_id,
        source_type="json",
        collector="pg-test-agent",
        source_sequence="seq-001",
        timestamp=datetime.now(UTC),
        raw_event={
            "message": "User failed logon",
            "host": "PG-SRV-01",
            "source_ip": "10.0.0.99",
            "username": "target_user",
            "event_category": "authentication",
            "action": "logon",
            "outcome": "failure",
        },
    )

    # 1. Ingest event first time
    with session_factory.begin() as db:
        res_1 = ingest(db, settings, org_id, [event], source_id)
        assert len(res_1["accepted"]) == 1

    # 2. Ingest duplicate event (same source, sequence, and payload)
    with session_factory.begin() as db:
        res_2 = ingest(db, settings, org_id, [event], source_id)
        # Ingestion deduplication drops duplicate
        assert len(res_2["accepted"]) == 0
        assert len(res_2["duplicates"]) == 1

    # 3. Process worker pass
    processed = process_once(settings, session_factory, storage)
    assert processed >= 1

    # 4. Simulate worker restart / re-run worker: no new events claimed
    re_processed = process_once(settings, session_factory, storage)
    assert re_processed == 0

    # 5. Check database contains exactly one event record for this sequence
    with session_factory() as db:
        records = list(
            db.scalars(
                select(EventRecord).where(
                    EventRecord.organization_id == org_id,
                    EventRecord.source == source_id,
                )
            )
        )
        assert len(records) == 1


# ==============================================================================
# 6. MIGRATION FROM PREVIOUS SCHEMA (0004) TO CURRENT SCHEMA (0005)
# ==============================================================================


def test_postgres_schema_migration_previous_to_current(pg_engine):
    """Verify clean upgrade from previous schema (0004) to hardened schema (0005) on PostgreSQL."""
    from pathlib import Path

    import psycopg
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    mig_db_name = f"aegis_mig_{uuid4().hex[:8]}"

    # Create temporary database outside transaction
    raw_conn = psycopg.connect(
        "postgresql://aegis:7801778711a54980fe47b0e2807da5a0a9c9313e73df9914@127.0.0.1:5433/postgres",
        autocommit=True,
    )
    try:
        raw_conn.execute(f"CREATE DATABASE {mig_db_name}")
        mig_url = f"postgresql+psycopg://aegis:7801778711a54980fe47b0e2807da5a0a9c9313e73df9914@127.0.0.1:5433/{mig_db_name}"
        cfg.set_main_option("sqlalchemy.url", mig_url)

        # 1. Migrate to revision 0004 (previous schema)
        command.upgrade(cfg, "0004")

        mig_engine = create_engine(mig_url)
        with mig_engine.connect() as conn:
            v = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert v == "0004"
            tables = set(conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).scalars().all())
            assert "agents" not in tables
            assert "audit_heads" not in tables
            assert "audit_checkpoints" not in tables

        # 2. Upgrade to revision 0005 (current schema)
        command.upgrade(cfg, "0005")

        with mig_engine.connect() as conn:
            v_after = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert v_after == "0005"
            tables_after = set(conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).scalars().all())
            assert "agents" in tables_after
            assert "audit_heads" in tables_after
            assert "audit_checkpoints" in tables_after
            assert "agent_enrollment_tokens" in tables_after

        mig_engine.dispose()
    finally:
        raw_conn.execute(f"DROP DATABASE IF EXISTS {mig_db_name}")
        raw_conn.close()

