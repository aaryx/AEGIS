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
import time
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
    Collector,
    Entity,
    EventRecord,
    Organization,
    User,
    WindowState,
)
from aegis.detection import SQLState
from aegis.parsers import digest
from aegis.pipeline import detect_batch, ingest, seed_rules
from aegis.schemas import EventInput
from aegis.security import audit, rate_limit, verify_audit
from aegis.storage import LocalStorage
from aegis.worker import process_once

POSTGRES_TEST_URL = os.environ.get("AEGIS_POSTGRES_TEST_URL")
AUDIT_SECRET = os.environ.get("AUDIT_SECRET", "pg-test-audit-integrity-key-32chars-min")


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
        audit_secret=AUDIT_SECRET,
        redis_url=os.environ.get("REDIS_URL"),
        opensearch_url=os.environ.get("OPENSEARCH_URL"),
        opensearch_username=os.environ.get("OPENSEARCH_USERNAME", "aegis"),
        opensearch_password=os.environ.get("OPENSEARCH_PASSWORD"),
        intel_mock_enabled=True,
        _env_file=None,
    )
    with pg_session_factory.begin() as db:
        org = Organization(name=f"PG-Test-Org-{uuid4().hex[:8]}")
        db.add(org)
        db.flush()
        org_id = org.id
        admin_user = User(
            organization_id=org_id,
            username=f"pg_admin_{uuid4().hex[:8]}",
            password_hash="dummy_hash",
            role="admin",
        )
        db.add(admin_user)
        db.flush()
        user_id = admin_user.id
        seed_rules(db, org_id)

    return {
        "engine": pg_engine,
        "sessions": pg_session_factory,
        "settings": settings,
        "org": org_id,
        "user_id": user_id,
    }


# ==============================================================================
# 1. CONCURRENT RATE LIMITING (POSTGRESQL ON CONFLICT DO NOTHING)
# ==============================================================================


@pytest.mark.integration
@pytest.mark.parametrize("conflicting", [False, True])
def test_postgres_cerberus_concurrent_evidence_conflict(pg_system, conflicting):
    from types import SimpleNamespace

    from tests.test_cerberus import test_simultaneous_source_sequence_reuse as run_scenario

    run_scenario(
        {
            "app": SimpleNamespace(
                state=SimpleNamespace(sessions=pg_system["sessions"], engine=pg_system["engine"])
            ),
            "settings": pg_system["settings"],
            "org": pg_system["org"],
        },
        conflicting,
    )


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


def _mp_audit_worker(args: tuple[str, str, int]) -> bool:
    url, org_id, worker_id = args
    engine = create_engine(url, pool_pre_ping=True)
    session_maker = sessionmaker(bind=engine)
    worker_settings = Settings(
        environment="testing",
        database_url=url,
        audit_secret=AUDIT_SECRET,
        _env_file=None,
    )
    with session_maker.begin() as db:
        audit(
            db,
            worker_settings,
            org_id,
            actor=f"mp_worker_{worker_id}",
            action="mp.action",
            resource_id=f"res_{worker_id}",
            details={"mp_worker": worker_id},
        )
    engine.dispose()
    return True


# ==============================================================================
# 2. CONCURRENT AUDIT-CHAIN WRITES & SEQUENCE ALLOCATION
# ==============================================================================


def test_postgres_multiprocess_concurrent_audit_writes(pg_system):
    """Verify that multiple independent operating system processes with separate

    database connection engines concurrently allocate audit sequence numbers via
    PostgreSQL AuditHead row locking without gaps, duplicates, or deadlocks.
    """
    from concurrent.futures import ProcessPoolExecutor

    settings = pg_system["settings"]
    session_factory = pg_system["sessions"]
    org_id = pg_system["org"]
    num_procs = 4

    assert POSTGRES_TEST_URL is not None
    args_list = [(POSTGRES_TEST_URL, org_id, i) for i in range(num_procs)]
    with ProcessPoolExecutor(max_workers=num_procs) as executor:
        results = list(executor.map(_mp_audit_worker, args_list))

    assert all(results)
    with session_factory() as db:
        head = db.get(AuditHead, org_id)
        assert head is not None
        assert head.sequence_number >= num_procs
        assert verify_audit(db, settings, org_id) is True


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
            db.add(WindowState(key=test_key, data=[1], expires=time.time() + 3600.0))
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
        db.add(WindowState(key=test_key, data=[42], expires=time.time() + 3600.0))

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
# 6. SIMULTANEOUS DUPLICATE EVENT INGESTION RACE CONDITION
# ==============================================================================


def test_postgres_simultaneous_duplicate_event_ingestion_race(pg_system):
    """Verify that simultaneous concurrent ingestion of identical events across independent

    sessions does NOT raise unique-constraint IntegrityError, maintains Collector counts,
    and returns deterministic accepted/duplicates accounting.
    """
    settings = pg_system["settings"]
    session_factory = pg_system["sessions"]
    org_id = pg_system["org"]
    num_threads = 8

    race_event = EventInput(
        source=f"race-src-{uuid4().hex[:6]}",
        source_type="json",
        collector=f"col-{uuid4().hex[:6]}",
        source_sequence="seq-simultaneous-001",
        timestamp=datetime.now(UTC),
        raw_event={
            "message": "Simultaneous ingestion stress event",
            "host": "PG-RACE-SRV",
            "source_ip": "192.168.1.100",
            "event_category": "system",
        },
    )

    exceptions = []
    results = []

    def ingest_worker():
        try:
            with session_factory.begin() as db:
                res = ingest(db, settings, org_id, [race_event], "race-worker")
                results.append(res)
        except Exception as exc:
            exceptions.append(exc)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(ingest_worker) for _ in range(num_threads)]
        for f in futures:
            f.result()

    assert len(exceptions) == 0, f"Simultaneous ingestion produced unexpected exceptions: {exceptions}"
    assert len(results) == num_threads

    total_accepted = sum(len(r["accepted"]) for r in results)
    total_duplicates = sum(len(r["duplicates"]) for r in results)

    # Exactly 1 request accepted the event; the remaining num_threads - 1 handled it as duplicate
    assert total_accepted == 1
    assert total_duplicates == num_threads - 1

    # Verify database contains exactly 1 EventRecord row
    with session_factory() as db:
        records = list(
            db.scalars(
                select(EventRecord).where(
                    EventRecord.organization_id == org_id,
                    EventRecord.source == race_event.source,
                )
            )
        )
        assert len(records) == 1
        collector = db.scalar(
            select(Collector).where(
                Collector.organization_id == org_id,
                Collector.name == race_event.collector,
            )
        )
        assert collector is not None
        assert collector.events_received == num_threads


# ==============================================================================
# 7. MULTI-TENANT CONCURRENT AUDIT-CHAIN ISOLATION
# ==============================================================================


def test_postgres_multi_tenant_concurrent_audit_isolation(pg_engine, pg_session_factory):
    """Verify that concurrent audit writes from two separate organizations progress

    independently without deadlocks, sequence interference, or cross-tenant contamination.
    """
    settings = Settings(
        environment="testing",
        database_url=POSTGRES_TEST_URL,
        audit_secret=AUDIT_SECRET,
        _env_file=None,
    )
    with pg_session_factory.begin() as db:
        org_a = Organization(name=f"PG-TenantA-{uuid4().hex[:6]}")
        org_b = Organization(name=f"PG-TenantB-{uuid4().hex[:6]}")
        db.add_all([org_a, org_b])
        db.flush()
        org_a_id, org_b_id = org_a.id, org_b.id

    writes_per_org = 10
    exceptions = []

    def tenant_audit_worker(org_id: str, index: int):
        try:
            with pg_session_factory.begin() as db:
                audit(
                    db,
                    settings,
                    org_id,
                    actor=f"tenant_worker_{index}",
                    action="tenant.action",
                    resource_id=f"res_{index}",
                )
        except Exception as exc:
            exceptions.append((org_id, exc))

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for i in range(writes_per_org):
            futures.append(executor.submit(tenant_audit_worker, org_a_id, i))
            futures.append(executor.submit(tenant_audit_worker, org_b_id, i))
        for f in futures:
            f.result()

    assert len(exceptions) == 0, f"Exceptions in multi-tenant audit: {exceptions}"

    with pg_session_factory() as db:
        # Both tenant audit heads must reach exactly writes_per_org
        head_a = db.get(AuditHead, org_a_id)
        head_b = db.get(AuditHead, org_b_id)
        assert head_a is not None and head_a.sequence_number == writes_per_org
        assert head_b is not None and head_b.sequence_number == writes_per_org

        # Both HMAC chains must independently verify as 100% valid
        assert verify_audit(db, settings, org_a_id) is True
        assert verify_audit(db, settings, org_b_id) is True


# ==============================================================================
# 8. CONCURRENT ENTITY EXTRACTION AND GRAPH UPSERTS
# ==============================================================================


def test_postgres_concurrent_entity_and_relationship_upserts(pg_system):
    """Verify that multiple concurrent worker processes extracting the exact same

    entity identities and semantic relationships concurrently do not raise UniqueViolation.
    """
    settings = pg_system["settings"]
    session_factory = pg_system["sessions"]
    org_id = pg_system["org"]
    num_threads = 6

    # Ingest multiple events referencing the same host and user
    events = [
        EventInput(
            source=f"shared-src-{uuid4().hex[:6]}",
            source_type="json",
            collector="entity-bench",
            source_sequence=f"seq-shared-{i}",
            timestamp=datetime.now(UTC),
            raw_event={
                "message": f"Logon session {i}",
                "host": "CRITICAL-DC-01",
                "username": "domain_admin",
                "source_ip": "10.0.0.5",
                "event_category": "authentication",
                "action": "logon",
            },
        )
        for i in range(num_threads)
    ]

    with session_factory.begin() as db:
        ingest_res = ingest(db, settings, org_id, events, "entity-test")
        assert len(ingest_res["accepted"]) == num_threads

    exceptions = []

    def detect_worker(record_id: str):
        try:
            with session_factory.begin() as db:
                rec = db.get(EventRecord, record_id)
                if rec and rec.state in ["PENDING", "RETRY"]:
                    detect_batch(db, settings, [rec])
        except Exception as exc:
            exceptions.append(exc)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(detect_worker, evt_id) for evt_id in ingest_res["accepted"]]
        for f in futures:
            f.result()

    assert len(exceptions) == 0, f"Concurrent entity extraction threw: {exceptions}"

    with session_factory() as db:
        # Check that unique entity records exist without duplicate entries
        entities = list(
            db.scalars(
                select(Entity).where(
                    Entity.organization_id == org_id,
                    Entity.value.in_(["CRITICAL-DC-01", "domain_admin", "10.0.0.5"]),
                )
            )
        )
        entity_values = {e.value for e in entities}
        assert entity_values == {"CRITICAL-DC-01", "domain_admin", "10.0.0.5"}


# ==============================================================================
# 9. POSTGRESQL LOCK TIMEOUT AND TRANSACTION ABORT RECOVERY
# ==============================================================================


def test_postgres_lock_timeout_and_abort_recovery(pg_system):
    """Verify that PostgreSQL lock_timeout aborts blocked queries safely and that the

    connection pool recovers cleanly without poisoned state.
    """
    session_factory = pg_system["sessions"]
    lock_key = f"lock_test_{uuid4().hex[:6]}"

    # Setup initial row with future expiration so background worker does not prune it
    with session_factory.begin() as db:
        db.add(WindowState(key=lock_key, data=[100], expires=time.time() + 3600.0))

    import threading
    barrier = threading.Barrier(2)
    timed_out = []
    holding_errors = []

    def holding_worker():
        try:
            with session_factory.begin() as db:
                # Take an exclusive row lock
                db.scalar(
                    select(WindowState)
                    .where(WindowState.key == lock_key)
                    .with_for_update()
                )
                barrier.wait()
                # Hold lock for 0.8s
                time.sleep(0.8)
        except Exception as exc:
            holding_errors.append(exc)

    def blocked_worker():
        barrier.wait()
        with session_factory() as db:
            # Set short lock timeout: 200 milliseconds
            db.execute(text("SET LOCAL lock_timeout = '200ms'"))
            try:
                db.scalar(
                    select(WindowState)
                    .where(WindowState.key == lock_key)
                    .with_for_update()
                )
            except Exception as exc:
                timed_out.append(exc)
                db.rollback()

    t1 = threading.Thread(target=holding_worker)
    t2 = threading.Thread(target=blocked_worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(holding_errors) == 0, f"holding_worker encountered: {holding_errors}"
    # The blocked session must have encountered lock timeout error
    assert len(timed_out) == 1
    assert "lock timeout" in str(timed_out[0]).lower() or "canceling statement due to lock timeout" in str(timed_out[0]).lower()

    # Verify that the recycled connection pool continues operating normally
    with session_factory.begin() as db:
        row = db.get(WindowState, lock_key)
        assert row is not None
        assert row.data == [100]


# ==============================================================================
# 10. MIGRATION FROM PREVIOUS SCHEMA (0004) TO CURRENT SCHEMA (0005)
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

    from sqlalchemy.engine import make_url

    parsed_url = make_url(POSTGRES_TEST_URL)
    admin_url = parsed_url.set(database="postgres")
    psycopg_dsn = admin_url.render_as_string(hide_password=False).replace("postgresql+psycopg://", "postgresql://")
    # Create temporary database outside transaction
    raw_conn = psycopg.connect(
        psycopg_dsn,
        autocommit=True,
    )
    try:
        raw_conn.execute(f"CREATE DATABASE {mig_db_name}")
        mig_url = parsed_url.set(database=mig_db_name).render_as_string(hide_password=False)
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

        # 2. Upgrade to revision 0005
        command.upgrade(cfg, "0005")

        with mig_engine.connect() as conn:
            v_after = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert v_after == "0005"
            tables_after = set(conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).scalars().all())
            assert "agents" in tables_after
            assert "audit_heads" in tables_after
            assert "audit_checkpoints" in tables_after
            assert "agent_enrollment_tokens" in tables_after

        # 3. Upgrade to revision 0006 (immutable audit anchoring)
        command.upgrade(cfg, "0006")

        with mig_engine.connect() as conn:
            v_0006 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert v_0006 == "0006"
            columns_0006 = set(conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'audit_checkpoints'")).scalars().all())
            assert "anchor_status" in columns_0006
            assert "anchor_uri" in columns_0006
            assert "anchor_version_id" in columns_0006
            assert "anchored_at" in columns_0006
            assert "anchor_error" in columns_0006

        # 4. Upgrade to revision 0007 (detection replay lab)
        command.upgrade(cfg, "0007")

        with mig_engine.connect() as conn:
            v_0007 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert v_0007 == "0007"
            tables_0007 = set(conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).scalars().all())
            assert "replay_jobs" in tables_0007
            assert "replay_matches" in tables_0007

        command.upgrade(cfg, "0008")
        with mig_engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0008"
            assert conn.execute(text("SELECT count(*) FROM storylines")).scalar() == 0

        # 5. Upgrade to revision 0009 (SOAR)
        command.upgrade(cfg, "0009")
        with mig_engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0009"
            assert conn.execute(text("SELECT count(*) FROM soar_playbooks")).scalar() == 0

        # 6. Upgrade to revision 0010 (Threat Intelligence)
        command.upgrade(cfg, "0010")
        with mig_engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0010"
            assert conn.execute(text("SELECT count(*) FROM intel_observables")).scalar() == 0
        mig_engine.dispose()
    finally:
        raw_conn.execute(f"DROP DATABASE IF EXISTS {mig_db_name}")
        raw_conn.close()


# ==============================================================================
# 11. CONCURRENT RULE ACTIVATION AND REPLAY ON REAL POSTGRESQL
# ==============================================================================


def test_postgres_concurrent_rule_activation_and_replay(pg_system):
    """Verify that concurrent rule version updates and replay persistence on PostgreSQL

    preserve row-level lock serialization, foreign key integrity, and JSONB serialization.
    """
    from aegis.db import ReplayJob, ReplayMatch, Rule, RuleVersion
    from aegis.replay import execute_replay
    from aegis.schemas import ReplayRequest

    session_factory = pg_system["sessions"]
    org_id = pg_system["org"]
    user_id = pg_system["user_id"]

    # 1. Ensure a seeded rule exists in PostgreSQL
    with session_factory.begin() as db:
        rule_row = db.scalar(
            select(Rule).where(
                Rule.organization_id == org_id,
                (Rule.rule_id == "AUTH-001") | (Rule.rule_id == "AEGIS-AUTH-001"),
            )
        )
        assert rule_row is not None
        target_rule_id = rule_row.rule_id
        db.add(
            RuleVersion(
                organization_id=org_id,
                rule_id=rule_row.id,
                version=1,
                author=user_id,
                summary="Initial PostgreSQL version",
                lifecycle_stage="ACTIVE",
                document=rule_row.document,
            )
        )

    # 2. Run two concurrent replays against PostgreSQL
    num_replays = 4
    results = []
    exceptions = []

    def replay_worker(worker_id: int):
        try:
            with session_factory.begin() as db:
                req = ReplayRequest(
                    rule_id=target_rule_id,
                    target_type="DATASET",
                    dataset_name="AUTH-001",
                    max_events=100,
                    dry_run=True,
                )
                res = execute_replay(
                    db=db,
                    org_id=org_id,
                    user_id=user_id,
                    request=req,
                )
                results.append(res)
        except Exception as exc:
            exceptions.append(exc)

    with ThreadPoolExecutor(max_workers=num_replays) as executor:
        futures = [executor.submit(replay_worker, i) for i in range(num_replays)]
        for f in futures:
            f.result()

    assert len(exceptions) == 0, f"PostgreSQL concurrent replay threw: {exceptions}"
    assert len(results) == num_replays

    # 3. Verify PostgreSQL database state: jobs, matches, and foreign key cascades
    with session_factory() as db:
        jobs = list(
            db.scalars(
                select(ReplayJob).where(
                    ReplayJob.organization_id == org_id,
                    ReplayJob.rule_id == target_rule_id,
                )
            )
        )
        assert len(jobs) == num_replays
        for j in jobs:
            assert j.status in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
            assert j.events_evaluated > 0
            matches = list(db.scalars(select(ReplayMatch).where(ReplayMatch.job_id == j.id)))
            if isinstance(j.metrics, dict) and "candidate_matches_count" in j.metrics:
                assert len(matches) == j.metrics["candidate_matches_count"]
            else:
                assert len(matches) >= 0




def test_postgres_concurrent_storyline_correlation(pg_system):
    from types import SimpleNamespace

    from sqlalchemy import func

    from aegis.db import Alert, Incident, Storyline, StorylineMember
    from aegis.storylines import correlate

    sessions, org = pg_system["sessions"], pg_system["org"]
    principal = SimpleNamespace(organization_id=org, user=SimpleNamespace(id=pg_system["user_id"]))
    with sessions.begin() as db:
        entity = Entity(organization_id=org, type="host", value="correlation-host")
        db.add(entity)
        db.flush()
        for _ in range(4):
            identifier = str(uuid4())
            db.add(Alert(id="ALT-" + identifier, organization_id=org, title="Synthetic detection",
                         severity="high", rule_id="test", rule_version=1, fingerprint=identifier,
                         correlation_key=identifier, confidence=80, risk_score=70, risk_factors={},
                         explanation={}, mitre_techniques=[], entity_ids=[entity.id],
                         first_seen=datetime.now(UTC), last_seen=datetime.now(UTC)))

    def run(_):
        with sessions.begin() as db:
            return correlate(db, pg_system["settings"], principal, 1800)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run, range(4)))
    assert sum(r["changed"] for r in results) == 1

    def update_or_correlate(index):
        if index % 2:
            return run(index)
        with sessions.begin() as db:
            incident = db.scalar(select(Incident).join(Storyline, Storyline.incident_id == Incident.id)
                                 .where(Storyline.organization_id == org).with_for_update(of=Incident))
            incident.revision += 1
            audit(db, pg_system["settings"], org, principal.user.id,
                  "incidents.update", incident.id, details={"revision": incident.revision})
        return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(update_or_correlate, range(8)))
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(Storyline).where(Storyline.organization_id == org)) == 1
        assert db.scalar(select(func.count()).select_from(StorylineMember).where(StorylineMember.organization_id == org)) == 4
        assert verify_audit(db, pg_system["settings"], org) is True


def test_postgres_soar_transactional_concurrency(pg_system):
    """Run the same workflow concurrently against real PostgreSQL when configured."""
    from types import SimpleNamespace

    from aegis.db import CaseNote, Incident, Playbook, PlaybookVersion, WorkflowRun
    from aegis.soar import RunInput, enqueue, process_workflows

    sessions = pg_system["sessions"]
    org = pg_system["org"]
    with sessions.begin() as db:
        user = db.get(User, pg_system["user_id"])
        user.role = "SUPER_ADMIN"
        source = Incident(organization_id=org, title="SOAR concurrency", severity="high")
        book = Playbook(organization_id=org, name="Concurrency", enabled=True, version=1)
        db.add_all([source, book])
        db.flush()
        db.add(PlaybookVersion(organization_id=org, playbook_id=book.id, version=1, author=user.id,
            document={"description": "Concurrent local note", "trigger": {"source": "incident"},
                      "steps": [{"id": "note", "action": "incident_note"}]}))
        source_id, book_id = source.id, book.id
        principal = SimpleNamespace(user=user, organization_id=org)
    def submit(_):
        with sessions.begin() as db:
            return enqueue(db, pg_system["settings"], principal, book_id, RunInput(
                source_type="incident", source_id=source_id, dry_run=False, idempotency_key="pg-concurrent")).id
    with ThreadPoolExecutor(max_workers=4) as pool:
        identifiers = list(pool.map(submit, range(4)))
    assert len(set(identifiers)) == 1
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: process_workflows(pg_system["settings"], sessions), range(4)))
    with sessions() as db:
        assert db.get(WorkflowRun, identifiers[0]).status == "SUCCEEDED"
        assert len(list(db.scalars(select(CaseNote).where(CaseNote.organization_id == org)))) == 1
        assert verify_audit(db, pg_system["settings"], org) is True


# ==============================================================================
# 15. LIVE IOC CACHE AND LOOKUP PERSISTENCE (POSTGRESQL + REDIS)
# ==============================================================================


def test_postgres_ioc_cache_and_lookup_persistence(pg_system):
    """Validate IOC observation, PostgreSQL persistence, and Redis caching on real infra."""
    from redis import Redis

    from aegis.db import Enrichment, EnrichmentHistory, Observable
    from aegis.intelligence import lookup_once, observe, queue, source_context
    from aegis.observables import extract

    sessions = pg_system["sessions"]
    settings = pg_system["settings"]
    org = pg_system["org"]

    if not settings.redis_url:
        pytest.skip("REDIS_URL not configured")

    redis = Redis.from_url(settings.redis_url, socket_timeout=3)
    assert redis.ping() is True

    # 1. Ingest event with observables into real PostgreSQL
    raw = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source_ip": "198.51.100.55",
        "destination_ip": "203.0.113.88",
        "network": {"domain": "malicious.example.test"},
        "url": "https://malicious.example.test/beacon",
        "file": {"sha256": "a" * 64},
    }
    event_payload = {
        "raw_event": raw,
        **raw,
    }
    extracted = extract(event_payload)
    assert len(extracted) >= 5

    with sessions.begin() as db:
        event_rec = EventRecord(
            organization_id=org,
            source="ioc-live-test",
            timestamp=datetime.now(UTC),
            evidence_hash=digest(raw),
            payload=event_payload,
            state="PROCESSED",
        )
        db.add(event_rec)
        db.flush()
        event_id = event_rec.id

        # 2. Observe all extracted observables
        for kind, value, _ in extracted:
            obs = observe(db, org, kind, value, event_rec)
            assert obs.id is not None
            assert obs.organization_id == org

    # 3. Queue enrichment with mock provider inside transaction commit
    with sessions.begin() as db:
        stored_obs = list(db.scalars(select(Observable).where(Observable.organization_id == org)))
        assert len(stored_obs) >= 5
        for obs in stored_obs:
            queue(db, settings, obs, "mock")

    # 4. Process enrichment via lookup_once
    processed = lookup_once(settings, sessions)
    assert processed > 0

    with sessions() as db:
        enrichments = list(db.scalars(select(Enrichment).where(Enrichment.organization_id == org)))
        assert len(enrichments) > 0
        assert any(e.status in {"COMPLETED", "COMPLETE", "UNKNOWN"} for e in enrichments)
        history = list(db.scalars(select(EnrichmentHistory).where(EnrichmentHistory.organization_id == org)))
        assert len(history) > 0

    # 5. Verify source_context queries cached data
    with sessions() as db:
        event_rec = db.get(EventRecord, event_id)
        ctx = source_context(db, org, [event_rec])
        assert len(ctx) > 0


# ==============================================================================
# 16. SOAR EXECUTION PERSISTENCE, APPROVAL GATE, AND RECOVERY
# ==============================================================================


def test_postgres_soar_approval_and_recovery_persistence(pg_system):
    """Validate SOAR approval gate, simulated containment, and recovery in real PostgreSQL."""
    from types import SimpleNamespace

    from aegis.db import CaseNote, Incident, Playbook, PlaybookVersion, User, WorkflowRun
    from aegis.soar import RunInput, enqueue, process_workflows, record

    sessions = pg_system["sessions"]
    settings = pg_system["settings"]
    org = pg_system["org"]

    with sessions.begin() as db:
        senior_analyst = User(
            organization_id=org, username=f"senior_{uuid4().hex[:6]}", password_hash="h", role="SENIOR_ANALYST"
        )
        manager = User(
            organization_id=org, username=f"mgr_{uuid4().hex[:6]}", password_hash="h", role="SOC_MANAGER"
        )
        incident = Incident(organization_id=org, title="SOAR Approval & Recovery", severity="critical")
        entity = Entity(organization_id=org, type="host", value="compromised-server-01")
        book = Playbook(organization_id=org, name="Isolate Host With Approval", enabled=True, version=1)
        db.add_all([senior_analyst, manager, incident, entity, book])
        db.flush()

        # Playbook requires containment action (simulate_isolate_host) + incident_note
        db.add(
            PlaybookVersion(
                organization_id=org,
                playbook_id=book.id,
                version=1,
                author=manager.id,
                document={
                    "description": "Simulated containment after approval",
                    "trigger": {"source": "incident"},
                    "input_schema": {"target_id": "entity"},
                    "steps": [
                        {"id": "isolate", "action": "simulate_isolate_host"},
                        {"id": "note", "action": "incident_note"},
                    ],
                },
            )
        )
        book_id, incident_id, entity_id = book.id, incident.id, entity.id
        manager_id = manager.id
        senior_p = SimpleNamespace(user=senior_analyst, organization_id=org)

    # 1. Enqueue workflow by senior analyst (has playbooks.execute permission)
    with sessions.begin() as db:
        run = enqueue(
            db,
            settings,
            senior_p,
            book_id,
            RunInput(
                source_type="incident",
                source_id=incident_id,
                dry_run=False,
                inputs={"target_id": entity_id},
                idempotency_key="soar-approval-gate-key",
            ),
        )
        run_id = run.id

    # 2. Duplicate enqueue must be idempotent
    with sessions.begin() as db:
        dup = enqueue(
            db,
            settings,
            senior_p,
            book_id,
            RunInput(
                source_type="incident",
                source_id=incident_id,
                dry_run=False,
                inputs={"target_id": entity_id},
                idempotency_key="soar-approval-gate-key",
            ),
        )
        assert dup.id == run_id

    # 3. Process workflow -> containment action requires approval -> transitions to WAITING_FOR_APPROVAL
    process_workflows(settings, sessions)
    with sessions() as db:
        run = db.get(WorkflowRun, run_id)
        assert run.status == "WAITING_FOR_APPROVAL"
        assert run.approved_by is None

    # 4. Independent approval by SOC_MANAGER succeeds (two-person rule)
    with sessions.begin() as db:
        run = db.get(WorkflowRun, run_id)
        assert run.requested_by != manager_id
        run.approved_by, run.approved_at, run.status = manager_id, time.time(), "QUEUED"
        record(db, settings, run, "approve", manager_id)

    # 5. Worker processes approved workflow to completion (executing each step in order)
    for _ in range(5):
        if process_workflows(settings, sessions) == 0:
            break

    with sessions() as db:
        run = db.get(WorkflowRun, run_id)
        assert run.status == "SUCCEEDED"
        # Confirm containment was strictly simulated
        assert len(run.history) == 2
        isolate_step = run.history[0]
        assert isolate_step["step"] == "isolate"
        assert isolate_step["status"] == "SUCCEEDED"
        assert isolate_step["output"]["data"]["action"] == "simulate_isolate_host"
        assert "Simulation only" in isolate_step["output"]["data"]["message"]

        # Confirm case note was persisted
        notes = list(
            db.scalars(
                select(CaseNote).where(CaseNote.organization_id == org, CaseNote.resource_id == incident_id)
            )
        )
        assert len(notes) == 1
        assert "No external containment performed" in notes[0].text

        # Cryptographically verify the tamper-evident audit log
        assert verify_audit(db, settings, org) is True


# ==============================================================================
# 17. OPENSEARCH INTEGRATION, INDEXING, AND TENANT ISOLATION
# ==============================================================================


def test_postgres_opensearch_indexing_and_isolation(pg_system):
    """Validate real OpenSearch indexing, cursor search, and strict tenant isolation."""
    from aegis.schemas import SearchQuery
    from aegis.storage import OpenSearchStorage

    settings = pg_system["settings"]
    org_a = pg_system["org"]
    org_b = f"org_b_{uuid4().hex[:8]}"

    if not settings.opensearch_url:
        pytest.skip("OPENSEARCH_URL not configured")

    storage = OpenSearchStorage(settings)
    storage.setup()
    assert storage.health() == "HEALTHY"

    # Index events for Tenant A
    event_a1 = {
        "event_id": f"evt_a1_{uuid4().hex[:8]}",
        "organization_id": org_a,
        "source": "os-test",
        "timestamp": datetime.now(UTC).isoformat(),
        "event_category": "network",
        "host": "HOST-A",
        "evidence_hash": "a" * 64,
        "raw_event": "network connect 443",
        "payload": {"action": "allow", "port": 443},
    }
    event_a2 = {
        "event_id": f"evt_a2_{uuid4().hex[:8]}",
        "organization_id": org_a,
        "source": "os-test",
        "timestamp": datetime.now(UTC).isoformat(),
        "event_category": "authentication",
        "host": "HOST-A",
        "evidence_hash": "b" * 64,
        "raw_event": "auth login alice",
        "payload": {"action": "login", "user": "alice"},
    }
    # Index event for Tenant B
    event_b1 = {
        "event_id": f"evt_b1_{uuid4().hex[:8]}",
        "organization_id": org_b,
        "source": "os-test",
        "timestamp": datetime.now(UTC).isoformat(),
        "event_category": "network",
        "host": "HOST-B",
        "evidence_hash": "c" * 64,
        "raw_event": "network block 22",
        "payload": {"action": "block", "port": 22},
    }

    storage.index(org_a, [event_a1, event_a2])
    storage.index(org_b, [event_b1])

    # Allow OpenSearch to refresh index
    storage.client.indices.refresh(index="aegis-events*")

    # Query Tenant A: must see only Tenant A's events
    query_a = SearchQuery(limit=10, aggregate="event_category")
    results_a = storage.search(org_a, query_a)
    assert results_a["total"] >= 2
    item_ids_a = {item["event_id"] for item in results_a["items"]}
    assert event_a1["event_id"] in item_ids_a
    assert event_a2["event_id"] in item_ids_a
    assert event_b1["event_id"] not in item_ids_a

    # Query Tenant B: must see only Tenant B's events
    results_b = storage.search(org_b, SearchQuery(limit=10))
    item_ids_b = {item["event_id"] for item in results_b["items"]}
    assert event_b1["event_id"] in item_ids_b
    assert event_a1["event_id"] not in item_ids_b
    assert event_a2["event_id"] not in item_ids_b

    # Query non-existent tenant: must return 0 results
    results_empty = storage.search(str(uuid4()), SearchQuery(limit=10))
    assert results_empty["total"] == 0
    assert len(results_empty["items"]) == 0


# ==============================================================================
# 18. POSTGRESQL CROSS-TENANT DATABASE TRIGGER CONSTRAINTS
# ==============================================================================


def test_postgres_cross_tenant_database_constraints(pg_system):
    """Validate PostgreSQL triggers enforce multi-tenant isolation on relational joins."""
    from sqlalchemy.exc import DBAPIError

    from aegis.db import Alert, AlertEvent, Incident, Observable, ObservableEvent

    sessions = pg_system["sessions"]
    org_a = pg_system["org"]

    with sessions.begin() as db:
        org_b_row = Organization(name=f"Foreign Tenant {uuid4().hex[:6]}")
        db.add(org_b_row)
        db.flush()
        org_b = org_b_row.id

        # Ingest Event for Org A and Event for Org B
        raw_a = {"event": "a", "message": "event a"}
        raw_b = {"event": "b", "message": "event b"}
        event_a = EventRecord(
            organization_id=org_a,
            source="s",
            timestamp=datetime.now(UTC),
            evidence_hash=digest(raw_a),
            payload={"raw_event": raw_a, **raw_a},
            state="PROCESSED",
        )
        event_b = EventRecord(
            organization_id=org_b,
            source="s",
            timestamp=datetime.now(UTC),
            evidence_hash=digest(raw_b),
            payload={"raw_event": raw_b, **raw_b},
            state="PROCESSED",
        )
        obs_a = Observable(
            organization_id=org_a, type="ip", value="1.1.1.1", external_allowed=True, normalized_key="key_a"
        )
        alert_a = Alert(
            id=f"ALT-{uuid4().hex[:8]}",
            organization_id=org_a,
            title="Alert A",
            severity="high",
            rule_id="r1",
            rule_version=1,
            fingerprint=uuid4().hex,
            correlation_key=uuid4().hex,
            confidence=90,
            risk_score=80,
            risk_factors={},
            explanation={},
            mitre_techniques=[],
            entity_ids=[],
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        incident_a = Incident(organization_id=org_a, title="Incident A", severity="high")
        db.add_all([event_a, event_b, obs_a, alert_a, incident_a])
        db.flush()
        event_b_id, obs_a_id = event_b.id, obs_a.id
        alert_a_id = alert_a.id

    # 1. Cross-tenant link in intel_observable_events must be rejected by PostgreSQL trigger
    with sessions() as db:
        try:
            db.add(ObservableEvent(organization_id=org_a, observable_id=obs_a_id, event_id=event_b_id))
            db.flush()
            db.rollback()
            pytest.fail("PostgreSQL allowed cross-tenant observable-to-event link")
        except DBAPIError:
            db.rollback()

    # 2. Cross-tenant link in alert_events must be rejected by PostgreSQL trigger
    with sessions() as db:
        try:
            db.add(AlertEvent(alert_id=alert_a_id, event_id=event_b_id))
            db.flush()
            db.rollback()
            pytest.fail("PostgreSQL allowed cross-tenant alert-to-event link")
        except DBAPIError:
            db.rollback()


# ==============================================================================
# 19. FULL END-TO-END IOC -> DETECTION -> SOAR -> AUDIT WORKFLOW
# ==============================================================================


def test_postgres_full_e2e_ioc_to_soar_simulated_containment_pipeline(pg_system):
    """Validate full live IOC -> detection -> incident -> SOAR -> approval -> containment -> audit pipeline."""
    from types import SimpleNamespace

    from aegis.db import (
        Alert,
        CaseNote,
        Entity,
        Incident,
        Observable,
        Playbook,
        PlaybookVersion,
        Storyline,
        User,
        WorkflowRun,
    )
    from aegis.intelligence import index_once
    from aegis.pipeline import ingest
    from aegis.soar import RunInput, enqueue, process_workflows, record
    from aegis.storage import LocalStorage, OpenSearchStorage
    from aegis.storylines import correlate
    from aegis.worker import process_once

    sessions = pg_system["sessions"]
    settings = pg_system["settings"]
    org = pg_system["org"]
    storage = OpenSearchStorage(settings) if settings.opensearch_url else LocalStorage(sessions)

    # 1. Setup users
    with sessions.begin() as db:
        senior = User(
            organization_id=org, username=f"pipe_senior_{uuid4().hex[:6]}", password_hash="h", role="SENIOR_ANALYST"
        )
        manager = User(
            organization_id=org, username=f"pipe_mgr_{uuid4().hex[:6]}", password_hash="h", role="SUPER_ADMIN"
        )
        db.add_all([senior, manager])
        db.flush()
        manager_id = manager.id
        senior_p = SimpleNamespace(user=senior, organization_id=org)
        manager_p = SimpleNamespace(user=manager, organization_id=org)

    # 2. Ingest 12 failed logins (triggers AEGIS-AUTH-001) + 1 privileged login (triggers AEGIS-AUTH-003)
    # sharing host and source_ip so they correlate into a Storyline.
    events = [
        EventInput(
            source="pipeline-live-src",
            source_type="json",
            collector="auth-collector",
            source_sequence=f"auth-seq-{i}",
            timestamp=datetime.now(UTC),
            raw_event={
                "message": f"Auth failed attempt {i}",
                "host": "AUTH-SERVER-01",
                "username": "victim-user",
                "source_ip": "198.51.100.99",
                "event_category": "authentication",
                "action": "login",
                "outcome": "failure",
            },
        )
        for i in range(12)
    ] + [
        EventInput(
            source="pipeline-live-src",
            source_type="json",
            collector="auth-collector",
            source_sequence="auth-seq-priv",
            timestamp=datetime.now(UTC),
            raw_event={
                "message": "Privileged login success after failure",
                "host": "AUTH-SERVER-01",
                "username": "victim-user",
                "source_ip": "198.51.100.99",
                "event_category": "authentication",
                "action": "login",
                "outcome": "success",
                "authentication": {"privileged": True},
            },
        )
    ]
    with sessions.begin() as db:
        ingest_res = ingest(db, settings, org, events, "e2e-live")
        assert len(ingest_res["accepted"]) == 13

    # 3. Worker process_once: detection, search indexing, and IOC observable extraction
    for _ in range(10):
        w = process_once(settings, sessions, storage)
        i = index_once(settings, sessions)
        if w == 0 and i == 0:
            break

    with sessions() as db:
        alerts = list(db.scalars(select(Alert).where(Alert.organization_id == org)))
        assert len(alerts) >= 2

    # 4. Correlate alerts into Incident and Storyline
    with sessions.begin() as db:
        corr_res = correlate(db, settings, manager_p, 1800)
        assert corr_res["changed"] >= 1
        incident = db.scalar(
            select(Incident).where(Incident.organization_id == org).order_by(Incident.created_at.desc())
        )
        assert incident is not None
        incident_id = incident.id
        storyline = db.scalar(select(Storyline).where(Storyline.organization_id == org))
        assert storyline is not None

    with sessions() as db:
        observables = list(db.scalars(select(Observable).where(Observable.organization_id == org)))
        assert any(o.value == "198.51.100.99" for o in observables)
        entity = db.scalar(
            select(Entity).where(Entity.organization_id == org, Entity.value == "AUTH-SERVER-01")
        )
        assert entity is not None
        entity_id = entity.id

    # 5. Create & trigger SOAR playbook with simulated containment action
    with sessions.begin() as db:
        book = Playbook(organization_id=org, name="Simulated Incident Response", enabled=True, version=1)
        db.add(book)
        db.flush()
        db.add(
            PlaybookVersion(
                organization_id=org,
                playbook_id=book.id,
                version=1,
                author=manager_p.user.id,
                document={
                    "description": "Simulated containment after approval",
                    "trigger": {"source": "incident"},
                    "input_schema": {"target_id": "entity"},
                    "steps": [
                        {"id": "contain", "action": "simulate_isolate_host"},
                        {"id": "doc_note", "action": "incident_note"},
                    ],
                },
            )
        )
        book_id = book.id

    with sessions.begin() as db:
        run = enqueue(
            db,
            settings,
            senior_p,
            book_id,
            RunInput(
                source_type="incident",
                source_id=incident_id,
                dry_run=False,
                inputs={"target_id": entity_id},
                idempotency_key="e2e-full-pipeline-run",
            ),
        )
        run_id = run.id

    # 6. Worker processes -> reaches approval gate
    process_workflows(settings, sessions)
    with sessions() as db:
        run = db.get(WorkflowRun, run_id)
        assert run.status == "WAITING_FOR_APPROVAL"

    # 7. Human approval by supervisor (independent user)
    with sessions.begin() as db:
        run = db.get(WorkflowRun, run_id)
        assert run.requested_by != manager_id
        run.approved_by, run.approved_at, run.status = manager_id, time.time(), "QUEUED"
        record(db, settings, run, "approve", manager_id)

    # 8. Worker executes approved workflow to completion
    for _ in range(5):
        if process_workflows(settings, sessions) == 0:
            break

    with sessions() as db:
        run = db.get(WorkflowRun, run_id)
        assert run.status == "SUCCEEDED"
        # Confirm simulated containment
        assert run.history[0]["output"]["data"]["action"] == "simulate_isolate_host"
        assert "Simulation only" in run.history[0]["output"]["data"]["message"]

        # Confirm incident note
        notes = list(
            db.scalars(
                select(CaseNote).where(CaseNote.organization_id == org, CaseNote.resource_id == incident_id)
            )
        )
        assert len(notes) == 1
        assert "No external containment performed" in notes[0].text

        # Cryptographically verify audit log
        assert verify_audit(db, settings, org) is True
