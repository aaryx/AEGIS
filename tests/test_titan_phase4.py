"""Controlled local schedules; SQLite results do not qualify PostgreSQL locks."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest
from pydantic import ValidationError
from sqlalchemy import event, func, select

from aegis.config import Settings
from aegis.db import AuditLog, Collector, EventRecord
from aegis.pipeline import ingest
from aegis.schemas import EventInput
from aegis.security import audit, verify_audit
from aegis.transport import postgres_connect_kwargs, redis_client


def production(**overrides):
    return Settings(
        **(
            {
                "environment": "production",
                "database_url": "postgresql+psycopg://user:placeholder@postgres/aegis?sslmode=verify-full&sslrootcert=/ca.pem",
                "redis_url": "rediss://:placeholder@redis/0",
                "opensearch_url": "https://opensearch:9200",
                "opensearch_ca": "/ca.pem",
                "audit_secret": "phase-four-test-integrity-key-32-characters",
                "cookie_secure": True,
                "public_origin": "https://aegis.example.com",
                "_env_file": None,
            }
            | overrides
        )
    )


@pytest.mark.parametrize(
    "query",
    [
        "sslmode=verify-ca&sslrootcert=/ca.pem",
        "sslmode=verify-full&sslmode=disable&sslrootcert=/ca.pem",
        "sslmode=verify-full&sslrootcert=/ca.pem&sslrootcert=",
        "sslmode=verify-full&sslrootcert=/ca.pem&host=",
    ],
)
def test_postgres_rejects_ambiguous_or_unverified_transport(query):
    with pytest.raises(ValidationError):
        production(database_url="postgresql+psycopg://u:placeholder@postgres/aegis?" + query)


@pytest.mark.parametrize(
    "suffix",
    [
        "?ssl_check_hostname=false",
        "?ssl_cert_reqs=required&ssl_cert_reqs=none",
        "?ssl_cert_reqs=",
        "?ssl_ca_certs=",
        "?ssl_check_hostname=0",
    ],
)
def test_redis_rejects_url_security_overrides(suffix):
    with pytest.raises(ValidationError):
        production(redis_url="rediss://:placeholder@redis/0" + suffix)


def test_redis_username_without_password_is_not_authentication():
    with pytest.raises(ValidationError):
        production(redis_url="rediss://user@redis/0")


def test_validation_diagnostics_hide_input_credentials():
    marker = "unique-credential-canary"
    with pytest.raises(ValidationError) as caught:
        production(database_url=f"postgresql://u:{marker}@postgres/aegis")
    assert marker not in str(caught.value)


def test_real_redis_pool_enforces_hostname_and_custom_ca():
    client = redis_client(production(redis_ca="/custom-ca.pem"))
    kwargs = client.connection_pool.connection_kwargs
    assert kwargs["ssl_cert_reqs"] == "required"
    assert kwargs["ssl_check_hostname"] is True
    assert kwargs["ssl_ca_certs"] == "/custom-ca.pem"
    client.close()


def test_bootstrap_preserves_postgres_tls_parameters():
    kwargs = postgres_connect_kwargs(production().database_url)
    assert kwargs["sslmode"] == "verify-full"
    assert kwargs["sslrootcert"] == "/ca.pem"
    assert kwargs["host"] == "postgres"
    assert kwargs["dbname"] == "aegis"


def test_maintenance_database_cannot_bypass_production_tls():
    with pytest.raises(ValidationError):
        production(maintenance_database_url="postgresql://user:placeholder@postgres/aegis")


def test_postgres_engine_has_bounded_waits_and_hides_parameters(monkeypatch):
    from unittest.mock import MagicMock

    import aegis.db as database_module

    factory = MagicMock()
    monkeypatch.setattr(database_module, "create_engine", factory)
    database_module.database(production().database_url)
    kwargs = factory.call_args.kwargs
    assert kwargs["hide_parameters"] is True
    assert kwargs["connect_args"] == {
        "connect_timeout": 5,
        "options": "-c lock_timeout=5000 -c statement_timeout=30000",
    }


@pytest.mark.parametrize("sqlstate", ["40001", "40P01", "55P03", "57014", "disconnect"])
def test_worker_transaction_failure_rolls_back_without_poisoning_evidence(system, monkeypatch, sqlstate):
    from sqlalchemy.exc import OperationalError

    import aegis.worker as worker

    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    with sessions.begin() as db:
        ingest(db, settings, org, [EventInput(source="test", raw_event={"n": 1})], "test")
    original = worker.detect_batch

    def failure(db, settings, records, **kwargs):
        audit(db, settings, org, "test", "must.rollback")
        cause = RuntimeError("synthetic database failure")
        cause.sqlstate = sqlstate
        raise OperationalError(None, None, cause, connection_invalidated=sqlstate == "disconnect")

    monkeypatch.setattr(worker, "detect_batch", failure)
    with pytest.raises(OperationalError):
        worker.process_once(settings, sessions, system["app"].state.storage)
    with sessions() as db:
        record = db.scalar(select(EventRecord))
        assert record.state == "PENDING" and record.attempts == 0
        assert (
            db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "must.rollback"))
            == 0
        )
        assert verify_audit(db, settings, org)
    monkeypatch.setattr(worker, "detect_batch", original)
    assert worker.process_once(settings, sessions, system["app"].state.storage) == 1


def test_audit_first_write_locks_tenant_before_creating_head(system):
    engine = system["app"].state.sessions.kw["bind"]
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(engine, "before_cursor_execute", capture)
    try:
        with system["app"].state.sessions.begin() as db:
            audit(db, system["settings"], system["org"], "test", "first.write")
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    first_write = next(s for s in statements if s.startswith(("insert", "update")))
    assert first_write.startswith("update organizations")


@pytest.mark.parametrize("rollback", [False, True])
def test_admission_waits_for_transaction_outcome(system, monkeypatch, rollback):
    import aegis.soar as soar

    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    settings.queue_capacity = 1
    held, attempted, release = Event(), Event(), Event()
    original = soar.lock_tenant

    def controlled(db, tenant):
        if db.info.get("contender"):
            attempted.set()
        original(db, tenant)

    monkeypatch.setattr(soar, "lock_tenant", controlled)

    def owner():
        with sessions() as db:
            ingest(db, settings, org, [EventInput(source="test", raw_event={"n": 1})], "owner")
            held.set()
            assert release.wait(5)
            db.rollback() if rollback else db.commit()

    def contender():
        assert held.wait(5)
        with sessions() as db:
            db.info["contender"] = True
            try:
                ingest(db, settings, org, [EventInput(source="test", raw_event={"n": 2})], "contender")
                db.commit()
                return "accepted"
            except OverflowError:
                db.rollback()
                return "full"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(owner), pool.submit(contender)
        try:
            assert attempted.wait(5)
        finally:
            release.set()
        first.result(timeout=8)
        assert second.result(timeout=8) == ("accepted" if rollback else "full")
    with sessions() as db:
        assert (
            db.scalar(select(func.count()).select_from(EventRecord).where(EventRecord.organization_id == org))
            == 1
        )
        assert (
            db.scalar(select(func.sum(Collector.events_received)).where(Collector.organization_id == org))
            == 1
        )
        assert (
            db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.organization_id == org)) == 1
        )
        assert verify_audit(db, settings, org)


def test_simultaneous_tenant_admission_and_duplicate_retry(system):
    sessions, settings = system["app"].state.sessions, system["settings"]
    settings.queue_capacity = 1
    barrier = Barrier(4, timeout=5)

    def submit(tenant, number):
        barrier.wait()
        with sessions.begin() as db:
            try:
                return ingest(
                    db, settings, tenant, [EventInput(source="test", raw_event={"n": number})], "test"
                )
            except OverflowError:
                return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda args: submit(*args),
                [
                    (system["org"], 1),
                    (system["org"], 1),
                    (system["other"], 2),
                    (system["other"], 3),
                ],
            )
        )
    assert sum(len(r["accepted"]) for r in results if r) == 2
    assert sum(len(r["duplicates"]) for r in results if r) == 1
    assert results.count(None) == 1


@pytest.mark.parametrize("pause_point", ["verification", "persistence"])
def test_receipt_holding_gate_commits_before_waiting_revocation(system, monkeypatch, pause_point):
    import time

    import aegis.api as api
    import aegis.soar as soar
    from aegis.agent import EndpointAgent
    from aegis.crypto import ed25519_sign_canonical
    from aegis.db import Agent, PlaybookExecution
    from tests.test_agent_nonce_replay_invariant import helper_create_command

    client, sessions = system["client"], system["app"].state.sessions
    agent = EndpointAgent(name="phase4-receipt", simulation_mode=True)
    agent.heartbeat(client=client)
    command_id = helper_create_command(system, agent.name)
    command = next(c for c in agent.poll_commands(client=client) if c["id"] == command_id)
    receipt = {
        "command_id": command_id,
        "agent_id": agent.name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "timestamp": time.time(),
        "nonce": "phase4_deterministic_nonce",
        "command_signature": command["controller_signature"],
    }
    payload = {
        "command_id": command_id,
        "action": "isolate_host",
        "status": "SUCCESS",
        "receipt": receipt,
        "signature": ed25519_sign_canonical(agent.private_key, receipt),
    }
    paused, attempted, release = Event(), Event(), Event()
    original_verify, original_lock = api.ed25519_verify_canonical, soar.lock_tenant

    def pause():
        paused.set()
        assert release.wait(5)

    def verify(*args):
        if pause_point == "verification":
            pause()
        return original_verify(*args)

    def lock(db, org):
        if paused.is_set() and not release.is_set():
            attempted.set()
        original_lock(db, org)

    def before_sql(conn, cursor, statement, parameters, context, executemany):
        if pause_point == "persistence" and statement.lower().startswith("update playbook_executions"):
            if not paused.is_set():
                pause()

    monkeypatch.setattr(api, "ed25519_verify_canonical", verify)
    monkeypatch.setattr(soar, "lock_tenant", lock)
    engine = sessions.kw["bind"]
    event.listen(engine, "before_cursor_execute", before_sql)
    headers = {"Authorization": "Bearer " + system["tokens"]["SUPER_ADMIN"]}
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            accepted = pool.submit(
                client.post, f"/api/v1/agents/{agent.name}/receipts", json=payload, headers=headers
            )
            try:
                assert paused.wait(5)
                revoked = pool.submit(
                    client.post,
                    f"/api/v1/agents/{agent.name}/revoke",
                    json={"reason": "race regression"},
                    headers=headers,
                )
                assert attempted.wait(5)
            finally:
                release.set()
            assert accepted.result(timeout=8).status_code == 200
            assert revoked.result(timeout=8).status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", before_sql)
    assert (
        client.post(f"/api/v1/agents/{agent.name}/receipts", json=payload, headers=headers).status_code == 403
    )
    with sessions() as db:
        assert db.scalar(select(Agent).where(Agent.name == agent.name)).status == "REVOKED"
        execution = db.get(PlaybookExecution, command_id)
        assert execution.result["receipt"] == receipt
        assert execution.status != "CANCELLED"
        assert verify_audit(db, system["settings"], system["org"])
