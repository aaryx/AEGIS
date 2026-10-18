"""Regression and security verification tests for AEGIS TITAN Phase 3.

Covers:
- H-001: Ingestion concurrency and queue capacity invariant under load
- H-002: Lock hierarchy and elimination of AB-BA deadlocks between tenant locking and audit heads
- H-003: Agent key revocation, in-flight execution cancellation, and receipt race prevention
- H-004: Production PostgreSQL and Redis transport encryption enforcement
"""

import concurrent.futures
import secrets
import threading
import time

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from aegis.agent import EndpointAgent
from aegis.config import Settings
from aegis.crypto import ed25519_sign_canonical
from aegis.db import Agent, AuditHead, Organization, PlaybookExecution, uid
from aegis.pipeline import ingest
from aegis.schemas import EventInput
from aegis.security import audit
from aegis.soar import lock_tenant
from tests.test_agent_nonce_replay_invariant import helper_create_command

# ============================================================================
# H-001: Ingestion Concurrency and Queue Capacity
# ============================================================================


def test_ingestion_queue_capacity_boundary(system):
    """Verify queue capacity boundary rejects submissions exceeding queue limit."""
    settings = system["app"].state.settings
    org_id = system["org"]
    sessions = system["app"].state.sessions

    original_capacity = settings.queue_capacity
    settings.queue_capacity = 5
    try:
        events = [
            EventInput(source="test", raw_event={"login": f"u{i}"})
            for i in range(5)
        ]
        with sessions() as db:
            result = ingest(db, settings, org_id, events, actor="test-operator")
            db.commit()
            assert len(result["accepted"]) == 5

        # Submitting 1 more event when at capacity must fail with OverflowError / 429
        with pytest.raises((OverflowError, HTTPException)) as exc_info:
            with sessions() as db:
                ingest(
                    db,
                    settings,
                    org_id,
                    [EventInput(source="test", raw_event={"login": "overflow"})],
                    actor="test-operator",
                )
        err_msg = str(exc_info.value.detail if hasattr(exc_info.value, "detail") else exc_info.value).lower()
        assert "backlog" in err_msg or "full" in err_msg or "capacity" in err_msg
    finally:
        settings.queue_capacity = original_capacity


def test_ingestion_concurrent_submissions_capacity_invariant(system):
    """Verify that concurrent ingestion workers cannot exceed queue capacity."""
    settings = system["app"].state.settings
    org_id = system["org"]
    sessions = system["app"].state.sessions

    original_capacity = settings.queue_capacity
    settings.queue_capacity = 20
    try:
        num_threads = 8
        batch_size = 5  # Total attempted = 40, capacity = 20
        accepted_total = 0
        rejected_total = 0
        lock = threading.Lock()

        def worker(thread_idx):
            nonlocal accepted_total, rejected_total
            events = [
                EventInput(source="load", raw_event={"thread": thread_idx, "idx": i})
                for i in range(batch_size)
            ]
            try:
                with sessions() as db:
                    res = ingest(db, settings, org_id, events, actor=f"worker-{thread_idx}")
                    db.commit()
                    with lock:
                        accepted_total += len(res["accepted"])
            except Exception:
                with lock:
                    rejected_total += 1

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # The accepted count must not exceed settings.queue_capacity
        assert accepted_total <= settings.queue_capacity
        assert accepted_total + (rejected_total * batch_size) == num_threads * batch_size
    finally:
        settings.queue_capacity = original_capacity


def test_ingestion_tenant_capacity_isolation(system):
    """Verify capacity accounting in Org A does not block ingestion in Org B."""
    settings = system["app"].state.settings
    sessions = system["app"].state.sessions
    org_a = system["org"]

    with sessions() as db:
        org_b_row = Organization(id=uid(), name="Isolated Tenant B")
        db.add(org_b_row)
        db.commit()
        org_b = org_b_row.id

    original_capacity = settings.queue_capacity
    settings.queue_capacity = 3
    try:
        # Fill Org A to capacity
        with sessions() as db:
            ingest(
                db,
                settings,
                org_a,
                [EventInput(source="test", raw_event={"evt": f"a{i}"}) for i in range(3)],
                actor="tenant-a-user",
            )
            db.commit()

        # Org B must still accept events up to its own capacity
        with sessions() as db:
            res_b = ingest(
                db,
                settings,
                org_b,
                [EventInput(source="test", raw_event={"evt": "b0"})],
                actor="tenant-b-user",
            )
            db.commit()
            assert len(res_b["accepted"]) == 1
    finally:
        settings.queue_capacity = original_capacity


# ============================================================================
# H-002: Lock Ordering and Deadlock Prevention
# ============================================================================


def test_canonical_lock_ordering_organization_before_audit_head(system):
    """Verify audit() acquires Organization before AuditHead in canonical order."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    with sessions() as db:
        # Pre-populate AuditHead
        head = AuditHead(organization_id=org_id, audit_head="0" * 64, sequence_number=0)
        db.add(head)
        db.commit()

    # Perform concurrent operations:
    # Thread 1: lock_tenant() then audit()
    # Thread 2: audit() directly
    def op_tenant_then_audit():
        with sessions() as db:
            lock_tenant(db, org_id)
            time.sleep(0.01)
            audit(db, settings, org_id, "user-1", "test.action.1", "target-1")
            db.commit()

    def op_audit():
        with sessions() as db:
            audit(db, settings, org_id, "user-2", "test.action.2", "target-2")
            db.commit()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        f1 = executor.submit(op_tenant_then_audit)
        f2 = executor.submit(op_audit)
        f1.result(timeout=5)
        f2.result(timeout=5)


# ============================================================================
# H-003: Agent Key Revocation and In-Flight Execution Race Prevention
# ============================================================================


def test_agent_revocation_cancels_in_flight_executions(system):
    """Verify agent revocation immediately cancels all in-flight executions."""
    client = system["client"]
    org_id = system["org"]
    sessions = system["app"].state.sessions

    agent = EndpointAgent(name="REVOKE-AGENT-01", simulation_mode=True)
    agent.heartbeat(client=client)

    # Create command for agent
    command_id = helper_create_command(system, agent.name)
    with sessions() as db:
        exec_row = db.get(PlaybookExecution, command_id)
        assert exec_row.status == "DISPATCHED"

    # Revoke agent using operator credentials
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    revoke_res = client.post(
        f"/api/v1/agents/{agent.name}/revoke",
        json={"reason": "Compromised machine key leaked"},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "REVOKED"

    # Verify agent is marked REVOKED with timestamp
    with sessions() as db:
        db_agent = db.scalar(
            select(Agent).where(Agent.organization_id == org_id, Agent.name == agent.name)
        )
        assert db_agent.status == "REVOKED"
        assert db_agent.revoked_at is not None

        # Verify command execution status transitioned to CANCELLED
        updated_exec = db.get(PlaybookExecution, command_id)
        assert updated_exec.status == "CANCELLED"
        assert "revoked" in (updated_exec.result or {}).get("error", "").lower()
        assert (updated_exec.result or {}).get("containment_status") == "UNKNOWN"


def test_revoked_agent_cannot_poll_commands(system):
    """Verify revoked agent receives 401/403 when polling for commands."""
    client = system["client"]
    agent = EndpointAgent(name="REVOKE-AGENT-02", simulation_mode=True)
    agent.heartbeat(client=client)

    # Revoke agent identity using operator credentials
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    revoke_res = client.post(
        f"/api/v1/agents/{agent.name}/revoke",
        json={"reason": "Decommissioned host"},
    )
    assert revoke_res.status_code == 200

    # Agent attempts to poll commands using its own token (should fail closed with 401/403)
    client.headers["Authorization"] = f"Bearer {agent.token}"
    poll_res = client.get(f"/api/v1/agents/{agent.name}/commands")
    assert poll_res.status_code in {401, 403}

    # Operator also cannot poll commands for a revoked agent
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    op_poll_res = client.get(f"/api/v1/agents/{agent.name}/commands")
    assert op_poll_res.status_code == 403


def test_revoked_agent_receipt_rejected(system):
    """Verify receipt submission from or for revoked agent is rejected."""
    client = system["client"]
    org_id = system["org"]

    agent = EndpointAgent(name="REVOKE-AGENT-03", simulation_mode=True)
    agent.heartbeat(client=client)
    command_id = helper_create_command(system, agent.name)

    # Poll command to get controller signature
    cmd = next(c for c in agent.poll_commands(client=client) if c["id"] == command_id)

    # Revoke agent using operator credentials
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    revoke_res = client.post(
        f"/api/v1/agents/{agent.name}/revoke",
        json={"reason": "Emergency revocation"},
    )
    assert revoke_res.status_code == 200

    receipt = {
        "command_id": command_id,
        "agent_id": agent.name,
        "organization_id": org_id,
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "timestamp": time.time(),
        "nonce": secrets.token_hex(16),
        "command_signature": cmd["controller_signature"],
    }
    sig = ed25519_sign_canonical(agent.private_key, receipt)

    # 1. Revoked agent token must be rejected (401/403)
    client.headers["Authorization"] = f"Bearer {agent.token}"
    receipt_res = client.post(
        f"/api/v1/agents/{agent.name}/receipts",
        json={
            "command_id": command_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt,
            "signature": sig,
        },
    )
    assert receipt_res.status_code in {401, 403}

    # 2. Operator submitting receipt for revoked agent/cancelled command must be rejected (403/409)
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    op_receipt_res = client.post(
        f"/api/v1/agents/{agent.name}/receipts",
        json={
            "command_id": command_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt,
            "signature": sig,
        },
    )
    assert op_receipt_res.status_code in {403, 409}


# ============================================================================
# H-004: PostgreSQL and Redis Transport Encryption Enforcement
# ============================================================================


def test_production_rejects_plaintext_postgres():
    """Verify production mode rejects sqlite and plaintext postgresql URLs."""
    valid_kwargs = {
        "environment": "production",
        "redis_url": "rediss://:secret@127.0.0.1:6379/0",
        "opensearch_url": "https://opensearch:9200",
        "opensearch_ca": "/etc/ssl/certs/ca.pem",
        "audit_secret": "super-secret-key-at-least-32chars-long-xxx",
        "cookie_secure": True,
        "public_origin": "https://aegis.example.com",
        "_env_file": None,
    }

    # SQLite rejected in production
    with pytest.raises(ValidationError) as exc:
        Settings(database_url="sqlite:///./aegis.db", **valid_kwargs)
    assert "Production requires PostgreSQL" in str(exc.value)

    # Plaintext PostgreSQL without TLS params rejected
    with pytest.raises(ValidationError) as exc:
        Settings(database_url="postgresql+psycopg://user:pass@127.0.0.1:5432/aegis", **valid_kwargs)
    assert "Production requires verified PostgreSQL TLS" in str(exc.value)


def test_production_rejects_sslmode_require_without_certificate_validation():
    """Verify sslmode=require alone is rejected in production (fails closed)."""
    valid_kwargs = {
        "environment": "production",
        "redis_url": "rediss://:secret@127.0.0.1:6379/0",
        "opensearch_url": "https://opensearch:9200",
        "opensearch_ca": "/etc/ssl/certs/ca.pem",
        "audit_secret": "super-secret-key-at-least-32chars-long-xxx",
        "cookie_secure": True,
        "public_origin": "https://aegis.example.com",
        "_env_file": None,
    }

    # sslmode=require does not verify CA or hostnames
    with pytest.raises(ValidationError) as exc:
        Settings(
            database_url="postgresql+psycopg://user:pass@127.0.0.1:5432/aegis?sslmode=require",
            **valid_kwargs,
        )
    assert "sslmode=require alone does not verify certificates or hostnames" in str(exc.value)

    # sslmode=verify-full without sslrootcert rejected
    with pytest.raises(ValidationError) as exc:
        Settings(
            database_url="postgresql+psycopg://user:pass@127.0.0.1:5432/aegis?sslmode=verify-full",
            **valid_kwargs,
        )
    assert "sslrootcert" in str(exc.value)


def test_production_rejects_plaintext_or_insecure_redis():
    """Verify production mode rejects plaintext redis:// and disabled cert verification."""
    valid_kwargs = {
        "environment": "production",
        "database_url": "postgresql+psycopg://user:pass@127.0.0.1:5432/aegis?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.pem",
        "opensearch_url": "https://opensearch:9200",
        "opensearch_ca": "/etc/ssl/certs/ca.pem",
        "audit_secret": "super-secret-key-at-least-32chars-long-xxx",
        "cookie_secure": True,
        "public_origin": "https://aegis.example.com",
        "_env_file": None,
    }

    # Plaintext redis://
    with pytest.raises(ValidationError) as exc:
        Settings(redis_url="redis://:pass@127.0.0.1:6379/0", **valid_kwargs)
    assert "Production requires TLS for Redis (rediss://)" in str(exc.value)

    # Disabled verification ?ssl_cert_reqs=none
    with pytest.raises(ValidationError) as exc:
        Settings(redis_url="rediss://:pass@127.0.0.1:6379/0?ssl_cert_reqs=none", **valid_kwargs)
    assert "certificate verification must not be disabled" in str(exc.value)

    # Missing authentication
    with pytest.raises(ValidationError) as exc:
        Settings(redis_url="rediss://127.0.0.1:6379/0", **valid_kwargs)
    assert "authenticated Redis connection" in str(exc.value)


def test_production_valid_configuration_succeeds():
    """Verify that a fully compliant TLS configuration succeeds in production."""
    settings = Settings(
        environment="production",
        database_url="postgresql+psycopg://aegis:pass@127.0.0.1:5432/aegis?sslmode=verify-full&sslrootcert=/etc/ssl/certs/pg-ca.pem",
        redis_url="rediss://:secret@127.0.0.1:6379/0?ssl_cert_reqs=required",
        redis_ca="/etc/ssl/certs/redis-ca.pem",
        opensearch_url="https://opensearch:9200",
        opensearch_ca="/etc/ssl/certs/os-ca.pem",
        audit_secret="super-secret-key-at-least-32chars-long-xxx",
        cookie_secure=True,
        public_origin="https://aegis.example.com",
        _env_file=None,
    )
    assert settings.environment == "production"
    assert "sslmode=verify-full" in settings.database_url
    assert settings.redis_url.startswith("rediss://")
    assert settings.redis_ca == "/etc/ssl/certs/redis-ca.pem"
    assert settings.opensearch_url.startswith("https://")
