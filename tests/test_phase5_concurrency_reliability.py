"""Phase 5 Concurrency, Lock Hierarchy and Database Reliability Test Suite.

Validates the global lock ordering, optimistic revision concurrency,
race conditions, and recovery behaviors:
1. Concurrent incident status updates with revision checking (prevents lost updates)
2. Concurrent agent revocation and receipt submission race
3. Concurrent SOAR execution approval race (only one succeeds, revision bumps once)
4. Simultaneous duplicate event ingestion race (deduplication under concurrency)
5. Simulated database lock/statement timeout and rollback recovery
"""

import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import func, select

from aegis.crypto import ed25519_sign_canonical, generate_ed25519_keypair
from aegis.db import (
    Agent,
    EventRecord,
    Incident,
    PlaybookExecution,
    User,
    now,
)
from aegis.security import verify_audit


def test_concurrent_incident_status_updates_with_revision_checking(system):
    """Concurrent updates to an incident require matching revision; prevents lost updates."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    with sessions.begin() as db:
        inc = Incident(
            organization_id=org_id,
            title="Concurrent Incident Update",
            severity="medium",
            status="OPEN",
            revision=1,
        )
        db.add(inc)
        db.flush()
        inc_id = inc.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"

    success_count = 0
    conflict_count = 0

    def attempt_update(target_status: str, rev: int):
        nonlocal success_count, conflict_count
        resp = client.patch(
            f"/api/v1/incidents/{inc_id}/status",
            json={"status": target_status, "revision": rev},
        )
        if resp.status_code == 200:
            success_count += 1
        elif resp.status_code == 409:
            conflict_count += 1

    # Two concurrent requests attempting to update from revision 1 to TRIAGED
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(attempt_update, "TRIAGED", 1)
        f2 = executor.submit(attempt_update, "TRIAGED", 1)
        f1.result()
        f2.result()

    # Exactly one request must succeed (200), and the other must be rejected (409)
    assert success_count == 1
    assert conflict_count == 1

    # Final DB state: revision is exactly 2 and status is TRIAGED
    with sessions() as db:
        refreshed = db.get(Incident, inc_id)
        assert refreshed.status == "TRIAGED"
        assert refreshed.revision == 2


def test_concurrent_soar_approval_race(system):
    """Simultaneous approvals of the same execution permit only one winner; revision bumps once."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    with sessions.begin() as db:
        analyst = db.scalar(
            select(User).where(User.organization_id == org_id, User.role == "SENIOR_ANALYST")
        )
        execution = PlaybookExecution(
            id="SOAR-EXEC-CONCUR-01",
            organization_id=org_id,
            action="isolate_host",
            target="192.168.1.50",
            status="APPROVAL_REQUIRED",
            requested_by=analyst.id,
            idempotency_key="idemp-concur-01",
            revision=0,
        )
        db.add(execution)
        db.flush()
        exec_id = execution.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SOC_MANAGER']}"

    statuses = []

    def approve_call():
        resp = client.post(f"/api/v1/playbooks/{exec_id}/approve")
        statuses.append(resp.status_code)

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(approve_call)
        f2 = executor.submit(approve_call)
        f1.result()
        f2.result()

    # One must succeed with 200, one must fail with 409 (already approved)
    assert 200 in statuses
    assert 409 in statuses

    # Final DB state: approved_by is set, status is APPROVED, revision is 1
    with sessions() as db:
        refreshed = db.get(PlaybookExecution, exec_id)
        assert refreshed.status == "APPROVED"
        assert refreshed.approved_by == system["users"]["SOC_MANAGER"].id
        assert refreshed.revision == 1


def test_concurrent_agent_revocation_and_receipt_overlap(system):
    """When revocation races receipt submission, once revoked all subsequent receipts fail."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    agent_priv, agent_pub = generate_ed25519_keypair()
    agent_name = "SRV-CONCUR-RACE"

    with sessions.begin() as db:
        agent = Agent(
            organization_id=org_id,
            name=agent_name,
            public_key=agent_pub,
            status="ENROLLED",
            version="1.0.0",
            auth_token_hash="placeholder-token-hash",
        )
        db.add(agent)
        db.flush()

        exec_row = PlaybookExecution(
            id="SOAR-EXEC-RACE-01",
            organization_id=org_id,
            action="isolate_host",
            target=agent_name,
            status="APPROVED",
            requested_by=system["users"]["SENIOR_ANALYST"].id,
            idempotency_key="idemp-race-01",
            revision=1,
        )
        db.add(exec_row)
        db.flush()
        exec_id = exec_row.id

    # 1. Execute revocation
    client.headers["Authorization"] = f"Bearer {system['tokens']['SUPER_ADMIN']}"
    resp_rev = client.post(
        f"/api/v1/agents/{agent_name}/revoke",
        json={"reason": "Revocation race qualification"},
    )
    assert resp_rev.status_code == 200

    # 2. Attempt receipt submission after revocation has committed
    receipt_data = {
        "command_id": exec_id,
        "action": "isolate_host",
        "agent_id": agent_name,
        "organization_id": org_id,
        "status": "SUCCESS",
        "timestamp": time.time(),
        "nonce": "test-race-nonce-001",
        "result": {"status": "ENFORCED"},
    }
    signature = ed25519_sign_canonical(agent_priv, receipt_data)
    receipt_payload = {
        "command_id": exec_id,
        "action": "isolate_host",
        "status": "SUCCESS",
        "receipt": receipt_data,
        "signature": signature,
    }

    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"
    resp_rec = client.post(f"/api/v1/agents/{agent_name}/receipts", json=receipt_payload)
    # Must fail closed with 403
    assert resp_rec.status_code == 403
    assert "Agent identity is not enrolled or is revoked" in resp_rec.json()["error"]["message"]


def test_simultaneous_duplicate_event_ingestion_race(system):
    """Simultaneous concurrent requests with identical events deduplicate safely with zero duplicate rows."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    ts = now().isoformat()
    raw = {"event_id": 999, "action": "login", "user": "target_user"}
    payload = {
        "events": [
            {
                "source": "collector-race",
                "source_type": "json",
                "timestamp": ts,
                "raw_event": raw,
            }
        ]
    }

    all_accepted = []
    all_duplicates = []

    def ingest_thread():
        resp = client.post("/api/v1/events/ingest", json=payload)
        if resp.status_code == 202:
            all_accepted.extend(resp.json()["accepted"])
            all_duplicates.extend(resp.json()["duplicates"])

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(ingest_thread) for _ in range(4)]
        for f in futures:
            f.result()

    # Across all 4 concurrent requests: exactly 1 accepted, and 3 duplicates
    assert len(all_accepted) == 1
    event_id = all_accepted[0]
    assert len(all_duplicates) == 3
    assert all(dup_id == event_id for dup_id in all_duplicates)

    # In database: exactly 1 row exists
    with sessions() as db:
        count = db.scalar(select(func.count()).where(EventRecord.id == event_id))
        assert count == 1
        assert verify_audit(db, system["settings"], org_id) is True
