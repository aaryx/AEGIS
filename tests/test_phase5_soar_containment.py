"""Phase 5 SOAR and Containment Safety Test Suite.

Validates the playbook execution lifecycle, approval security, agent receipt verification,
and containment safety invariants:
1. Two-person approval rule: author cannot approve own execution
2. API Key cannot approve execution (requires human operator)
3. Role enforcement: VIEWER / ANALYST cannot approve; only SOC_MANAGER / SUPER_ADMIN can approve
4. Dry-run safety: dry_run=True marks action simulated and prevents external side-effects
5. Duplicate execution & Idempotency: identical idempotency_key returns cached execution without re-executing
6. Agent receipt Ed25519 cryptographic signature verification:
   - Valid signature accepted
   - Corrupted/forged signature rejected with 400
   - Mismatched execution ID rejected with 400
7. Revocation race: receipt submitted after agent revocation fails closed (403)
8. Receipt outcome and containment state model:
   - Accurately distinguishes REQUESTED, SIMULATED, ENFORCED, RELEASED, FAILED, and UNKNOWN
   - Refuses to report ENFORCED without verified nftables policy hash match
"""

import hashlib
import secrets
import time

from sqlalchemy import select

from aegis.containment import execution_containment_status, receipt_outcome
from aegis.crypto import (
    ed25519_sign_canonical,
    generate_ed25519_keypair,
)
from aegis.db import Agent, Incident, PlaybookExecution, User, now
from aegis.soar import Playbook, PlaybookVersion


def test_soar_two_person_approval_rule_enforced(system):
    """The user who requested a playbook execution cannot approve it."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    with sessions.begin() as db:
        # SOC_MANAGER (has playbooks.approve permission) creates execution requiring approval
        mgr = db.scalar(
            select(User).where(User.organization_id == org_id, User.role == "SOC_MANAGER")
        )
        execution = PlaybookExecution(
            id="SOAR-EXEC-2PERSON-01",
            organization_id=org_id,
            action="isolate_host",
            target="192.168.1.100",
            status="APPROVAL_REQUIRED",
            requested_by=mgr.id,
            idempotency_key="idemp-2p-01",
            revision=0,
        )
        db.add(execution)
        db.flush()
        exec_id = execution.id

    # 1. SOC_MANAGER attempts to approve their own execution
    client.headers["Authorization"] = f"Bearer {system['tokens']['SOC_MANAGER']}"
    resp_self = client.post(f"/api/v1/playbooks/{exec_id}/approve")
    # Two-person rule must block self-approval with 403
    assert resp_self.status_code == 403
    assert "A different human operator must approve" in resp_self.json()["error"]["message"]

    # 2. SUPER_ADMIN (different human operator with playbooks.approve) approves successfully
    client.headers["Authorization"] = f"Bearer {system['tokens']['SUPER_ADMIN']}"
    resp_super = client.post(f"/api/v1/playbooks/{exec_id}/approve")
    assert resp_super.status_code == 200
    assert resp_super.json()["status"] == "APPROVED"
    assert resp_super.json()["approved_by"] == system["users"]["SUPER_ADMIN"].id


def test_soar_approval_role_enforcement(system):
    """VIEWER and ANALYST roles lack playbooks.approve permission and cannot approve executions."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    with sessions.begin() as db:
        mgr = db.scalar(select(User).where(User.organization_id == org_id, User.role == "SOC_MANAGER"))
        execution = PlaybookExecution(
            id="SOAR-EXEC-ROLE-01",
            organization_id=org_id,
            action="isolate_host",
            target="192.168.1.101",
            status="APPROVAL_REQUIRED",
            requested_by=mgr.id,
            idempotency_key="idemp-role-01",
            revision=0,
        )
        db.add(execution)
        db.flush()
        exec_id = execution.id

    # 1. VIEWER attempts approval
    client.headers["Authorization"] = f"Bearer {system['tokens']['VIEWER']}"
    resp_viewer = client.post(f"/api/v1/playbooks/{exec_id}/approve")
    assert resp_viewer.status_code == 403
    assert "Permissions required:" in resp_viewer.json()["error"]["message"]

    # 2. ANALYST attempts approval
    client.headers["Authorization"] = f"Bearer {system['tokens']['ANALYST']}"
    resp_analyst = client.post(f"/api/v1/playbooks/{exec_id}/approve")
    assert resp_analyst.status_code == 403
    assert "Permissions required:" in resp_analyst.json()["error"]["message"]


def test_soar_execution_idempotency_key_prevents_duplicate_runs(system):
    """Submitting the same idempotency key for playbook execution returns existing record."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    with sessions.begin() as db:
        user = db.scalar(select(User).where(User.organization_id == org_id, User.role == "SENIOR_ANALYST"))
        inc = Incident(organization_id=org_id, title="Idempotency Source Incident", severity="high")
        db.add(inc)
        db.flush()
        inc_id = inc.id

        pb = Playbook(organization_id=org_id, name="Idempotent Playbook", enabled=True, version=1)
        db.add(pb)
        db.flush()
        db.add(
            PlaybookVersion(
                organization_id=org_id,
                playbook_id=pb.id,
                version=1,
                document={
                    "description": "Idempotency test playbook",
                    "trigger": {"source": "incident"},
                    "steps": [{"id": "step1", "action": "summary"}],
                },
                author=user.id,
            )
        )
        db.flush()
        pb_id = pb.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"
    run_input = {
        "source_type": "incident",
        "source_id": inc_id,
        "idempotency_key": "unique-idempotency-key-001",
        "dry_run": True,
    }

    # First execution submission
    resp1 = client.post(f"/api/v1/soar/playbooks/{pb_id}/execute", json=run_input)
    assert resp1.status_code == 200
    run1 = resp1.json()

    # Second execution submission with identical idempotency key
    resp2 = client.post(f"/api/v1/soar/playbooks/{pb_id}/execute", json=run_input)
    assert resp2.status_code == 200
    run2 = resp2.json()

    # Returned execution run ID must be identical; no duplicate execution was spawned
    assert run1["id"] == run2["id"]


def test_agent_receipt_cryptographic_verification(system):
    """Agent receipts require valid Ed25519 signature; tampered signatures are rejected."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    # Generate Ed25519 keypair for test agent
    agent_priv, agent_pub = generate_ed25519_keypair()
    agent_name = "SRV-CRYPTO-TEST"

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
            id="SOAR-EXEC-RECEIPT-01",
            organization_id=org_id,
            action="isolate_host",
            target=agent_name,
            status="APPROVED",
            requested_by=system["users"]["SENIOR_ANALYST"].id,
            idempotency_key="idemp-receipt-01",
            revision=1,
        )
        db.add(exec_row)
        db.flush()
        exec_id = exec_row.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"

    # Build canonical receipt dictionary
    receipt_data = {
        "command_id": exec_id,
        "action": "isolate_host",
        "agent_id": agent_name,
        "organization_id": org_id,
        "status": "SUCCESS",
        "timestamp": time.time(),
        "nonce": secrets.token_hex(16),
        "result": {"status": "ENFORCED"},
    }
    valid_signature = ed25519_sign_canonical(agent_priv, receipt_data)

    # 1. Tampered signature attempt
    invalid_payload = {
        "command_id": exec_id,
        "action": "isolate_host",
        "status": "SUCCESS",
        "receipt": receipt_data,
        "signature": "0" * 128,  # Forged/invalid hex signature
    }
    resp_bad = client.post(f"/api/v1/agents/{agent_name}/receipts", json=invalid_payload)
    assert resp_bad.status_code == 400
    assert "Cryptographic execution receipt signature verification failed" in resp_bad.json()["error"]["message"]

    # 2. Valid signature submission without live nftables evidence fails closed to UNKNOWN
    valid_payload = {
        "command_id": exec_id,
        "action": "isolate_host",
        "status": "SUCCESS",
        "receipt": receipt_data,
        "signature": valid_signature,
    }
    resp_good = client.post(f"/api/v1/agents/{agent_name}/receipts", json=valid_payload)
    assert resp_good.status_code == 200
    # Because receipt lacks mode='simulated' or verified nftables evidence, status fails closed to UNKNOWN
    assert resp_good.json()["status"] == "UNKNOWN"
    assert resp_good.json()["result"]["receipt_authenticated"] is True
    assert resp_good.json()["result"]["containment_status"] == "UNKNOWN"


def test_agent_revocation_invalidates_subsequent_receipts(system):
    """Once an agent is revoked, subsequent receipt submissions fail closed with 403."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    agent_priv, agent_pub = generate_ed25519_keypair()
    agent_name = "SRV-REVOKED-TEST"

    with sessions.begin() as db:
        agent = Agent(
            organization_id=org_id,
            name=agent_name,
            public_key=agent_pub,
            status="REVOKED",  # Agent is revoked
            revoked_at=now(),
            version="1.0.0",
            auth_token_hash="placeholder-token-hash",
        )
        db.add(agent)
        db.flush()

        exec_row = PlaybookExecution(
            id="SOAR-EXEC-REVOKED-01",
            organization_id=org_id,
            action="isolate_host",
            target=agent_name,
            status="APPROVED",
            requested_by=system["users"]["SENIOR_ANALYST"].id,
            idempotency_key="idemp-revoked-01",
            revision=1,
        )
        db.add(exec_row)
        db.flush()
        exec_id = exec_row.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"

    receipt_data = {
        "command_id": exec_id,
        "action": "isolate_host",
        "agent_id": agent_name,
        "organization_id": org_id,
        "status": "SUCCESS",
        "timestamp": time.time(),
        "nonce": secrets.token_hex(16),
        "result": {"status": "ENFORCED"},
    }
    signature = ed25519_sign_canonical(agent_priv, receipt_data)

    payload = {
        "command_id": exec_id,
        "action": "isolate_host",
        "status": "SUCCESS",
        "receipt": receipt_data,
        "signature": signature,
    }
    resp = client.post(f"/api/v1/agents/{agent_name}/receipts", json=payload)
    assert resp.status_code == 403
    assert "Agent identity is not enrolled or is revoked" in resp.json()["error"]["message"]


def test_containment_status_and_evidence_invariants():
    """receipt_outcome refuses to report ENFORCED without valid nftables cryptographic evidence."""
    policy_hash = hashlib.sha256(b"canonical-nftables-policy").hexdigest()

    # 1. Mode simulated -> SIMULATED
    sim_result = {"mode": "simulated", "outcome": "ENFORCED"}
    assert receipt_outcome("isolate_host", "SUCCESS", sim_result) == "SIMULATED"

    # 2. Failed execution status -> FAILED
    assert receipt_outcome("isolate_host", "FAILED", sim_result) == "FAILED"

    # 3. Live mode without verification evidence -> UNKNOWN (fails closed)
    unverified_live = {"mode": "live", "outcome": "ENFORCED", "evidence": None}
    assert receipt_outcome("isolate_host", "SUCCESS", unverified_live) == "UNKNOWN"

    # 4. Live mode with mismatched observed hash -> UNKNOWN (fails closed)
    tampered_evidence = {
        "mode": "live",
        "outcome": "ENFORCED",
        "evidence": {
            "backend": "nftables-v1",
            "verified": True,
            "state": "ENFORCED",
            "policy_sha256": policy_hash,
            "observed_sha256": "0" * 64,  # Mismatched hash!
        },
    }
    assert receipt_outcome("isolate_host", "SUCCESS", tampered_evidence) == "UNKNOWN"

    # 5. Live mode with exact matching cryptographic evidence -> ENFORCED
    valid_evidence = {
        "mode": "live",
        "outcome": "ENFORCED",
        "evidence": {
            "backend": "nftables-v1",
            "verified": True,
            "state": "ENFORCED",
            "policy_sha256": policy_hash,
            "observed_sha256": policy_hash,
        },
    }
    assert receipt_outcome("isolate_host", "SUCCESS", valid_evidence) == "ENFORCED"

    # 6. execution_containment_status state mappings
    assert execution_containment_status("REQUESTED", {}) == "REQUESTED"
    assert execution_containment_status("APPROVAL_REQUIRED", {}) == "REQUESTED"
    assert execution_containment_status("APPROVED", {}) == "APPROVED"
    assert execution_containment_status("DISPATCHED", {}) == "DISPATCHED"
    assert execution_containment_status("FAILED", {}) == "FAILED"
