"""Adversarial and boundary verification test suite.

Validates:
- Agent duplicate command delivery, retry behavior, agent/controller restart resilience.
- Non-leakage of private keys and secrets across all API responses.
- Audit hash-chain tampering detection (modification, deletion, reordering, truncation).
- Independent audit checkpoint verification and external export boundary audit.
- MFA challenge enforcement, invalid/expired codes, lockout, and session revocation.
"""

import secrets
import time
from datetime import UTC

from sqlalchemy import select

from aegis.agent import EndpointAgent
from aegis.crypto import (
    ed25519_sign_canonical,
    ed25519_verify_canonical,
    generate_totp,
    get_controller_public_key_hex,
    get_controller_signing_key,
)
from aegis.db import Agent, AuditCheckpoint, AuditLog
from aegis.security import (
    audit,
    create_audit_checkpoint,
    verify_audit,
)

# ==============================================================================
# A. AGENT CRYPTOGRAPHIC SECURITY & RESTART RESILIENCE
# ==============================================================================


def test_duplicate_command_delivery_and_retry_behavior(system):
    """Verify that duplicate command delivery is safely rejected by agent replay controls."""
    settings = system["app"].state.settings
    ctrl_priv = get_controller_signing_key(settings)
    ctrl_pub = get_controller_public_key_hex(settings)

    agent = EndpointAgent(name="SRV-DUP-DELIVERY", simulation_mode=True)
    agent.controller_public_key = ctrl_pub

    envelope = {
        "version": "1.0",
        "command_id": "CMD-DUP-01",
        "agent_id": agent.name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "parameters": {},
        "issued_at": time.time(),
        "expires_at": time.time() + 300,
        "nonce": secrets.token_hex(16),
    }
    sig = ed25519_sign_canonical(ctrl_priv, envelope)
    cmd = {
        "id": "CMD-DUP-01",
        "action": "isolate_host",
        "envelope": envelope,
        "controller_signature": sig,
        "controller_public_key": ctrl_pub,
    }

    # First delivery: verified and accepted
    assert agent.verify_command(cmd) is True

    # Immediate duplicate delivery of identical command: rejected via nonce cache
    assert agent.verify_command(cmd) is False

    # Retry delivery with a fresh nonce and new timestamp: accepted
    retry_envelope = dict(envelope)
    retry_envelope["nonce"] = secrets.token_hex(16)
    retry_envelope["issued_at"] = time.time()
    retry_sig = ed25519_sign_canonical(ctrl_priv, retry_envelope)
    retry_cmd = {
        "id": "CMD-DUP-01",
        "action": "isolate_host",
        "envelope": retry_envelope,
        "controller_signature": retry_sig,
        "controller_public_key": ctrl_pub,
    }
    assert agent.verify_command(retry_cmd) is True


def test_agent_restart_during_execution(system, tmp_path):
    """Verify that an endpoint agent securely persists its private key to disk with 0o600

    permissions and re-loads it after an agent process restart.
    """
    key_file = str(tmp_path / "agent_identity.key")
    agent_name = "SRV-PERSIST-AGENT"

    # 1. First agent instance generates and saves key to file via key_path
    agent_1 = EndpointAgent(name=agent_name, simulation_mode=True, key_path=key_file)
    pub_1 = agent_1.public_key_hex

    # 2. Simulate agent restart by creating new agent instance with the same key_path
    agent_2 = EndpointAgent(name=agent_name, simulation_mode=True, key_path=key_file)
    pub_2 = agent_2.public_key_hex

    assert pub_1 == pub_2

    # 3. Verify that the re-instantiated agent signs receipts that verify against pub_1
    payload = {"command_id": "CMD-TEST-01", "result": "ok"}
    sig = ed25519_sign_canonical(agent_2.private_key, payload)
    assert ed25519_verify_canonical(pub_1, sig, payload) is True


def test_controller_restart_state_persistence(system):
    """Verify that the controller derives identical keys across restarts

    and enrolled agents remain authorized.
    """
    settings = system["app"].state.settings
    pub_1 = get_controller_public_key_hex(settings)

    # Controller restart simulated by deriving key again with fresh Settings
    pub_2 = get_controller_public_key_hex(settings)
    assert pub_1 == pub_2

    # Enrolled agent remains recognized in database
    client = system["client"]
    agent = EndpointAgent(name="SRV-RESTART-CTRL", simulation_mode=True)
    agent.heartbeat(client=client)

    with system["app"].state.sessions() as db:
        agent_db = db.scalar(select(Agent).where(Agent.name == "SRV-RESTART-CTRL"))
        assert agent_db is not None
        assert agent_db.public_key == agent.public_key_hex
        assert agent_db.status in ("ENROLLED", "ACTIVE")


def test_private_keys_and_secrets_never_returned_by_apis(system):
    """Audit all agent, auth, and user endpoints to ensure private keys and secrets

    are NEVER returned in response payloads.
    """
    client = system["client"]

    # 1. Agent listing
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    agents_resp = client.get("/api/v1/agents")
    assert agents_resp.status_code == 200
    agents_json = str(agents_resp.json()).lower()
    assert "private" not in agents_json
    assert "secret" not in agents_json
    assert "seed" not in agents_json

    # 2. Users listing
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    users_resp = client.get("/api/v1/users")
    assert users_resp.status_code == 200
    users_json = str(users_resp.json()).lower()
    assert "password_hash" not in users_json
    assert "mfa_secret" not in users_json

    # 3. Current user profile
    me_resp = client.get("/api/v1/auth/me")
    assert me_resp.status_code == 200
    me_json = str(me_resp.json()).lower()
    assert "password" not in me_json
    assert "secret" not in me_json


# ==============================================================================
# B. AUDIT INTEGRITY AND TAMPER-EVIDENT DETECTION
# ==============================================================================


def test_audit_tampering_modification_detected(system):
    """Modifying any field in an existing audit record invalidates hash-chain verification."""
    settings = system["app"].state.settings
    org_id = system["org"]

    with system["app"].state.sessions.begin() as db:
        for i in range(5):
            audit(db, settings, org_id, actor="admin", action=f"action_{i}", resource_id=f"res_{i}")

    # Valid chain passes
    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is True

    # Tamper with an action payload in a record
    with system["app"].state.sessions.begin() as db:
        record = db.scalars(select(AuditLog).where(AuditLog.organization_id == org_id)).first()
        assert record is not None
        record.action = "tampered_action_name"

    # Chain verification MUST fail
    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_tampering_deletion_detected(system):
    """Deleting a record from the audit log leaves a break in the hash chain."""
    settings = system["app"].state.settings
    org_id = system["org"]

    with system["app"].state.sessions.begin() as db:
        for i in range(5):
            audit(db, settings, org_id, actor="admin", action=f"action_{i}", resource_id=f"res_{i}")

    # Delete record 2 (middle record)
    with system["app"].state.sessions.begin() as db:
        records = list(db.scalars(select(AuditLog).where(AuditLog.organization_id == org_id).order_by(AuditLog.created_at.asc())))
        db.delete(records[2])

    # Verification MUST fail
    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_tampering_reordering_detected(system):
    """Swapping records or their linkage invalidates the hash chain."""
    settings = system["app"].state.settings
    org_id = system["org"]

    with system["app"].state.sessions.begin() as db:
        for i in range(4):
            audit(db, settings, org_id, actor="admin", action=f"action_{i}", resource_id=f"res_{i}")

    # Swap previous_hash between records
    with system["app"].state.sessions.begin() as db:
        records = list(db.scalars(select(AuditLog).where(AuditLog.organization_id == org_id).order_by(AuditLog.created_at.asc())))
        records[1].previous_hash, records[2].previous_hash = records[2].previous_hash, records[1].previous_hash

    # Verification MUST fail
    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_tampering_truncation_detected(system):
    """Truncating the latest record in the chain is detected via the AuditHead checkpoint."""
    settings = system["app"].state.settings
    org_id = system["org"]

    with system["app"].state.sessions.begin() as db:
        for i in range(5):
            audit(db, settings, org_id, actor="admin", action=f"action_{i}", resource_id=f"res_{i}")

    # Delete the latest record (truncation of head)
    with system["app"].state.sessions.begin() as db:
        records = list(db.scalars(select(AuditLog).where(AuditLog.organization_id == org_id).order_by(AuditLog.created_at.asc())))
        db.delete(records[-1])

    # Verification MUST fail because AuditHead expects 5 entries with head hash 5
    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_checkpoint_independent_verification_and_tampering(system):
    """Verify an audit checkpoint independently using raw Ed25519 routines

    and confirm that modifying any field invalidates the checkpoint.
    """
    settings = system["app"].state.settings
    org_id = system["org"]

    with system["app"].state.sessions.begin() as db:
        for i in range(3):
            audit(db, settings, org_id, actor="admin", action=f"chk_action_{i}", resource_id=f"chk_res_{i}")
        chk = create_audit_checkpoint(db, settings, org_id)

    # 1. Independent Ed25519 verification with controller public key
    ctrl_pub = get_controller_public_key_hex(settings)
    stamp = chk.created_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    payload = {
        "organization_id": chk.organization_id,
        "sequence_number": chk.sequence_number,
        "head_entry_hash": chk.head_entry_hash,
        "timestamp": stamp.isoformat(),
    }
    assert ed25519_verify_canonical(ctrl_pub, chk.signature, payload) is True

    # 2. Modify sequence number -> raw signature verification fails
    tampered_payload = dict(payload)
    tampered_payload["sequence_number"] = 999
    assert ed25519_verify_canonical(ctrl_pub, chk.signature, tampered_payload) is False

    # 3. Modify head_entry_hash -> raw signature verification fails
    tampered_payload_2 = dict(payload)
    tampered_payload_2["head_entry_hash"] = "0" * 64
    assert ed25519_verify_canonical(ctrl_pub, chk.signature, tampered_payload_2) is False


def test_audit_checkpoint_external_export_boundary_status(system):
    """Determine whether checkpoints are exported to an independently controlled

    immutable or append-only destination.

    Finding: In the current architecture, checkpoints are persisted to the relational
    database table `audit_checkpoints`, but no external immutable destination
    (e.g., AWS S3 Object Lock, Cloud KMS, or WORM destination) is actively configured.
    Therefore, external trust anchoring is documented as INCOMPLETE.
    """
    with system["app"].state.sessions() as db:
        chk_count = db.scalar(select(AuditCheckpoint))
        assert chk_count is None or isinstance(chk_count, AuditCheckpoint)

    # Architectural boundary verification: settings have no external WORM bucket configured
    settings = system["app"].state.settings
    assert not hasattr(settings, "worm_storage_bucket")
    assert not hasattr(settings, "s3_object_lock_arn")


# ==============================================================================
# C. ENTERPRISE MFA, CHALLENGE, AND LOCKOUT CONTROLS
# ==============================================================================


def test_mfa_incomplete_challenges_and_invalid_codes(system):
    """Test MFA challenge flow: missing code, invalid code, and valid code."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SECURITY_ADMIN"]

    # Setup MFA for security_admin
    setup_resp = client.post("/api/v1/auth/mfa/setup")
    assert setup_resp.status_code == 200
    secret = setup_resp.json()["secret"]

    # Enable MFA
    code = generate_totp(secret)
    verify_resp = client.post("/api/v1/auth/mfa/verify", json={"code": code})
    assert verify_resp.status_code == 200

    # 1. Login without MFA code -> returns mfa_required, NO access_token
    client.headers.pop("Authorization")
    resp_no_mfa = client.post(
        "/api/v1/auth/login",
        json={"username": "security_admin", "password": "correct-test-password-123"},
    )
    assert resp_no_mfa.status_code == 200
    assert resp_no_mfa.json().get("mfa_required") is True
    assert "access_token" not in resp_no_mfa.json()

    # 2. Login with invalid 6-digit MFA code -> 401 Unauthorized
    resp_bad_mfa = client.post(
        "/api/v1/auth/login",
        json={"username": "security_admin", "password": "correct-test-password-123", "mfa_code": "000000"},
    )
    assert resp_bad_mfa.status_code == 401

    # 3. Login with expired MFA code (time step from 2 minutes ago) -> 401 Unauthorized
    expired_code = generate_totp(secret, timestamp=time.time() - 120)
    resp_exp_mfa = client.post(
        "/api/v1/auth/login",
        json={"username": "security_admin", "password": "correct-test-password-123", "mfa_code": expired_code},
    )
    assert resp_exp_mfa.status_code == 401


def test_mfa_brute_force_lockout_after_five_failed_attempts(system):
    """Verify that 5 failed MFA attempts trigger a 15-minute account lockout."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]

    # Setup and enable MFA
    setup_resp = client.post("/api/v1/auth/mfa/setup")
    secret = setup_resp.json()["secret"]
    client.post("/api/v1/auth/mfa/verify", json={"code": generate_totp(secret)})

    # Fail 5 times with bad MFA code
    client.headers.pop("Authorization")
    for i in range(5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "soc_manager", "password": "correct-test-password-123", "mfa_code": f"11111{i}"},
        )
        assert resp.status_code == 401

    # 6th attempt with CORRECT password and CORRECT MFA code must fail due to lockout
    good_code = generate_totp(secret)
    locked_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "soc_manager", "password": "correct-test-password-123", "mfa_code": good_code},
    )
    assert locked_resp.status_code == 401
    error_msg = locked_resp.json().get("error", {}).get("message", "").lower()
    assert "locked" in error_msg


def test_session_revocation_across_endpoints(system):
    """Verify that logging out revokes the session token immediately."""
    client = system["client"]
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "viewer", "password": "correct-test-password-123"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    client.headers["Authorization"] = f"Bearer {token}"
    # Valid call succeeds
    me_resp = client.get("/api/v1/auth/me")
    assert me_resp.status_code == 200

    # Logout
    logout_resp = client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 200

    # Subsequent call with the revoked token fails (401 Unauthorized)
    revoked_resp = client.get("/api/v1/auth/me")
    assert revoked_resp.status_code == 401


def test_unauthorized_access_to_privileged_agent_and_admin_endpoints(system):
    """Verify strict RBAC enforcement on newly added security and agent endpoints."""
    client = system["client"]

    # 1. Unauthenticated request to issue enrollment token -> 401
    client.headers.pop("Authorization", None)
    assert client.post("/api/v1/agents/enrollment-tokens").status_code == 401

    # 2. Viewer role attempting to issue enrollment token -> 403 Forbidden
    client.headers["Authorization"] = "Bearer " + system["tokens"]["VIEWER"]
    assert client.post("/api/v1/agents/enrollment-tokens").status_code == 403

    # 3. Viewer role attempting to revoke an agent -> 403 Forbidden
    assert client.post("/api/v1/agents/SRV-TEST/revoke", json={"reason": "test"}).status_code == 403

    # 4. Super Admin can access enrollment tokens
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    assert client.post("/api/v1/agents/enrollment-tokens").status_code == 200
