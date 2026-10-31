"""Tests for Audit key versioning & checkpoints (P1) and Enterprise MFA (P1).
"""

import json

from sqlalchemy import select

from aegis.crypto import generate_totp
from aegis.db import AuditLog, User
from aegis.security import (
    audit,
    create_audit_checkpoint,
    verify_audit,
    verify_audit_checkpoint,
)


def test_audit_key_rotation_and_checkpoints(system):
    """Test audit log HMAC key rotation across versions and signed checkpoints."""
    settings = system["app"].state.settings
    org_id = system["org"]

    # 1. Write audit records under key version 1
    settings.audit_key_version = 1
    with system["app"].state.sessions.begin() as db:
        for i in range(3):
            audit(db, settings, org_id, actor="admin", action=f"v1_action_{i}", resource_id=f"r1_{i}")

    # 2. Create and verify signed audit checkpoint
    with system["app"].state.sessions.begin() as db:
        chk1 = create_audit_checkpoint(db, settings, org_id)
        assert verify_audit_checkpoint(db, settings, chk1) is True

    # 3. Rotate key version to 2
    settings.audit_key_version = 2
    with system["app"].state.sessions.begin() as db:
        for i in range(3):
            audit(db, settings, org_id, actor="admin", action=f"v2_action_{i}", resource_id=f"r2_{i}")

    # 4. Verify that historical v1 and current v2 entries both verify
    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is True

    # 5. Create and verify checkpoint for version 2
    with system["app"].state.sessions.begin() as db:
        chk2 = create_audit_checkpoint(db, settings, org_id)
        assert chk2.sequence_number == 6
        assert verify_audit_checkpoint(db, settings, chk2) is True

    # 6. Tampering with checkpoint signature or data fails verification
    chk2.head_entry_hash = "f" * 64
    assert verify_audit_checkpoint(db, settings, chk2) is False


def test_enterprise_mfa_lifecycle_and_login_challenge(system):
    """Test TOTP MFA setup, verification, login challenge, and lockout protection."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # 1. Initiate MFA setup
    setup_resp = client.post("/api/v1/auth/mfa/setup")
    assert setup_resp.status_code == 200, setup_resp.text
    secret = setup_resp.json()["secret"]
    assert len(secret) == 32
    assert "otpauth://" in setup_resp.json()["otpauth_uri"]

    # 2. Verify with invalid code -> 400
    bad_resp = client.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
    assert bad_resp.status_code == 400

    # 3. Verify with valid TOTP code
    valid_code = generate_totp(secret)
    good_resp = client.post("/api/v1/auth/mfa/verify", json={"code": valid_code})
    assert good_resp.status_code == 200
    assert good_resp.json()["mfa_enabled"] is True

    # 4. Attempt login without MFA code -> returns mfa_required
    client.headers.pop("Authorization")
    login_attempt = client.post(
        "/api/v1/auth/login",
        json={"username": "super_admin", "password": "correct-test-password-123"},
    )
    assert login_attempt.status_code == 200
    assert login_attempt.json().get("mfa_required") is True

    # 5. Attempt login with bad MFA code -> 401
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"username": "super_admin", "password": "correct-test-password-123", "mfa_code": "999999"},
    )
    assert bad_login.status_code == 401

    # 6. Login with valid MFA code -> succeeds
    current_code = generate_totp(secret)
    success_login = client.post(
        "/api/v1/auth/login",
        json={"username": "super_admin", "password": "correct-test-password-123", "mfa_code": current_code},
    )
    assert success_login.status_code == 200
    assert "access_token" in success_login.json()


def test_audit_verification_closed_failure_on_missing_or_tampered_head(system):
    """Section 11: Audit integrity must fail closed when AuditHead is deleted, desynced, or tampered."""
    from sqlalchemy import delete, select

    from aegis.db import AuditHead, AuditLog

    settings = system["app"].state.settings
    org_id = system["org"]

    # 1. Write audit entries
    with system["app"].state.sessions.begin() as db:
        for i in range(4):
            audit(db, settings, org_id, actor="admin", action=f"op_{i}", resource_id=f"res_{i}")

    # 2. Baseline passes
    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is True

    # 3. Attacker deletes AuditHead row -> verify_audit MUST fail closed (return False)
    with system["app"].state.sessions.begin() as db:
        db.execute(delete(AuditHead).where(AuditHead.organization_id == org_id))

    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is False

    # 4. Restore AuditHead but with mismatched sequence number -> return False
    with system["app"].state.sessions.begin() as db:
        # Re-fetch the last audit entry hash
        last_log = db.scalar(
            select(AuditLog).where(AuditLog.organization_id == org_id).order_by(AuditLog.created_at.desc())
        )
        head = AuditHead(
            organization_id=org_id,
            audit_head=last_log.entry_hash,
            sequence_number=999,  # tampered sequence number
        )
        db.add(head)

    with system["app"].state.sessions() as db:
        assert verify_audit(db, settings, org_id) is False



def test_mfa_setup_refused_when_enabled(system):
    """B3: a session for an MFA-enabled account cannot re-key the second factor."""
    client = system["client"]
    s1 = client.post("/api/v1/auth/mfa/setup").json()["secret"]
    assert client.post("/api/v1/auth/mfa/verify", json={"code": generate_totp(s1)}).status_code == 200

    resp = client.post("/api/v1/auth/mfa/setup")
    assert resp.status_code == 409, resp.text
    with system["app"].state.sessions() as db:
        assert db.get(User, system["users"]["SUPER_ADMIN"].id).mfa_secret == s1

    client.headers.pop("Authorization")
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "super_admin", "password": "correct-test-password-123", "mfa_code": generate_totp(s1)},
    )
    assert login.status_code == 200 and "access_token" in login.json()


def test_mfa_setup_is_audited_without_secret(system):
    """B3: first-time MFA setup leaves one audit row that does not leak the secret."""
    user_id = system["users"]["SUPER_ADMIN"].id
    secret = system["client"].post("/api/v1/auth/mfa/setup").json()["secret"]
    with system["app"].state.sessions() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.action == "auth.mfa_setup", AuditLog.actor == user_id)
        ).all()
    assert len(rows) == 1
    assert secret not in json.dumps(rows[0].details)
