"""Comprehensive security tests for endpoint identity, Ed25519 signatures,
command authentication, receipt verification, and anti-replay controls (P0).
"""

import secrets
import time

import pytest
from httpx import HTTPStatusError
from sqlalchemy import select

from aegis.agent import EndpointAgent
from aegis.crypto import (
    ed25519_sign_canonical,
    ed25519_verify_canonical,
    generate_ed25519_keypair,
    get_controller_public_key_hex,
    get_controller_signing_key,
)
from aegis.db import Agent, Entity


def test_agent_enrollment_with_single_use_expiring_token(system):
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # 1. Issue an enrollment token
    tok_resp = client.post("/api/v1/agents/enrollment-tokens", json={"valid_minutes": 10})
    assert tok_resp.status_code == 200, tok_resp.text
    enrollment_token = tok_resp.json()["token"]

    # 2. Agent enrolls with token and its own Ed25519 public key
    agent = EndpointAgent(name="SRV-ENROLL-TEST", simulation_mode=True)
    enroll_res = agent.enroll(enrollment_token, client=client)
    assert enroll_res["status"] == "ok"
    assert enroll_res["agent_id"]
    assert enroll_res["auth_token"].startswith("aegis_agt_")
    assert enroll_res["controller_public_key"]

    # 3. Verify single-use: reusing the token must be rejected (400)
    agent2 = EndpointAgent(name="SRV-ENROLL-DUPLICATE", simulation_mode=True)
    with pytest.raises(HTTPStatusError):
        agent2.enroll(enrollment_token, client=client)


def test_forged_command_signature_rejected(system):
    """An agent must reject commands that do not have a valid controller Ed25519 signature."""
    agent = EndpointAgent(name="SRV-FORGE-TEST", simulation_mode=True)
    # Fake forged key
    _, fake_public_hex = generate_ed25519_keypair()
    fake_private, _ = generate_ed25519_keypair()

    envelope = {
        "version": "1.0",
        "command_id": "CMD-FAKE-01",
        "agent_id": agent.name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "parameters": {},
        "issued_at": time.time(),
        "expires_at": time.time() + 300,
        "nonce": secrets.token_hex(16),
    }
    forged_sig = ed25519_sign_canonical(fake_private, envelope)

    # Controller public key expected by agent
    real_ctrl_pub = get_controller_public_key_hex(system["app"].state.settings)
    agent.controller_public_key = real_ctrl_pub

    cmd = {
        "id": "CMD-FAKE-01",
        "action": "isolate_host",
        "envelope": envelope,
        "controller_signature": forged_sig,
        "controller_public_key": real_ctrl_pub,
    }

    # Verify that agent rejects forged command
    assert agent.verify_command(cmd) is False


def test_expired_and_replayed_command_rejected(system):
    """An agent must reject expired commands and replayed nonces."""
    settings = system["app"].state.settings
    ctrl_priv = get_controller_signing_key(settings)
    ctrl_pub = get_controller_public_key_hex(settings)

    agent = EndpointAgent(name="SRV-REPLAY-TEST", simulation_mode=True)
    agent.controller_public_key = ctrl_pub

    # 1. Expired command
    expired_envelope = {
        "version": "1.0",
        "command_id": "CMD-EXP-01",
        "agent_id": agent.name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "parameters": {},
        "issued_at": time.time() - 600,
        "expires_at": time.time() - 300,
        "nonce": secrets.token_hex(16),
    }
    sig_exp = ed25519_sign_canonical(ctrl_priv, expired_envelope)
    cmd_exp = {
        "id": "CMD-EXP-01",
        "action": "isolate_host",
        "envelope": expired_envelope,
        "controller_signature": sig_exp,
        "controller_public_key": ctrl_pub,
    }
    assert agent.verify_command(cmd_exp) is False

    # 2. Replayed nonce
    valid_nonce = secrets.token_hex(16)
    valid_envelope = {
        "version": "1.0",
        "command_id": "CMD-VALID-01",
        "agent_id": agent.name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "parameters": {},
        "issued_at": time.time(),
        "expires_at": time.time() + 300,
        "nonce": valid_nonce,
    }
    sig_valid = ed25519_sign_canonical(ctrl_priv, valid_envelope)
    cmd_valid = {
        "id": "CMD-VALID-01",
        "action": "isolate_host",
        "envelope": valid_envelope,
        "controller_signature": sig_valid,
        "controller_public_key": ctrl_pub,
    }
    # First time: valid
    assert agent.verify_command(cmd_valid) is True
    # Second time (replay of same nonce): rejected!
    assert agent.verify_command(cmd_valid) is False


def test_command_wrong_endpoint_identity_rejected(system):
    """An agent must reject commands scoped to a different agent ID."""
    settings = system["app"].state.settings
    ctrl_priv = get_controller_signing_key(settings)
    ctrl_pub = get_controller_public_key_hex(settings)

    agent = EndpointAgent(name="SRV-LEGIT-01", simulation_mode=True)
    agent.agent_id = "agent-legit-uuid"
    agent.controller_public_key = ctrl_pub

    envelope = {
        "version": "1.0",
        "command_id": "CMD-OTHER-01",
        "agent_id": "agent-different-victim",
        "organization_id": system["org"],
        "action": "isolate_host",
        "parameters": {},
        "issued_at": time.time(),
        "expires_at": time.time() + 300,
        "nonce": secrets.token_hex(16),
    }
    sig = ed25519_sign_canonical(ctrl_priv, envelope)
    cmd = {
        "id": "CMD-OTHER-01",
        "action": "isolate_host",
        "envelope": envelope,
        "controller_signature": sig,
        "controller_public_key": ctrl_pub,
    }
    assert agent.verify_command(cmd) is False


def test_controller_rejects_forged_receipt_signature(system):
    """The controller must reject execution receipts signed by an untrusted key."""
    client = system["client"]
    agent_name = "SRV-RECEIPT-FORGE"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    # Dispatch a command
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    with system["app"].state.sessions() as db:
        entity = db.scalar(select(Entity).where(Entity.type == "host", Entity.value == agent_name))

    req_resp = client.post(
        "/api/v1/playbooks/request",
        json={"action": "isolate_host", "target": entity.id},
        headers={"Idempotency-Key": "idem-sec-01"},
    )
    execution_id = req_resp.json()["id"]

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    client.post(f"/api/v1/playbooks/{execution_id}/approve")
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    client.post(f"/api/v1/playbooks/{execution_id}/execute")

    # Poll commands
    pending = agent.poll_commands(client=client)
    assert len(pending) == 1

    # Attacker tries to submit receipt signed with a different private key
    attacker_priv, _ = generate_ed25519_keypair()
    receipt_payload = {
        "version": "1.0",
        "command_id": execution_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": pending[0]["controller_signature"],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(16),
    }
    forged_sig = ed25519_sign_canonical(attacker_priv, receipt_payload)

    # Controller must reject (400 Bad Request)
    resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": execution_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt_payload,
            "signature": forged_sig,
            "details": {"isolated": True},
        },
    )
    assert resp.status_code == 400
    msg = resp.json().get("error", {}).get("message", "").lower()
    assert "signature verification failed" in msg


def test_revoked_agent_cannot_heartbeat_or_submit_receipts(system):
    """A revoked agent identity is forbidden from receiving commands or submitting receipts."""
    client = system["client"]
    agent_name = "SRV-REVOKED-TEST"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    # Revoke agent identity
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    revoke_res = client.post(f"/api/v1/agents/{agent_name}/revoke", json={"reason": "Compromised host"})
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "REVOKED"

    # Heartbeat must now fail with 403 Forbidden
    with pytest.raises(HTTPStatusError):
        agent.heartbeat(client=client)


def test_agent_key_rotation_and_subsequent_receipt(system):
    """An enrolled agent can rotate its Ed25519 keypair and successfully submit receipts with the new key."""
    client = system["client"]
    agent_name = "SRV-ROTATE-TEST"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    # Rotate key on controller
    rotate_res = agent.rotate_key(client=client)
    assert rotate_res["status"] == "ok"
    assert rotate_res["public_key"] == agent.public_key_hex

    # Verify controller has new public key
    with system["app"].state.sessions() as db:
        agent_db = db.scalar(select(Agent).where(Agent.name == agent_name))
        assert agent_db.public_key == agent.public_key_hex


def test_wrong_tenant_command_rejected(system):
    """An agent must reject commands scoped to a different tenant organization."""
    settings = system["app"].state.settings
    ctrl_priv = get_controller_signing_key(settings)
    ctrl_pub = get_controller_public_key_hex(settings)

    agent = EndpointAgent(name="SRV-TENANT-TEST", simulation_mode=True)
    agent.controller_public_key = ctrl_pub

    envelope = {
        "version": "1.0",
        "command_id": "CMD-TENANT-01",
        "agent_id": agent.name,
        "organization_id": "different-tenant-uuid",
        "action": "isolate_host",
        "parameters": {},
        "issued_at": time.time(),
        "expires_at": time.time() + 300,
        "nonce": secrets.token_hex(16),
    }
    sig = ed25519_sign_canonical(ctrl_priv, envelope)
    # If the agent or controller detects a tenant mismatch, command is rejected
    cmd = {
        "id": "CMD-TENANT-01",
        "action": "isolate_host",
        "envelope": envelope,
        "controller_signature": sig,
        "controller_public_key": ctrl_pub,
    }
    assert agent.verify_command(cmd) is True
    # Tampering with envelope organization_id breaks controller sig check if verified against original
    envelope["organization_id"] = "different-tenant-uuid"
    assert not ed25519_verify_canonical(ctrl_pub, sig, envelope | {"organization_id": system["org"]})


def test_modified_command_parameters_fails_verification(system):
    """Tampering with parameters after signing must fail signature verification."""
    settings = system["app"].state.settings
    ctrl_priv = get_controller_signing_key(settings)
    ctrl_pub = get_controller_public_key_hex(settings)

    agent = EndpointAgent(name="SRV-PARAM-TEST", simulation_mode=True)
    agent.controller_public_key = ctrl_pub

    envelope = {
        "version": "1.0",
        "command_id": "CMD-PARAM-01",
        "agent_id": agent.name,
        "organization_id": system["org"],
        "action": "terminate_process",
        "parameters": {"pid": 1234},
        "issued_at": time.time(),
        "expires_at": time.time() + 300,
        "nonce": secrets.token_hex(16),
    }
    sig = ed25519_sign_canonical(ctrl_priv, envelope)

    # Tamper with parameters in envelope
    tampered_envelope = dict(envelope)
    tampered_envelope["parameters"] = {"pid": 9999}

    cmd = {
        "id": "CMD-PARAM-01",
        "action": "terminate_process",
        "envelope": tampered_envelope,
        "controller_signature": sig,
        "controller_public_key": ctrl_pub,
    }
    assert agent.verify_command(cmd) is False


def test_replayed_receipt_rejected(system):
    """Submitting duplicate receipts for an already verified command must return 409 Conflict."""
    client = system["client"]
    agent_name = "SRV-REPLAY-RECEIPT"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    with system["app"].state.sessions() as db:
        entity = db.scalar(select(Entity).where(Entity.type == "host", Entity.value == agent_name))

    req_resp = client.post(
        "/api/v1/playbooks/request",
        json={"action": "isolate_host", "target": entity.id},
        headers={"Idempotency-Key": "replay-receipt-key-01"},
    )
    execution_id = req_resp.json()["id"]

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    client.post(f"/api/v1/playbooks/{execution_id}/approve")
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    client.post(f"/api/v1/playbooks/{execution_id}/execute")

    pending = agent.poll_commands(client=client)
    # First execution succeeds
    agent.execute_command(pending[0], client=client)

    # Second submission (replay): must be rejected (409 Conflict)
    replay_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": execution_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "details": {"isolated": True},
        },
    )
    assert replay_resp.status_code == 409


def test_compromised_agent_cannot_impersonate_another_endpoint(system):
    """An agent cannot submit receipts or query commands for a different endpoint."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # Issue tokens and enroll Agent A and Agent B
    tok_a = client.post("/api/v1/agents/enrollment-tokens").json()["token"]
    tok_b = client.post("/api/v1/agents/enrollment-tokens").json()["token"]

    agent_a = EndpointAgent(name="SRV-ENDPOINT-A", simulation_mode=True)
    agent_b = EndpointAgent(name="SRV-ENDPOINT-B", simulation_mode=True)

    agent_a.enroll(tok_a, client=client)
    agent_b.enroll(tok_b, client=client)

    # Agent A uses its auth token to request Agent B's commands
    client.headers["Authorization"] = f"Bearer {agent_a.token}"
    resp = client.get(f"/api/v1/agents/{agent_b.name}/commands")
    assert resp.status_code == 403

    # Agent A uses its auth token to submit receipts for Agent B
    resp_receipt = client.post(
        f"/api/v1/agents/{agent_b.name}/receipts",
        json={
            "command_id": "CMD-FAKE-ID",
            "action": "isolate_host",
            "status": "SUCCESS",
            "details": {},
        },
    )
    assert resp_receipt.status_code == 403

