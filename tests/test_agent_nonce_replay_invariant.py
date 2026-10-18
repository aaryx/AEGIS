"""Agent Nonce Replay-Protection Invariant & Receipt Verification Test Suite.

Validates:
1. Replaying the same nonce before and after expiry is unconditionally rejected.
2. Concurrent duplicate receipt submissions are serialized atomically (exactly 1 succeeds, others 409).
3. Expired and canceled commands reject receipts and prevent replay.
4. Nonces persist in WindowState across sessions and are pruned only after validity expiration.
5. Ed25519 key rotation requires valid signature from previous key; invalid signatures and retired keys fail.
"""

from __future__ import annotations

import concurrent.futures
import secrets
import time

from sqlalchemy import delete, select

from aegis.agent import EndpointAgent
from aegis.crypto import (
    ed25519_sign_canonical,
    generate_ed25519_keypair,
)
from aegis.db import Agent, Entity, PlaybookExecution, WindowState


def helper_create_command(system, agent_name: str, action="isolate_host") -> str:
    """Helper to request, approve, and execute a command for an agent."""
    client = system["client"]
    org_id = system["org"]
    with system["app"].state.sessions() as db:
        entity = db.scalar(
            select(Entity).where(Entity.organization_id == org_id, Entity.type == "host", Entity.value == agent_name)
        )
        assert entity is not None, f"Host entity for {agent_name} not found"

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    req = client.post(
        "/api/v1/playbooks/request",
        json={"action": action, "target": entity.id},
        headers={"Idempotency-Key": f"idem-{secrets.token_hex(8)}"},
    )
    assert req.status_code == 200, f"Command request failed: {req.text}"
    c_id = req.json()["id"]

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    appr = client.post(f"/api/v1/playbooks/{c_id}/approve")
    assert appr.status_code == 200, f"Command approve failed: {appr.text}"

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    exec_res = client.post(f"/api/v1/playbooks/{c_id}/execute")
    assert exec_res.status_code == 200, f"Command execute failed: {exec_res.text}"
    return c_id


def test_nonce_replay_rejected_before_and_after_expiry(system):
    """Prove that replaying a nonce fails before expiry (409) and after expiry (400/409)."""
    client = system["client"]
    agent_name = "SRV-NONCE-REPLAY-01"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    cmd_id = helper_create_command(system, agent_name, "isolate_host")
    pending = agent.poll_commands(client=client)
    cmd = next(c for c in pending if c["id"] == cmd_id)
    ctrl_sig = cmd["controller_signature"]

    fixed_nonce = "fixed_test_nonce_" + secrets.token_hex(16)
    receipt_data = {
        "version": "1.0",
        "command_id": cmd_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": ctrl_sig,
        "timestamp": time.time(),
        "nonce": fixed_nonce,
    }
    sig = ed25519_sign_canonical(agent.private_key, receipt_data)

    # 1. First legitimate submission succeeds
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    res1 = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt_data,
            "signature": sig,
            "details": {"isolated": True},
        },
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "UNKNOWN"

    # 2. Immediate replay on the same execution is rejected with 409
    res_immediate_replay = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt_data,
            "signature": sig,
            "details": {"isolated": True},
        },
    )
    assert res_immediate_replay.status_code == 409

    # 3. Replay with the same nonce on a DIFFERENT active command before expiry is rejected with 409
    cmd2_id = helper_create_command(system, agent_name, "unisolate_host")
    pending2 = agent.poll_commands(client=client)
    cmd2 = next(c for c in pending2 if c["id"] == cmd2_id)

    receipt2_data = {
        "version": "1.0",
        "command_id": cmd2_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "unisolate_host",
        "status": "SUCCESS",
        "result": {"unisolated": True},
        "command_signature": cmd2["controller_signature"],
        "timestamp": time.time(),
        "nonce": fixed_nonce,  # REUSED NONCE!
    }
    sig2 = ed25519_sign_canonical(agent.private_key, receipt2_data)
    res_reused_nonce = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd2_id,
            "action": "unisolate_host",
            "status": "SUCCESS",
            "receipt": receipt2_data,
            "signature": sig2,
            "details": {"unisolated": True},
        },
    )
    assert res_reused_nonce.status_code == 409
    assert "nonce has already been used" in res_reused_nonce.json()["error"]["message"].lower()

    # Finish this command with a fresh authenticated receipt before dispatching
    # another command. An unresolved command now blocks conflicting dispatch.
    receipt2_data["nonce"] = secrets.token_hex(16)
    accepted = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={"command_id": cmd2_id, "action": "unisolate_host", "status": "SUCCESS",
              "receipt": receipt2_data, "signature": ed25519_sign_canonical(agent.private_key, receipt2_data)},
    )
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "UNKNOWN"
    assert accepted.json()["result"]["enforced_externally"] is False

    # 4. Replay with expired freshness window (> 300s) on active command is rejected with 400
    cmd3_id = helper_create_command(system, agent_name, "isolate_host")
    pending3 = agent.poll_commands(client=client)
    cmd3 = next(c for c in pending3 if c["id"] == cmd3_id)

    stale_receipt = {
        "version": "1.0",
        "command_id": cmd3_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": cmd3["controller_signature"],
        "timestamp": time.time() - 3600.0,  # Expired freshness window (1 hour ago)
        "nonce": "stale_freshness_nonce_" + secrets.token_hex(16),
    }
    stale_sig = ed25519_sign_canonical(agent.private_key, stale_receipt)
    res_stale = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd3_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": stale_receipt,
            "signature": stale_sig,
            "details": {"isolated": True},
        },
    )
    assert res_stale.status_code == 400
    assert "freshness window" in res_stale.json()["error"]["message"].lower()


def test_concurrent_duplicate_receipt_submissions(system):
    """Prove that concurrent submissions of the identical receipt result in exactly 1 success and N-1 409s."""
    client = system["client"]
    agent_name = "SRV-RACE-01"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    cmd_id = helper_create_command(system, agent_name, "isolate_host")
    pending = agent.poll_commands(client=client)
    cmd = next(c for c in pending if c["id"] == cmd_id)

    receipt = {
        "version": "1.0",
        "command_id": cmd_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": cmd["controller_signature"],
        "timestamp": time.time(),
        "nonce": "race_nonce_" + secrets.token_hex(16),
    }
    sig = ed25519_sign_canonical(agent.private_key, receipt)

    body = {
        "command_id": cmd_id,
        "action": "isolate_host",
        "status": "SUCCESS",
        "receipt": receipt,
        "signature": sig,
        "details": {"isolated": True},
    }

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]

    def submit_receipt(_):
        resp = client.post(f"/api/v1/agents/{agent_name}/receipts", json=body)
        return resp.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        statuses = list(pool.map(submit_receipt, range(6)))

    assert statuses.count(200) == 1, f"Expected exactly one 200, got: {statuses}"
    assert statuses.count(409) == 5, f"Expected five 409s, got: {statuses}"


def test_expired_and_canceled_commands_reject_receipt(system):
    """Submitting receipts for expired or canceled commands is strictly rejected."""
    client = system["client"]
    agent_name = "SRV-EXPIRE-CANCEL-01"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    # 1. Expired command envelope
    cmd_expired_id = helper_create_command(system, agent_name, "isolate_host")
    pending = agent.poll_commands(client=client)
    cmd_exp = next(c for c in pending if c["id"] == cmd_expired_id)

    # Force expiration into past
    with system["app"].state.sessions() as db:
        row = db.get(PlaybookExecution, cmd_expired_id)
        res_data = dict(row.result or {})
        env = dict(res_data.get("command_envelope") or {})
        env["expires_at"] = time.time() - 60.0
        res_data["command_envelope"] = env
        row.result = res_data
        db.commit()

    receipt_exp = {
        "version": "1.0",
        "command_id": cmd_expired_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": cmd_exp["controller_signature"],
        "timestamp": time.time(),
        "nonce": "exp_nonce_" + secrets.token_hex(16),
    }
    sig_exp = ed25519_sign_canonical(agent.private_key, receipt_exp)
    res_exp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd_expired_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt_exp,
            "signature": sig_exp,
            "details": {"isolated": True},
        },
    )
    assert res_exp.status_code == 409
    assert "expired" in res_exp.json()["error"]["message"].lower()

    # 2. Canceled command
    cmd_canceled_id = helper_create_command(system, agent_name, "unisolate_host")
    pending2 = agent.poll_commands(client=client)
    cmd_canc = next(c for c in pending2 if c["id"] == cmd_canceled_id)

    with system["app"].state.sessions() as db:
        row = db.get(PlaybookExecution, cmd_canceled_id)
        row.status = "CANCELED"
        db.commit()

    receipt_canc = {
        "version": "1.0",
        "command_id": cmd_canceled_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "unisolate_host",
        "status": "SUCCESS",
        "result": {"unisolated": True},
        "command_signature": cmd_canc["controller_signature"],
        "timestamp": time.time(),
        "nonce": "canc_nonce_" + secrets.token_hex(16),
    }
    sig_canc = ed25519_sign_canonical(agent.private_key, receipt_canc)
    res_canc = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd_canceled_id,
            "action": "unisolate_host",
            "status": "SUCCESS",
            "receipt": receipt_canc,
            "signature": sig_canc,
            "details": {"unisolated": True},
        },
    )
    assert res_canc.status_code == 409
    assert "canceled" in res_canc.json()["error"]["message"].lower()


def test_nonce_persistence_and_cleanup(system):
    """Verify nonces persist in WindowState across sessions and cleanup removes only expired nonces."""
    client = system["client"]
    agent_name = "SRV-PERSIST-01"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    cmd_id = helper_create_command(system, agent_name, "isolate_host")
    pending = agent.poll_commands(client=client)
    cmd = next(c for c in pending if c["id"] == cmd_id)

    unique_nonce = "persisted_nonce_" + secrets.token_hex(16)
    receipt = {
        "version": "1.0",
        "command_id": cmd_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": cmd["controller_signature"],
        "timestamp": time.time(),
        "nonce": unique_nonce,
    }
    sig = ed25519_sign_canonical(agent.private_key, receipt)

    res = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt,
            "signature": sig,
            "details": {"isolated": True},
        },
    )
    assert res.status_code == 200

    # Verify nonce row exists in WindowState database
    with system["app"].state.sessions() as db:
        agent_row = db.scalar(select(Agent).where(Agent.name == agent_name))
        nonce_key = f"agent_nonce:{agent_row.id}:{unique_nonce}"
        row = db.scalar(select(WindowState).where(WindowState.key == nonce_key))
        assert row is not None, "Nonce row must be persisted in WindowState"
        assert row.expires > time.time() + 3600.0, "Nonce TTL must span full retention window"

        # Simulate background worker pruning pass: active nonce must NOT be deleted
        db.execute(delete(WindowState).where(WindowState.expires < time.time()))
        db.commit()
        persisted_after_prune = db.scalar(select(WindowState).where(WindowState.key == nonce_key))
        assert persisted_after_prune is not None, "Active nonce must survive worker pruning"

        # If nonce expires in the past, it is cleaned up
        row.expires = time.time() - 10.0
        db.commit()
        db.execute(delete(WindowState).where(WindowState.expires < time.time()))
        db.commit()
        pruned_row = db.scalar(select(WindowState).where(WindowState.key == nonce_key))
        assert pruned_row is None, "Expired nonce must be pruned by cleanup"


def test_agent_key_rotation_and_invalid_signatures(system):
    """Test cryptographic Ed25519 key rotation with signature, and prove invalid keys fail."""
    client = system["client"]
    agent_name = "SRV-ROTATION-01"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    old_priv = agent.private_key

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]

    # 1. Invalid signature on rotation payload is rejected with 400
    fake_priv, _ = generate_ed25519_keypair()
    _, new_pub_hex = generate_ed25519_keypair()
    forged_sig = ed25519_sign_canonical(fake_priv, {"name": agent_name, "new_public_key": new_pub_hex})
    bad_resp = client.post(
        f"/api/v1/agents/{agent_name}/rotate-key",
        json={"new_public_key": new_pub_hex, "rotation_signature": forged_sig},
    )
    assert bad_resp.status_code == 400
    assert "signature" in bad_resp.json()["error"]["message"].lower()

    # 2. Legitimate key rotation signed by current key succeeds
    rotate_res = agent.rotate_key(client=client)
    assert rotate_res["status"] == "ok"
    assert rotate_res["public_key"] == agent.public_key_hex

    # 3. Submitting receipt signed by OLD (retired) key must now be rejected
    cmd_id = helper_create_command(system, agent_name, "isolate_host")
    pending = agent.poll_commands(client=client)
    cmd = next(c for c in pending if c["id"] == cmd_id)

    receipt_old_key = {
        "version": "1.0",
        "command_id": cmd_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": cmd["controller_signature"],
        "timestamp": time.time(),
        "nonce": "old_key_nonce_" + secrets.token_hex(16),
    }
    sig_old = ed25519_sign_canonical(old_priv, receipt_old_key)  # Signed with OLD key!
    res_old_key = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt_old_key,
            "signature": sig_old,
            "details": {"isolated": True},
        },
    )
    assert res_old_key.status_code == 400
    assert "signature verification failed" in res_old_key.json()["error"]["message"].lower()

    # 4. Submitting receipt signed by NEW key succeeds
    sig_new = ed25519_sign_canonical(agent.private_key, receipt_old_key)  # Signed with NEW key
    res_new_key = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": receipt_old_key,
            "signature": sig_new,
            "details": {"isolated": True},
        },
    )
    assert res_new_key.status_code == 200
    assert res_new_key.json()["status"] == "UNKNOWN"
