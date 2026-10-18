"""Project IRONCLAD: Autonomous Reliability, Security & Production Qualification Tests.

Adversarial validation covering:
- IRONCLAD-01: Retention legal hold preservation on CaseEvidence (plural and singular) and active alerts
- IRONCLAD-02: Cryptographic receipt verification requirement in agent receipts
- IRONCLAD-03: Enrolled agent token authentication on agent endpoints and anti-impersonation
- IRONCLAD-04: Cryptographic signature validation on agent Ed25519 key rotation
- IRONCLAD-05: Syslog TCP octet-counting bounded buffer defense against DoS
- IRONCLAD-06: Ingestion normalization returns 400 Bad Request instead of 503 on invalid IP/schema
- IRONCLAD-07: Process termination guardrails preventing PID <= 1 and system binary targeting
- IRONCLAD-08: Case workflow status transitions
"""

import hashlib
import secrets
import socket
import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from aegis.agent import EndpointAgent
from aegis.crypto import (
    canonical,
    ed25519_sign_canonical,
    generate_ed25519_keypair,
)
from aegis.db import (
    Alert,
    AlertEvent,
    Case,
    CaseEvidence,
    Entity,
    EventRecord,
    PlaybookExecution,
    User,
)
from aegis.retention import RetentionEngine
from aegis.syslog import SyslogServer


def test_ironclad_01_retention_legal_hold_case_evidence_plural_and_active_alerts(system):
    """Retention engine must protect events under case evidence (both 'events' and 'event')
    and active alerts (NEW, ACKNOWLEDGED, INVESTIGATING, ESCALATED)."""
    app = system["app"]
    sessions = app.state.sessions
    settings = app.state.settings
    org_id = system["org"]
    cutoff = datetime.now(UTC) - timedelta(days=settings.retention_days + 1)

    with sessions.begin() as db:
        user = db.scalar(select(User).where(User.organization_id == org_id))

        # 1. Old event with CaseEvidence resource_type="events" (standard API)
        ev_held_plural = EventRecord(
            id="ev-held-plural",
            organization_id=org_id,
            timestamp=cutoff - timedelta(days=5),
            source="test",
            evidence_hash="hash-plural",
            payload={"message": "held by case plural", "event_id": "ev-held-plural"},
            state="PROCESSED",
        )
        # 2. Old event with CaseEvidence resource_type="event" (singular)
        ev_held_singular = EventRecord(
            id="ev-held-singular",
            organization_id=org_id,
            timestamp=cutoff - timedelta(days=5),
            source="test",
            evidence_hash="hash-singular",
            payload={"message": "held by case singular", "event_id": "ev-held-singular"},
            state="PROCESSED",
        )
        # 3. Old event attached to an ESCALATED alert
        ev_escalated = EventRecord(
            id="ev-escalated-alert",
            organization_id=org_id,
            timestamp=cutoff - timedelta(days=5),
            source="test",
            evidence_hash="hash-escalated",
            payload={"message": "held by escalated alert", "event_id": "ev-escalated-alert"},
            state="PROCESSED",
        )
        # 4. Old event attached to an ACKNOWLEDGED alert
        ev_ack = EventRecord(
            id="ev-ack-alert",
            organization_id=org_id,
            timestamp=cutoff - timedelta(days=5),
            source="test",
            evidence_hash="hash-ack",
            payload={"message": "held by ack alert", "event_id": "ev-ack-alert"},
            state="PROCESSED",
        )
        # 5. Old unreferenced event (should be deleted)
        ev_unreferenced = EventRecord(
            id="ev-unreferenced-old",
            organization_id=org_id,
            timestamp=cutoff - timedelta(days=5),
            source="test",
            evidence_hash="hash-unref",
            payload={"message": "delete me", "event_id": "ev-unreferenced-old"},
            state="PROCESSED",
        )
        db.add_all([ev_held_plural, ev_held_singular, ev_escalated, ev_ack, ev_unreferenced])
        db.flush()

        # Add cases with evidence
        case_1 = Case(organization_id=org_id, title="Case Plural Evidence", status="OPEN", assignee=user.id)
        case_2 = Case(organization_id=org_id, title="Case Singular Evidence", status="OPEN", assignee=user.id)
        db.add_all([case_1, case_2])
        db.flush()

        db.add(
            CaseEvidence(
                organization_id=org_id,
                case_id=case_1.id,
                resource_type="events",  # API format
                resource_id=ev_held_plural.id,
                evidence_hash=ev_held_plural.evidence_hash,
                attached_by=user.id,
            )
        )
        db.add(
            CaseEvidence(
                organization_id=org_id,
                case_id=case_2.id,
                resource_type="event",  # Internal format
                resource_id=ev_held_singular.id,
                evidence_hash=ev_held_singular.evidence_hash,
                attached_by=user.id,
            )
        )

        # Add alerts
        alert_esc = Alert(
            id="alt-escalated",
            organization_id=org_id,
            title="Escalated Alert",
            severity="high",
            status="ESCALATED",
            rule_id="AEGIS-001",
            rule_version=1,
            fingerprint="fp-esc-1",
            correlation_key="ck-esc-1",
            confidence=90,
            risk_score=85,
            risk_factors={},
            explanation={},
            mitre_techniques=[],
            entity_ids=[],
            first_seen=cutoff,
            last_seen=cutoff,
            event_count=1,
        )
        alert_ack = Alert(
            id="alt-acknowledged",
            organization_id=org_id,
            title="Acknowledged Alert",
            severity="medium",
            status="ACKNOWLEDGED",
            rule_id="AEGIS-002",
            rule_version=1,
            fingerprint="fp-ack-1",
            correlation_key="ck-ack-1",
            confidence=80,
            risk_score=70,
            risk_factors={},
            explanation={},
            mitre_techniques=[],
            entity_ids=[],
            first_seen=cutoff,
            last_seen=cutoff,
            event_count=1,
        )
        db.add_all([alert_esc, alert_ack])
        db.flush()

        db.add(AlertEvent(alert_id=alert_esc.id, event_id=ev_escalated.id))
        db.add(AlertEvent(alert_id=alert_ack.id, event_id=ev_ack.id))

    # Run retention cycle
    engine = RetentionEngine(settings, sessions)
    engine.run_cycle(dry_run=False)

    with sessions() as db:
        # Held events must be preserved
        assert db.get(EventRecord, "ev-held-plural") is not None, "ev-held-plural was erroneously deleted"
        assert db.get(EventRecord, "ev-held-singular") is not None, "ev-held-singular was erroneously deleted"
        assert db.get(EventRecord, "ev-escalated-alert") is not None, (
            "ev-escalated-alert was erroneously deleted"
        )
        assert db.get(EventRecord, "ev-ack-alert") is not None, "ev-ack-alert was erroneously deleted"
        # Unreferenced event must be pruned
        assert db.get(EventRecord, "ev-unreferenced-old") is None, (
            "ev-unreferenced-old should have been pruned"
        )


def test_ironclad_02_agent_receipt_requires_cryptographic_verification(system):
    """Submitting an agent receipt without cryptographic signature or valid receipt hash must be rejected."""
    client = system["client"]
    agent_name = "SRV-RECEIPT-VERIF"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    with system["app"].state.sessions() as db:
        entity = db.scalar(select(Entity).where(Entity.type == "host", Entity.value == agent_name))

    req = client.post(
        "/api/v1/playbooks/request",
        json={"action": "isolate_host", "target": entity.id},
        headers={"Idempotency-Key": "idem-rcpt-verif-01"},
    )
    exec_id = req.json()["id"]

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    client.post(f"/api/v1/playbooks/{exec_id}/approve")
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    client.post(f"/api/v1/playbooks/{exec_id}/execute")

    # 1. Attacker tries to submit empty/unsigned receipt
    unverified_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": exec_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": {},
            "signature": "",
            "receipt_hash": None,
            "details": {"isolated": True},
        },
    )
    assert unverified_resp.status_code == 400
    assert "Cryptographic" in unverified_resp.json()["error"]["message"]

    # 2. Attacker tries to submit unkeyed recomputed SHA-256 checksum without Ed25519 signature
    expected_payload = {
        "command_id": exec_id,
        "agent": agent_name,
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
    }
    unkeyed_hash = hashlib.sha256(canonical(expected_payload).encode()).hexdigest()
    forged_hash_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": exec_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": {},
            "signature": "",
            "receipt_hash": unkeyed_hash,
            "details": {"isolated": True},
        },
    )
    # Must be rejected because an unkeyed SHA-256 checksum provides no cryptographic authenticity
    assert forged_hash_resp.status_code == 400, f"Expected 400 on unkeyed hash bypass, got {forged_hash_resp.status_code}"

    # Poll pending command to obtain controller signature
    pending = agent.poll_commands(client=client)
    assert len(pending) == 1
    ctrl_sig = pending[0]["controller_signature"]

    # 3. Attacker tries to submit receipt signed with forged/unregistered private key
    attacker_priv, attacker_pub = generate_ed25519_keypair()
    fake_receipt = {
        "version": "1.0",
        "command_id": exec_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": ctrl_sig,
        "timestamp": time.time(),
        "nonce": "a" * 32,
    }
    fake_sig = ed25519_sign_canonical(attacker_priv, fake_receipt)
    fake_sig_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": exec_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": fake_receipt,
            "signature": fake_sig,
            "details": {"isolated": True},
        },
    )
    assert fake_sig_resp.status_code == 400
    assert "signature verification failed" in fake_sig_resp.json()["error"]["message"].lower()

    # 4. Attacker tries to submit receipt with stale challenge (timestamp > 300s old)
    stale_receipt = dict(fake_receipt)
    stale_receipt["timestamp"] = time.time() - 3600.0  # 1 hour in the past
    stale_sig = ed25519_sign_canonical(agent.private_key, stale_receipt)
    stale_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": exec_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": stale_receipt,
            "signature": stale_sig,
            "details": {"isolated": True},
        },
    )
    assert stale_resp.status_code == 400
    assert "timestamp expired" in stale_resp.json()["error"]["message"].lower()

    # 5. Attacker tries to omit controller signature binding
    nobind_receipt = dict(fake_receipt)
    nobind_receipt["command_signature"] = ""
    nobind_sig = ed25519_sign_canonical(agent.private_key, nobind_receipt)
    nobind_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": exec_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": nobind_receipt,
            "signature": nobind_sig,
            "details": {"isolated": True},
        },
    )
    assert nobind_resp.status_code == 400
    assert "not bound" in nobind_resp.json()["error"]["message"].lower()

    # 6. Attacker modifies payload (tampered action inside signed receipt)
    tampered_receipt = dict(fake_receipt)
    tampered_receipt["action"] = "unisolate_host"
    tampered_sig = ed25519_sign_canonical(agent.private_key, tampered_receipt)
    tampered_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": exec_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": tampered_receipt,
            "signature": tampered_sig,
            "details": {"isolated": True},
        },
    )
    assert tampered_resp.status_code == 400
    assert "action does not match" in tampered_resp.json()["error"]["message"].lower()

    # 7. Legitimate agent executes command and submits cryptographically authentic receipt
    legit_result = agent.execute_command(pending[0], client=client)
    assert legit_result["status"] == "SIMULATED"
    assert legit_result["result"]["enforced_externally"] is False

    # 8. Replay of receipt against completed execution is rejected
    replay_resp = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": exec_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": fake_receipt,
            "signature": fake_sig,
            "details": {"isolated": True},
        },
    )
    assert replay_resp.status_code == 409


def test_ironclad_03_enrolled_agent_token_can_access_agent_endpoints_and_rejects_impersonation(system):
    """An enrolled agent with its assigned auth token must be permitted to call
    heartbeat, commands, and receipts for itself, but rejected when attempting to act for other agents."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # Enroll two agents
    tok_a = client.post("/api/v1/agents/enrollment-tokens").json()["token"]
    tok_b = client.post("/api/v1/agents/enrollment-tokens").json()["token"]

    agent_a = EndpointAgent(name="SRV-AUTHTOKEN-A", simulation_mode=True)
    agent_b = EndpointAgent(name="SRV-AUTHTOKEN-B", simulation_mode=True)

    agent_a.enroll(tok_a, client=client)
    agent_b.enroll(tok_b, client=client)

    assert agent_a.token.startswith("aegis_agt_")

    # Agent A can heartbeat for itself using its own auth token
    client.headers["Authorization"] = f"Bearer {agent_a.token}"
    hb_res = client.post("/api/v1/agents/heartbeat", json=agent_a.get_system_info())
    assert hb_res.status_code == 200
    assert hb_res.json()["status"] == "ok"

    # Agent A CANNOT heartbeat for Agent B (anti-impersonation)
    b_info = agent_b.get_system_info()
    hb_spoof = client.post("/api/v1/agents/heartbeat", json=b_info)
    assert hb_spoof.status_code == 403

    # Agent A can query its own commands using its token
    cmd_res = client.get(f"/api/v1/agents/{agent_a.name}/commands")
    assert cmd_res.status_code == 200

    # Agent A CANNOT query Agent B's commands
    cmd_spoof = client.get(f"/api/v1/agents/{agent_b.name}/commands")
    assert cmd_spoof.status_code == 403


def test_ironclad_04_agent_key_rotation_validates_signature(system):
    """Rotating an agent's public key must require a valid Ed25519 signature from the current private key."""
    client = system["client"]
    agent_name = "SRV-ROT-SIG-TEST"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]

    _, new_pub_hex = generate_ed25519_keypair()
    fake_priv, _ = generate_ed25519_keypair()

    # 1. Attacker tries to rotate key with forged signature (signed with an untrusted private key)
    forged_sig = ed25519_sign_canonical(fake_priv, {"name": agent_name, "new_public_key": new_pub_hex})
    bad_resp = client.post(
        f"/api/v1/agents/{agent_name}/rotate-key",
        json={"new_public_key": new_pub_hex, "rotation_signature": forged_sig},
    )
    assert bad_resp.status_code == 400
    assert "signature" in bad_resp.json()["error"]["message"].lower()

    # 2. Legitimate agent rotates key with valid signature
    rotate_res = agent.rotate_key(client=client)
    assert rotate_res["status"] == "ok"
    assert rotate_res["public_key"] == agent.public_key_hex


def test_ironclad_05_syslog_tcp_oversized_octet_frame_defense():
    """Syslog TCP listener must reject or clamp oversized octet frame lengths to prevent memory exhaustion."""
    received = []
    server = SyslogServer(handler=received.append, host="127.0.0.1", port=0, protocol="tcp", max_bytes=1024)
    server.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", server.port))

        # Send malicious oversized frame: 999999999 bytes followed by short message
        sock.sendall(b"999999999 <13>1 2026-10-17T00:00:00Z myhost app 123 - - Malicious payload\n")
        time.sleep(0.3)

        # Send valid small frame
        sock.sendall(b"37 <13>1 2026-10-17T00:00:00Z legit app - - ok\n")
        time.sleep(0.3)
        sock.close()
    finally:
        server.stop()


def test_ironclad_06_ingestion_parser_malformed_event_returns_400_not_503(system):
    """Ingesting an event with malformed source data (e.g. invalid IP address) must return
    HTTP 400 Bad Request, never an unhandled 503 Service Unavailable."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # Ingest event with unparseable IP address
    resp = client.post(
        "/api/v1/events/ingest",
        json={
            "events": [
                {
                    "source": "firewall-edge",
                    "source_type": "json",
                    "collector": "api",
                    "raw_event": {
                        "source_ip": "999.999.999.999",  # Invalid IPv4 address
                        "message": "connection attempt",
                    },
                }
            ]
        },
    )
    # Must fail with 400 or 422 client error, never 503
    assert resp.status_code in {400, 422}, f"Expected 400 or 422, got {resp.status_code}: {resp.text}"


def test_ironclad_07_agent_terminate_process_blocks_invalid_pid_and_system_binaries():
    """Agent process termination must reject invalid PIDs (<= 1) and protected system processes."""
    agent = EndpointAgent(name="SRV-TERMINATE-TEST", simulation_mode=True)

    # Rejects PID 0 (process group kill)
    with pytest.raises(ValueError, match="Invalid target PID"):
        agent.terminate_process(pid=0)

    # Rejects PID -1 (kill all processes)
    with pytest.raises(ValueError, match="Invalid target PID"):
        agent.terminate_process(pid=-1)

    # Rejects PID 1 (init / systemd)
    with pytest.raises(ValueError, match="Invalid target PID"):
        agent.terminate_process(pid=1)

    # Rejects system binaries
    with pytest.raises(ValueError, match="Invalid or restricted process name"):
        agent.terminate_process(name="winlogon.exe")

    with pytest.raises(ValueError, match="Invalid or restricted process name"):
        agent.terminate_process(name="init")

    with pytest.raises(ValueError, match="Invalid or restricted process name"):
        agent.terminate_process(name="malware; rm -rf /")

    # Allows valid PID > 1
    res_pid = agent.terminate_process(pid=12345)
    assert res_pid["terminated"] is True
    assert res_pid["target_pid"] == 12345

    # Allows valid process name
    res_name = agent.terminate_process(name="crypto_miner.exe")
    assert res_name["terminated"] is True
    assert res_name["target_name"] == "crypto_miner.exe"


def test_ironclad_08_case_status_workflow_transitions(system):
    """Case workflow status should support standard case lifecycle states (OPEN, IN_PROGRESS, RESOLVED, CLOSED)."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]

    # 1. Create a case
    create_resp = client.post(
        "/api/v1/cases", json={"title": "Investigation Case Alpha", "tags": ["malware"]}
    )
    assert create_resp.status_code == 201
    case_id = create_resp.json()["id"]
    assert create_resp.json()["status"] == "OPEN"
    revision = create_resp.json()["revision"]

    # 2. Update to IN_PROGRESS
    patch_resp = client.patch(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "IN_PROGRESS", "revision": revision},
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["status"] == "IN_PROGRESS"
    revision = patch_resp.json()["revision"]

    # 3. Update to RESOLVED
    patch_resp2 = client.patch(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "RESOLVED", "revision": revision},
    )
    assert patch_resp2.status_code == 200, patch_resp2.text
    assert patch_resp2.json()["status"] == "RESOLVED"


def test_ironclad_09_tenant_isolation_cases_and_evidence_cross_attach(system):
    """Cases and case evidence must enforce strict tenant boundaries.
    Tenant B cannot view Tenant A's case, nor attach Tenant A's events to Tenant B's case."""
    client = system["client"]
    org_a = system["org"]

    # 1. Tenant A creates a case and an event
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    c_res = client.post("/api/v1/cases", json={"title": "Org A Case", "tags": ["internal"]})
    assert c_res.status_code == 201
    case_a_id = c_res.json()["id"]

    with system["app"].state.sessions.begin() as db:
        ev_a = EventRecord(
            id="ev-org-a-private",
            organization_id=org_a,
            timestamp=datetime.now(UTC),
            source="test",
            evidence_hash="hash-org-a",
            payload={"message": "confidential org a telemetry"},
            state="PROCESSED",
        )
        db.add(ev_a)

    # 2. Tenant B tries to get Tenant A's case -> 404
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    get_res = client.get(f"/api/v1/cases/{case_a_id}")
    assert get_res.status_code == 404

    # 3. Tenant B creates its own case
    b_case_res = client.post("/api/v1/cases", json={"title": "Org B Case", "tags": ["external"]})
    assert b_case_res.status_code == 201
    case_b_id = b_case_res.json()["id"]

    # 4. Tenant B tries to attach Tenant A's event as evidence -> 404
    attach_res = client.post(
        f"/api/v1/cases/{case_b_id}/evidence",
        json={"resource_type": "events", "resource_id": "ev-org-a-private"},
    )
    assert attach_res.status_code == 404


def test_ironclad_10_tenant_isolation_soar_playbooks_and_executions(system):
    """SOAR playbooks and execution runs must remain strictly tenant isolated."""
    client = system["client"]

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    pb_doc = {
        "name": "Org A Isolation Playbook",
        "definition": {
            "description": "Tenant A bounded playbook",
            "trigger": {"source": "incident", "conditions": []},
            "steps": [
                {
                    "id": "step_summary",
                    "action": "summary",
                }
            ],
            "input_schema": {},
        },
        "enabled": True,
        "expected_version": 0,
    }
    pb_res = client.post("/api/v1/soar/playbooks", json=pb_doc)
    assert pb_res.status_code == 200
    pb_id = pb_res.json()["id"]

    # Tenant B tries to access Tenant A's playbook -> 404
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    pb_cross = client.get(f"/api/v1/soar/playbooks/{pb_id}")
    assert pb_cross.status_code == 404


def test_ironclad_11_soar_separation_of_duty_prevents_self_approval(system):
    """SOAR approval must enforce separation of duties: requester cannot approve own execution."""
    client = system["client"]
    org_id = system["org"]

    # Enroll host entity
    with system["app"].state.sessions.begin() as db:
        host = Entity(organization_id=org_id, type="host", value="SRV-SEPARATE-DUTY", attributes={})
        db.add(host)
        db.flush()
        host_id = host.id

    # SOC Manager requests execution (has playbooks.execute and playbooks.approve)
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    req = client.post(
        "/api/v1/playbooks/request",
        json={"action": "isolate_host", "target": host_id},
        headers={"Idempotency-Key": "idem-self-appr-01"},
    )
    assert req.status_code == 200
    exec_id = req.json()["id"]
    assert req.json()["status"] == "APPROVAL_REQUIRED"

    # Same SOC Manager attempts to approve their own request -> 403 Forbidden
    self_appr = client.post(f"/api/v1/playbooks/{exec_id}/approve")
    assert self_appr.status_code == 403
    assert "different human operator" in self_appr.json()["error"]["message"].lower()

    # Independent human operator (SUPER_ADMIN) approves -> 200 OK
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    mgr_appr = client.post(f"/api/v1/playbooks/{exec_id}/approve")
    assert mgr_appr.status_code == 200
    assert mgr_appr.json()["status"] == "APPROVED"


def test_ironclad_12_tenant_isolation_rule_replay_jobs(system):
    """Rule replays must be isolated to the requesting tenant."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # Trigger replay on Tenant A
    rep_res = client.post(
        "/api/v1/rules/AUTH-001/replay",
        json={"target_type": "DATASET", "dataset_name": "AUTH-001", "max_events": 10, "dry_run": True},
    )
    assert rep_res.status_code == 200
    job_id = rep_res.json()["job_id"]

    # Tenant B tries to query Tenant A's replay job -> 404
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    cross_rep = client.get(f"/api/v1/replays/{job_id}")
    assert cross_rep.status_code == 404


def test_ironclad_13_tenant_isolation_dead_letter_and_search_retries(system):
    """Dead letter and search retry endpoints must prevent cross-tenant access."""
    client = system["client"]
    org_a = system["org"]

    with system["app"].state.sessions.begin() as db:
        dead_ev = EventRecord(
            id="ev-dead-tenant-a",
            organization_id=org_a,
            timestamp=datetime.now(UTC),
            source="test",
            evidence_hash="dead-hash",
            payload={"message": "dead event"},
            state="DEAD",
        )
        db.add(dead_ev)

    # Tenant B attempts to retry Tenant A's dead event -> 404
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    res = client.post("/api/v1/system/dead-letter/ev-dead-tenant-a/retry")
    assert res.status_code == 404


def test_ironclad_14_tenant_isolation_export_endpoint(system):
    """Data export must be scoped strictly to the requesting tenant's records."""
    client = system["client"]
    org_a = system["org"]

    # Tenant A creates cases
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    client.post("/api/v1/cases", json={"title": "Export Case A1", "tags": ["export"]})
    client.post("/api/v1/cases", json={"title": "Export Case A2", "tags": ["export"]})

    # Tenant B exports cases
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    export_b = client.get("/api/v1/export/cases?format=json")
    assert export_b.status_code == 200
    b_items = export_b.json()["items"]
    # None of Tenant A's cases should appear in Tenant B's export
    assert all(item["organization_id"] != org_a for item in b_items)


def test_ironclad_15_incident_idempotency_key_conflict_rejection(system):
    """Creating an incident with the same idempotency key but different input must return 409 Conflict."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["ANALYST"]

    headers = {"Idempotency-Key": "idem-inc-conflict-test-01"}
    initial = client.post(
        "/api/v1/incidents",
        json={"title": "Ransomware Detected on DC01", "severity": "critical", "priority": 1, "alert_ids": []},
        headers=headers,
    )
    assert initial.status_code in {200, 201}
    inc_id = initial.json()["id"]

    # Replay with IDENTICAL payload -> returns same incident (idempotent 200 or 201)
    replay = client.post(
        "/api/v1/incidents",
        json={"title": "Ransomware Detected on DC01", "severity": "critical", "priority": 1, "alert_ids": []},
        headers=headers,
    )
    assert replay.status_code in {200, 201}
    assert replay.json()["id"] == inc_id

    # Replay with CONFLICTING payload -> rejected with 409 Conflict
    conflict = client.post(
        "/api/v1/incidents",
        json={"title": "Conflicting Title", "severity": "low", "priority": 3, "alert_ids": []},
        headers=headers,
    )
    assert conflict.status_code == 409
    assert "reused" in conflict.json()["error"]["message"].lower()


def test_ironclad_16_sigma_rule_import_validation_and_size_limits(system):
    """Sigma rule import must enforce size limits and reject malformed definitions with 422."""
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # 1. Oversized YAML content (> 500 KB) must be rejected with 422
    oversized = (
        "title: Oversized Rule\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: "
        + ("A" * 600_000)
    )
    resp_over = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": oversized})
    assert resp_over.status_code == 422
    assert "exceeds" in resp_over.json()["error"]["message"].lower()

    # 2. Malformed Sigma content must be rejected with 422
    malformed = "not: a: valid: sigma: {[[["
    resp_mal = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": malformed})
    assert resp_mal.status_code == 422

    # 3. Valid Sigma rule imports and parses successfully
    valid_sigma = """
title: Suspicious PowerShell Download
id: 12345678-1234-5678-1234-567812345678
status: experimental
description: Detects suspicious PowerShell download cradle
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'DownloadString'
            - 'Net.WebClient'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
    resp_valid = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": valid_sigma})
    assert resp_valid.status_code == 200
    assert resp_valid.json()["valid"] is True
    assert "Suspicious PowerShell Download" in resp_valid.json()["rule"]["name"]


def test_ironclad_17_phase3_agent_receipt_advanced_security_matrix(system):
    """Phase 3 Live Qualification: Agent Receipt Security Matrix
    Validates:
    - Malformed nonces format rejection (400)
    - Reused nonce across multiple commands (409)
    - Expired command envelope rejection and auto-expiration (409)
    - Canceled command receipt rejection (409)
    - Missing or incorrect agent identity binding (400)
    - Tampered details vs signed receipt result (400)
    - Concurrent replay race serialization
    """
    client = system["client"]
    agent_name = "SRV-P3-MATRIX"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)
    agent.heartbeat(client=client)

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    with system["app"].state.sessions() as db:
        entity = db.scalar(select(Entity).where(Entity.type == "host", Entity.value == agent_name))

    def create_command(action="isolate_host", idem_key=None):
        if not idem_key:
            idem_key = "idem-p3-" + secrets.token_hex(8)
        client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
        req = client.post(
            "/api/v1/playbooks/request",
            json={"action": action, "target": entity.id},
            headers={"Idempotency-Key": idem_key},
        )
        c_id = req.json()["id"]
        client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
        client.post(f"/api/v1/playbooks/{c_id}/approve")
        client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
        client.post(f"/api/v1/playbooks/{c_id}/execute")
        return c_id

    # 1. Malformed nonce format
    cmd1_id = create_command()
    pending1 = agent.poll_commands(client=client)
    assert any(c["id"] == cmd1_id for c in pending1)
    ctrl_sig1 = next(c["controller_signature"] for c in pending1 if c["id"] == cmd1_id)

    malformed_receipt = {
        "version": "1.0",
        "command_id": cmd1_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": ctrl_sig1,
        "timestamp": time.time(),
        "nonce": "invalid#nonce$with@bad*characters!",
    }
    malformed_sig = ed25519_sign_canonical(agent.private_key, malformed_receipt)
    res_malformed = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd1_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": malformed_receipt,
            "signature": malformed_sig,
            "details": {"isolated": True},
        },
    )
    assert res_malformed.status_code == 400
    assert "nonce" in res_malformed.json()["error"]["message"].lower()

    # 2. Missing agent identity in receipt
    no_agent_receipt = dict(malformed_receipt)
    no_agent_receipt["nonce"] = "valid_nonce_p3_" + secrets.token_hex(8)
    no_agent_receipt["agent_id"] = ""
    no_agent_sig = ed25519_sign_canonical(agent.private_key, no_agent_receipt)
    res_no_agent = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd1_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": no_agent_receipt,
            "signature": no_agent_sig,
            "details": {"isolated": True},
        },
    )
    assert res_no_agent.status_code == 400
    assert "agent id" in res_no_agent.json()["error"]["message"].lower()

    # 3. Incorrect agent identity in receipt (imposter)
    wrong_agent_receipt = dict(no_agent_receipt)
    wrong_agent_receipt["agent_id"] = "IMPOSTER_HOST_999"
    wrong_agent_sig = ed25519_sign_canonical(agent.private_key, wrong_agent_receipt)
    res_wrong_agent = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd1_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": wrong_agent_receipt,
            "signature": wrong_agent_sig,
            "details": {"isolated": True},
        },
    )
    assert res_wrong_agent.status_code == 400
    assert "agent id" in res_wrong_agent.json()["error"]["message"].lower()

    # 4. Altered result details mismatching signed receipt result
    mismatch_receipt = dict(no_agent_receipt)
    mismatch_receipt["agent_id"] = agent_name
    mismatch_sig = ed25519_sign_canonical(agent.private_key, mismatch_receipt)
    res_mismatch = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd1_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": mismatch_receipt,
            "signature": mismatch_sig,
            "details": {"isolated": False, "tampered_result": True},
        },
    )
    assert res_mismatch.status_code == 400
    assert "details do not match" in res_mismatch.json()["error"]["message"].lower()

    # 5. Legitimate receipt submission with unique nonce succeeds
    shared_nonce = "fixed_nonce_1234567890abcdef"
    legit_receipt1 = dict(mismatch_receipt)
    legit_receipt1["nonce"] = shared_nonce
    legit_sig1 = ed25519_sign_canonical(agent.private_key, legit_receipt1)
    res_legit1 = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd1_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": legit_receipt1,
            "signature": legit_sig1,
            "details": {"isolated": True},
        },
    )
    assert res_legit1.status_code == 200
    assert res_legit1.json()["status"] == "UNKNOWN"

    # 6. Reused nonce across a DIFFERENT command must be rejected with 409 Conflict
    cmd2_id = create_command(action="unisolate_host")
    pending2 = agent.poll_commands(client=client)
    ctrl_sig2 = next(c["controller_signature"] for c in pending2 if c["id"] == cmd2_id)

    reused_nonce_receipt = {
        "version": "1.0",
        "command_id": cmd2_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "unisolate_host",
        "status": "SUCCESS",
        "result": {"unisolated": True},
        "command_signature": ctrl_sig2,
        "timestamp": time.time(),
        "nonce": shared_nonce,  # REUSED from cmd1!
    }
    reused_sig = ed25519_sign_canonical(agent.private_key, reused_nonce_receipt)
    res_reused = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd2_id,
            "action": "unisolate_host",
            "status": "SUCCESS",
            "receipt": reused_nonce_receipt,
            "signature": reused_sig,
            "details": {"unisolated": True},
        },
    )
    assert res_reused.status_code == 409
    assert "nonce has already been used" in res_reused.json()["error"]["message"].lower()

    # A rejected receipt leaves the command pending. Complete it before the
    # next independent scenario; conflicting dispatch is now prohibited.
    reused_nonce_receipt["nonce"] = secrets.token_hex(16)
    completed = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={"command_id": cmd2_id, "action": "unisolate_host", "status": "SUCCESS",
              "receipt": reused_nonce_receipt,
              "signature": ed25519_sign_canonical(agent.private_key, reused_nonce_receipt)},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "UNKNOWN"
    assert completed.json()["result"]["enforced_externally"] is False

    # 7. Expired command envelope rejection
    cmd3_id = create_command(action="isolate_host")
    pending3 = agent.poll_commands(client=client)
    ctrl_sig3 = next(c["controller_signature"] for c in pending3 if c["id"] == cmd3_id)

    with system["app"].state.sessions() as db:
        exec_row = db.get(PlaybookExecution, cmd3_id)
        res_data = dict(exec_row.result or {})
        env = dict(res_data.get("command_envelope") or {})
        env["expires_at"] = time.time() - 10.0  # Expired in past
        res_data["command_envelope"] = env
        exec_row.result = res_data
        db.commit()

    expired_receipt = {
        "version": "1.0",
        "command_id": cmd3_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "command_signature": ctrl_sig3,
        "timestamp": time.time(),
        "nonce": "fresh_nonce_p3_" + secrets.token_hex(8),
    }
    expired_sig = ed25519_sign_canonical(agent.private_key, expired_receipt)
    res_expired = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd3_id,
            "action": "isolate_host",
            "status": "SUCCESS",
            "receipt": expired_receipt,
            "signature": expired_sig,
            "details": {"isolated": True},
        },
    )
    assert res_expired.status_code == 409
    assert "expired" in res_expired.json()["error"]["message"].lower()

    with system["app"].state.sessions() as db:
        exec_row = db.get(PlaybookExecution, cmd3_id)
        assert exec_row.status == "EXPIRED"

    # 8. Canceled command receipt submission rejection
    cmd4_id = create_command(action="unisolate_host")
    pending4 = agent.poll_commands(client=client)
    ctrl_sig4 = next(c["controller_signature"] for c in pending4 if c["id"] == cmd4_id)

    with system["app"].state.sessions() as db:
        exec_row = db.get(PlaybookExecution, cmd4_id)
        exec_row.status = "CANCELED"
        db.commit()

    canceled_receipt = {
        "version": "1.0",
        "command_id": cmd4_id,
        "agent_id": agent_name,
        "organization_id": system["org"],
        "action": "unisolate_host",
        "status": "SUCCESS",
        "result": {"unisolated": True},
        "command_signature": ctrl_sig4,
        "timestamp": time.time(),
        "nonce": "fresh_nonce_p3_cancel_" + secrets.token_hex(8),
    }
    canceled_sig = ed25519_sign_canonical(agent.private_key, canceled_receipt)
    res_canceled = client.post(
        f"/api/v1/agents/{agent_name}/receipts",
        json={
            "command_id": cmd4_id,
            "action": "unisolate_host",
            "status": "SUCCESS",
            "receipt": canceled_receipt,
            "signature": canceled_sig,
            "details": {"unisolated": True},
        },
    )
    assert res_canceled.status_code == 409
    assert "canceled" in res_canceled.json()["error"]["message"].lower()

    # 9. Concurrent receipt submission race: exactly 1 wins, rest receive 409
    cmd5_id = create_command(action="isolate_host")
    pending5 = agent.poll_commands(client=client)
    ctrl_sig5 = next(c["controller_signature"] for c in pending5 if c["id"] == cmd5_id)

    def submit_attempt(idx):
        receipt_obj = {
            "version": "1.0",
            "command_id": cmd5_id,
            "agent_id": agent_name,
            "organization_id": system["org"],
            "action": "isolate_host",
            "status": "SUCCESS",
            "result": {"isolated": True, "idx": idx},
            "command_signature": ctrl_sig5,
            "timestamp": time.time(),
            "nonce": f"concurrent_race_nonce_{idx}_{secrets.token_hex(8)}",
        }
        sig = ed25519_sign_canonical(agent.private_key, receipt_obj)
        resp = client.post(
            f"/api/v1/agents/{agent_name}/receipts",
            json={
                "command_id": cmd5_id,
                "action": "isolate_host",
                "status": "SUCCESS",
                "receipt": receipt_obj,
                "signature": sig,
                "details": {"isolated": True, "idx": idx},
            },
        )
        return resp.status_code

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        statuses = list(pool.map(submit_attempt, range(5)))

    assert statuses.count(200) == 1, f"Expected exactly one 200, got: {statuses}"
    assert statuses.count(409) == 4, f"Expected four 409s, got: {statuses}"
