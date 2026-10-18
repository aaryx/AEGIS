"""TITAN phase 2. Firewall execution is mocked; no host rules are touched."""

import copy
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from aegis.agent import EndpointAgent
from aegis.cli import app as cli
from aegis.crypto import ed25519_sign_canonical, generate_ed25519_keypair
from aegis.db import AuditLog, Entity, PlaybookExecution, as_dict
from aegis.endpoint_firewall import ContainmentError, LinuxContainment
from tests.test_agent_nonce_replay_invariant import helper_create_command


@pytest.fixture
def firewall(monkeypatch):
    policy = LinuxContainment("persistent-agent-key", "192.0.2.8", 443)
    state = {"objects": None, "writes": [], "admin": {"table": "administrator-managed"}}
    monkeypatch.setattr(policy, "locked", nullcontext)

    def run(args, document=None):
        if document is not None:
            state["writes"].append(copy.deepcopy(document))
            commands = document["nftables"]
            if "delete" in commands[0]:
                assert commands == [{"delete": {"table": {"family": "inet", "name": policy.table}}}]
                state["objects"] = None
            else:
                assert "create" in commands[0]
                state["objects"] = [next(iter(c.values())) for c in commands]
            return {}
        if args == ["-j", "list", "tables"]:
            tables = [{"table": {"family": "inet", "name": "admin"}}]
            if state["objects"] is not None:
                tables.append(state["objects"][0])
            return {"nftables": tables}
        assert args == ["-j", "list", "table", "inet", policy.table]
        return {"nftables": copy.deepcopy(state["objects"])}

    monkeypatch.setattr(policy, "run", run)
    return policy, state


def test_owned_policy_is_idempotent_and_release_preserves_admin_rules(firewall):
    policy, state = firewall
    before = copy.deepcopy(state["admin"])
    first = policy.apply(True)
    assert first["outcome"] == "ENFORCED"
    assert policy.apply(True) == {**first, "evidence": {**first["evidence"], "commands": []}}
    assert len(state["writes"]) == 1
    assert policy.apply(False)["outcome"] == "RELEASED"
    assert policy.apply(False)["outcome"] == "RELEASED"
    assert len(state["writes"]) == 2
    assert state["admin"] == before
    assert "flush" not in json.dumps(state["writes"])
    hooks = [o["chain"] for o in policy.objects if "chain" in o]
    assert {c["hook"] for c in hooks} == {"input", "output", "forward"}
    assert all(c["policy"] == "drop" for c in hooks)


@pytest.mark.parametrize("isolate", [True, False])
def test_modified_owned_table_is_never_changed(firewall, isolate):
    policy, state = firewall
    state["objects"] = copy.deepcopy(policy.objects)
    state["objects"][0]["table"]["comment"] = "administrator"
    with pytest.raises(ContainmentError) as caught:
        policy.apply(isolate)
    assert caught.value.evidence["verified"] is False
    assert state["writes"] == []


@pytest.mark.parametrize("address", ["192.0.2.8; flush ruleset", "--help", "0.0.0.0",  # noqa: S104 - negative input, no socket binding
 "224.0.0.1", "::1"])
def test_injected_or_unsupported_controller_rejected(address):
    with pytest.raises(ValueError):
        LinuxContainment("safe", address, 443)


def test_missing_capability_fails_without_mutation(firewall, monkeypatch):
    policy, state = firewall
    def denied(*args, **kwargs):
        raise PermissionError("synthetic capability missing")
    monkeypatch.setattr(policy, "run", denied)
    with pytest.raises(ContainmentError) as caught:
        policy.apply(True)
    assert caught.value.evidence["error_type"] == "PermissionError"
    assert state["writes"] == []


def test_nft_transport_has_timeout_and_no_shell(monkeypatch):
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout='{"nftables": []}')
    monkeypatch.setattr("aegis.endpoint_firewall.subprocess.run", fake_run)
    LinuxContainment("safe", "192.0.2.8", 443).run(["-j", "list", "tables"])
    args, kwargs = calls[0]
    assert args == ["/usr/sbin/nft", "-j", "list", "tables"]
    assert kwargs["timeout"] == 10 and kwargs["check"] is True
    assert not kwargs.get("shell")


def prepared(system):
    agent = EndpointAgent(name="TITAN-PHASE2", simulation_mode=True)
    agent.heartbeat(client=system["client"])
    identifier = helper_create_command(system, agent.name)
    command = next(c for c in agent.poll_commands(client=system["client"]) if c["id"] == identifier)
    return agent, command


def test_simulation_is_truthful_in_receipt_heartbeat_audit_and_api(system):
    agent, command = prepared(system)
    result = agent.execute_command(command, client=system["client"])
    assert result["status"] == result["containment_status"] == "SIMULATED"
    assert result["result"]["enforced_externally"] is False
    assert result["result"]["receipt_authenticated"] is True
    assert agent.heartbeat(client=system["client"])["isolation_status"] == "SIMULATED"
    agents = system["client"].get("/api/v1/agents").json()
    assert next(a for a in agents if a["name"] == agent.name)["isolation_status"] == "SIMULATED"
    with system["app"].state.sessions() as db:
        entry = db.scalar(select(AuditLog).where(AuditLog.resource_id == command["id"], AuditLog.action == "agent.receipt"))
        assert entry.details["containment_status"] == "SIMULATED"
        assert entry.details["enforced_externally"] is False


@pytest.mark.parametrize("failure", [PermissionError, FileNotFoundError, TimeoutError])
def test_failed_or_timed_out_action_never_becomes_enforced(system, monkeypatch, failure):
    agent, command = prepared(system)
    def fail(**kwargs):
        raise failure("synthetic-secret-not-for-audit")
    monkeypatch.setattr(agent, "isolate_host", fail)
    result = agent.execute_command(command, client=system["client"])
    assert result["status"] == "FAILED"
    assert result["result"]["enforced_externally"] is False
    assert "synthetic-secret" not in json.dumps(result)
    with system["app"].state.sessions() as db:
        host = db.scalar(select(Entity).where(Entity.value == agent.name))
        assert host.attributes["isolation_status"] == "UNKNOWN"


@pytest.mark.parametrize("details, expected", [({}, "UNKNOWN"), ({"mode": "live", "isolated": True}, "UNKNOWN"),
                                               ({"mode": "simulated_fallback"}, "UNKNOWN")])
def test_authentic_but_unsubstantiated_receipt_is_unknown(system, details, expected):
    agent, command = prepared(system)
    receipt = {"command_id": command["id"], "agent_id": agent.agent_id, "organization_id": system["org"],
               "action": "isolate_host", "status": "SUCCESS", "result": details,
               "timestamp": time.time(), "nonce": secrets.token_hex(16),
               "command_signature": command["controller_signature"]}
    result = agent.submit_receipt(command["id"], "isolate_host", "SUCCESS", receipt,
                                 ed25519_sign_canonical(agent.private_key, receipt), "", details,
                                 client=system["client"])
    assert result["status"] == expected
    assert result["result"]["enforced_externally"] is False


def test_heartbeat_cannot_forge_enforcement_or_replace_key(system):
    agent, _ = prepared(system)
    client = system["client"]
    payload = agent.get_system_info() | {"isolation_status": "ENFORCED"}
    response = client.post("/api/v1/agents/heartbeat", json=payload)
    assert response.status_code == 200
    assert response.json()["isolation_status"] == "UNKNOWN"
    _, foreign_key = generate_ed25519_keypair()
    response = client.post("/api/v1/agents/heartbeat", json=payload | {"public_key": foreign_key})
    assert response.status_code == 409


def test_missing_receipt_preserves_dispatched_state(system):
    agent, command = prepared(system)
    response = system["client"].post(f"/api/v1/agents/{agent.name}/receipts", json={
        "command_id": command["id"], "action": "isolate_host", "status": "SUCCESS"})
    assert response.status_code == 400
    with system["app"].state.sessions() as db:
        assert db.get(PlaybookExecution, command["id"]).status == "DISPATCHED"


def test_execution_reverifies_signed_parameters(system, monkeypatch):
    agent, command = prepared(system)
    command["params"] = {"controller_ip": "203.0.113.8"}
    monkeypatch.setattr(agent, "isolate_host", lambda **kw: pytest.fail("must not execute"))
    with pytest.raises(ValueError, match="Invalid"):
        agent.execute_command(command)


def test_concurrent_execution_calls_apply_once_and_reuse_receipt(system, monkeypatch):
    agent, command = prepared(system)
    calls = []
    monkeypatch.setattr(agent, "isolate_host", lambda **kw: calls.append(True) or {"mode": "simulated"})
    monkeypatch.setattr(agent, "submit_receipt", lambda *args, **kw: args[3])
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: agent.execute_command(command), range(4)))
    assert len(calls) == 1
    assert all(result == results[0] for result in results)


def test_receipt_transport_failure_does_not_rerun_action(system, monkeypatch):
    agent, command = prepared(system)
    calls = []
    monkeypatch.setattr(agent, "isolate_host", lambda **kw: calls.append(True) or {"mode": "simulated"})
    def unavailable(*args, **kwargs):
        raise ConnectionError("offline")
    monkeypatch.setattr(agent, "submit_receipt", unavailable)
    for _ in range(2):
        with pytest.raises(ConnectionError):
            agent.execute_command(command)
    assert len(calls) == 1


def test_historical_verified_record_remains_unchanged_and_unqualified(system):
    _, command = prepared(system)
    with system["app"].state.sessions.begin() as db:
        execution = db.get(PlaybookExecution, command["id"])
        execution.status = "VERIFIED"
        execution.result = {"enforced_externally": True}
        view = as_dict(execution)
        assert view["status"] == "VERIFIED"
        assert view["containment_status"] == "UNKNOWN"
        assert execution.result == {"enforced_externally": True}


def test_cli_local_status_is_unknown_without_receipt():
    result = CliRunner().invoke(cli, ["agent", "status"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["isolation_status"] == "UNKNOWN"


def test_live_actions_require_explicit_policy_and_never_fallback():
    agent = EndpointAgent(simulation_mode=False)
    with pytest.raises(RuntimeError, match="disabled or unsupported"):
        agent.isolate_host()
    with pytest.raises(RuntimeError, match="disabled or unsupported"):
        agent.unisolate_host()
    assert agent.isolated is False


@pytest.mark.parametrize("isolate", [True, False])
def test_signed_mock_kernel_readback_records_explicit_outcome(system, firewall, isolate):
    policy, _ = firewall
    agent = EndpointAgent(name="TITAN-READBACK", simulation_mode=True)
    agent.heartbeat(client=system["client"])
    action = "isolate_host" if isolate else "unisolate_host"
    identifier = helper_create_command(system, agent.name, action)
    command = next(c for c in agent.poll_commands(client=system["client"]) if c["id"] == identifier)
    details = policy.apply(isolate)  # mock, NOT a live firewall proof
    receipt = {"command_id": identifier, "agent_id": agent.agent_id, "organization_id": system["org"],
               "action": action, "status": "SUCCESS", "result": details,
               "timestamp": time.time(), "nonce": secrets.token_hex(16),
               "command_signature": command["controller_signature"]}
    result = agent.submit_receipt(identifier, action, "SUCCESS", receipt,
                                 ed25519_sign_canonical(agent.private_key, receipt), "", details,
                                 client=system["client"])
    assert result["status"] == ("ENFORCED" if isolate else "RELEASED")
    assert result["result"]["scope"] == "agent-reported"
    assert result["result"]["enforced_externally"] is isolate
    assert result["result"]["details"]["evidence"]["commands"] == details["evidence"]["commands"]


def test_concurrent_duplicate_requests_are_idempotent(system):
    agent = EndpointAgent(name="TITAN-IDEMPOTENT")
    host = agent.heartbeat(client=system["client"])["entity_id"]
    client = system["client"]
    def request(_):
        return client.post("/api/v1/playbooks/request", headers={"Idempotency-Key": "phase2-repeat-request"},
                           json={"action": "isolate_host", "target": host})
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(request, range(4)))
    assert [r.status_code for r in results] == [200] * 4
    assert len({r.json()["id"] for r in results}) == 1
    conflicting = client.post("/api/v1/playbooks/request", headers={"Idempotency-Key": "phase2-repeat-request"},
                              json={"action": "isolate_host", "target": host, "params": {"controller_ip": "192.0.2.4"}})
    assert conflicting.status_code == 409


def test_concurrent_conflicting_dispatch_only_one_wins(system):
    client = system["client"]
    agent = EndpointAgent(name="TITAN-CONFLICT")
    target = agent.heartbeat(client=client)["entity_id"]
    ids = []
    for action in ("isolate_host", "unisolate_host"):
        result = client.post("/api/v1/playbooks/request", headers={"Idempotency-Key": "phase2-" + action},
                             json={"action": action, "target": target})
        assert result.status_code == 200
        identifier = result.json()["id"]
        approval = client.post(f"/api/v1/playbooks/{identifier}/approve",
                               headers={"Authorization": "Bearer " + system["tokens"]["SOC_MANAGER"]})
        assert approval.status_code == 200
        ids.append(identifier)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda identifier: client.post(f"/api/v1/playbooks/{identifier}/execute"), ids))
    assert sorted(r.status_code for r in results) == [200, 409]
    winner = next(r.json() for r in results if r.status_code == 200)
    repeat = client.post(f"/api/v1/playbooks/{winner['id']}/execute")
    assert repeat.status_code == 200
    assert repeat.json()["revision"] == winner["revision"]


def test_controller_key_cannot_be_replaced_by_command_payload(system):
    agent, command = prepared(system)
    agent.controller_public_key = command["controller_public_key"]
    private, public = generate_ed25519_keypair()
    command["controller_public_key"] = public
    command["controller_signature"] = ed25519_sign_canonical(private, command["envelope"])
    assert agent.verify_command(command, consume=False) is False


def test_command_cannot_override_operator_firewall_exception():
    agent = EndpointAgent(controller_ip="192.0.2.8")
    with pytest.raises(ValueError, match="override"):
        agent.isolate_host("192.0.2.8; flush ruleset")


def test_policy_readback_failure_never_claims_success(firewall, monkeypatch):
    policy, _ = firewall
    monkeypatch.setattr(policy, "snapshot", lambda: None)
    with pytest.raises(ContainmentError) as caught:
        policy.apply(True)
    assert caught.value.evidence["verified"] is False
    assert caught.value.evidence["attempted_commands"]


def test_wrong_endpoint_with_enrolled_agent_token_cannot_acknowledge(system):
    client = system["client"]
    intended, wrong = EndpointAgent(name="T2-OWNER"), EndpointAgent(name="T2-OTHER")
    for agent in (intended, wrong):
        token = client.post("/api/v1/agents/enrollment-tokens", json={"valid_minutes": 10}).json()["token"]
        agent.enroll(token, client=client)
        agent.heartbeat(client=client)
    identifier = helper_create_command(system, intended.name)
    command = intended.poll_commands(client=client)[0]
    receipt = {"command_id": identifier, "agent_id": wrong.agent_id, "organization_id": system["org"],
               "action": "isolate_host", "status": "SUCCESS", "result": {"mode": "live"},
               "timestamp": time.time(), "nonce": secrets.token_hex(16),
               "command_signature": command["controller_signature"]}
    response = client.post(f"/api/v1/agents/{wrong.name}/receipts",
                           headers={"Authorization": "Bearer " + wrong.token},
                           json={"command_id": identifier, "action": "isolate_host", "status": "SUCCESS",
                                 "receipt": receipt, "signature": ed25519_sign_canonical(wrong.private_key, receipt)})
    assert response.status_code == 403
    with system["app"].state.sessions() as db:
        assert db.get(PlaybookExecution, identifier).status == "DISPATCHED"


def test_cli_preserves_legacy_record_with_explicit_unknown_interpretation(system, monkeypatch):
    _, command = prepared(system)
    with system["app"].state.sessions.begin() as db:
        execution = db.get(PlaybookExecution, command["id"])
        execution.status, execution.result = "VERIFIED", {"enforced_externally": True}
        view = as_dict(execution)
    monkeypatch.setattr("aegis.cli.call", lambda *a, **kw: {"items": [view]})
    response = CliRunner().invoke(cli, ["playbooks", "list"])
    assert response.exit_code == 0
    row = json.loads(response.stdout)["items"][0]
    assert row["containment_status"] == "UNKNOWN"
    assert row["status"] == "VERIFIED"
    assert "not proof" in row["containment_evidence_scope"]


def test_pending_approval_cannot_starve_dispatched_command(system):
    agent, first = prepared(system)
    client = system["client"]
    second = client.post("/api/v1/playbooks/request", headers={"Idempotency-Key": "phase2-pending-command"},
                         json={"action": "unisolate_host", "target": first["target"]})
    assert second.status_code == 200
    identifier = second.json()["id"]
    assert client.post(f"/api/v1/playbooks/{identifier}/approve",
                       headers={"Authorization": "Bearer " + system["tokens"]["SOC_MANAGER"]}).status_code == 200
    # Raw API polling is retriable; the agent's in-memory nonce cache is separate.
    response = client.get(f"/api/v1/agents/{agent.name}/commands")
    assert response.status_code == 200
    assert [command["id"] for command in response.json()] == [first["id"]]
