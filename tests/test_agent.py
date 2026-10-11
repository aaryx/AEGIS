from sqlalchemy import select

from aegis.agent import EndpointAgent
from aegis.db import Collector, Entity, PlaybookExecution


def test_agent_local_methods():
    agent = EndpointAgent(name="TEST-ENDPOINT-01", simulation_mode=True)
    info = agent.get_system_info()
    assert info["name"] == "TEST-ENDPOINT-01"
    assert info["status"] == "ONLINE"
    assert info["isolation_status"] == "NONE"
    assert "isolate_host" in info["capabilities"]
    assert "unisolate_host" in info["capabilities"]

    # Test isolation
    iso_result = agent.isolate_host(controller_ip="10.0.0.1")
    assert iso_result["isolated"] is True
    assert iso_result["mode"] == "simulated"
    assert agent.isolated is True
    assert agent.get_system_info()["isolation_status"] == "ISOLATED"

    # Test un-isolation
    uniso_result = agent.unisolate_host()
    assert uniso_result["isolated"] is False
    assert agent.isolated is False
    assert agent.get_system_info()["isolation_status"] == "NONE"

    # Test process termination
    term_result = agent.terminate_process(pid=1337)
    assert term_result["terminated"] is True
    assert term_result["target_pid"] == 1337

    term_name = agent.terminate_process(name="malware.exe")
    assert term_name["terminated"] is True
    assert term_name["target_name"] == "malware.exe"


def test_agent_api_registration_and_containment_lifecycle(system):
    client = system["client"]
    agent_name = "SRV-PROD-WEB01"
    agent = EndpointAgent(name=agent_name, simulation_mode=True)

    # 1. Heartbeat
    hb_resp = agent.heartbeat(client=client)
    assert hb_resp["status"] == "ok"
    assert hb_resp["name"] == agent_name
    assert hb_resp["isolation_status"] == "NONE"

    # Verify Collector and Entity in DB
    with system["app"].state.sessions() as db:
        collector = db.scalar(select(Collector).where(Collector.name == agent_name))
        assert collector is not None
        assert collector.type == "endpoint-agent"
        entity = db.scalar(select(Entity).where(Entity.type == "host", Entity.value == agent_name))
        assert entity is not None
        assert entity.attributes["isolation_status"] == "NONE"
        assert entity.attributes["agent_id"] == collector.id

    # 2. List agents via API
    agents_list = client.get("/api/v1/agents").json()
    assert any(a["name"] == agent_name for a in agents_list)

    # 3. Request isolate_host playbook execution
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    req_resp = client.post(
        "/api/v1/playbooks/request",
        json={"action": "isolate_host", "target": entity.id},
        headers={"Idempotency-Key": "isolate-web01-key"},
    )
    assert req_resp.status_code == 200, req_resp.text
    execution_id = req_resp.json()["id"]
    assert req_resp.json()["status"] == "APPROVAL_REQUIRED"

    # 4. Independent approval by SOC_MANAGER
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    appr_resp = client.post(f"/api/v1/playbooks/{execution_id}/approve")
    assert appr_resp.status_code == 200, appr_resp.text
    assert appr_resp.json()["status"] == "APPROVED"

    # 5. Dispatch command to agent
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    exec_resp = client.post(f"/api/v1/playbooks/{execution_id}/execute")
    assert exec_resp.status_code == 200, exec_resp.text
    assert exec_resp.json()["status"] == "DISPATCHED"
    assert exec_resp.json()["result"]["pending_receipt"] is True

    # 6. Agent polls commands
    pending = agent.poll_commands(client=client)
    assert len(pending) == 1
    assert pending[0]["id"] == execution_id
    assert pending[0]["action"] == "isolate_host"

    # 7. Agent executes command and posts cryptographic receipt
    receipt_result = agent.execute_command(pending[0], client=client)
    assert receipt_result["status"] == "VERIFIED"
    assert receipt_result["result"]["enforced_externally"] is True
    assert "receipt_hash" in receipt_result["result"]
    assert len(receipt_result["result"]["receipt_hash"]) == 64
    assert agent.isolated is True

    # Verify Entity isolation status is updated
    with system["app"].state.sessions() as db:
        updated_entity = db.get(Entity, entity.id)
        assert updated_entity.attributes["isolation_status"] == "ISOLATED"

    # 8. Un-isolation through full run_cycle
    uniso_req = client.post(
        "/api/v1/playbooks/request",
        json={"action": "unisolate_host", "target": entity.id},
        headers={"Idempotency-Key": "unisolate-web01-key"},
    )
    assert uniso_req.status_code == 200
    uniso_id = uniso_req.json()["id"]

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    client.post(f"/api/v1/playbooks/{uniso_id}/approve")

    # Run cycle directly executes and submits receipt
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    cycle_summary = agent.run_cycle(client=client)
    assert cycle_summary["pending_commands"] == 1
    assert len(cycle_summary["executed"]) == 1
    assert cycle_summary["executed"][0]["status"] == "VERIFIED"
    assert agent.isolated is False

    with system["app"].state.sessions() as db:
        cleared_entity = db.get(Entity, entity.id)
        assert cleared_entity.attributes["isolation_status"] == "NONE"
        cleared_exec = db.get(PlaybookExecution, uniso_id)
        assert cleared_exec.status == "VERIFIED"
        assert cleared_exec.result["enforced_externally"] is True
