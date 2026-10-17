import copy
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from aegis.db import CaseNote, Entity, Incident, WorkflowRun
from aegis.soar import ADAPTERS, Definition, enqueue, process_workflows

DOC = {
    "description": "Review an incident safely",
    "trigger": {"source": "incident"},
    "steps": [
        {"id": "enrich", "action": "enrich"},
        {"id": "note", "action": "incident_note"},
        {"id": "summary", "action": "summary"},
    ],
}


def setup(system, doc=None):
    with system["app"].state.sessions.begin() as db:
        source = Incident(organization_id=system["org"], title="Test", severity="high")
        target = Entity(organization_id=system["org"], type="ip", value="192.0.2.1")
        db.add_all([source, target])
        db.flush()
        source_id, target_id = source.id, target.id
    response = system["client"].post(
        "/api/v1/soar/playbooks", json={"name": "Review", "definition": doc or DOC, "enabled": True}
    )
    assert response.status_code == 200, response.text
    return response.json(), source_id, target_id


def submit(system, book, source, **kwargs):
    return system["client"].post(
        f"/api/v1/soar/playbooks/{book['id']}/execute",
        json={"source_type": "incident", "source_id": source, "idempotency_key": "request-0001", **kwargs},
    )


def tick(system, n=1):
    for _ in range(n):
        process_workflows(system["settings"], system["app"].state.sessions)


def get(system, identifier):
    return system["client"].get(f"/api/v1/soar/executions/{identifier}").json()


def test_version_validation(system):
    book, _, _ = setup(system)
    client = system["client"]
    assert client.post("/api/v1/soar/validate", json=DOC).json()["valid"]
    updated = client.post(
        "/api/v1/soar/playbooks", json={"name": "Review", "definition": DOC, "expected_version": 1}
    )
    assert updated.json()["version"] == 2
    assert not updated.json()["enabled"]
    assert len(client.get(f"/api/v1/soar/playbooks/{book['id']}").json()["versions"]) == 2
    assert (
        client.post("/api/v1/soar/playbooks", json={"name": "Review", "definition": DOC}).status_code == 409
    )


@pytest.mark.parametrize(
    "change",
    [
        {"steps": [{"id": "x", "action": "shell"}]},
        {"steps": [{"id": "x", "action": "summary", "on_false": "x"}]},
        {"steps": [{"id": "x", "action": "summary", "retries": 99}]},
        {"steps": [{"id": "x", "action": "summary", "command": "echo hi"}]},
        {"steps": [{"id": "x", "action": "simulate_block_ip"}]},
        {"trigger": {"source": "workflow"}},
    ],
)
def test_malformed(change):
    with pytest.raises(ValueError):
        Definition.model_validate(DOC | change)


def test_execution_branch_restart_and_notes(system):
    doc = copy.deepcopy(DOC)
    doc["steps"][0] |= {"when": {"field": "severity", "value": "critical"}, "on_false": "note"}
    book, source, _ = setup(system, doc)
    run = submit(system, book, source, dry_run=False).json()
    tick(system)
    assert get(system, run["id"])["history"][0]["status"] == "SKIPPED"
    # Every tick opens a fresh session and rehydrates persisted progress.
    system["app"].state.engine.dispose()
    tick(system, 2)
    result = get(system, run["id"])
    assert result["status"] == "SUCCEEDED"
    with system["app"].state.sessions() as db:
        assert len(list(db.scalars(select(CaseNote)))) == 1
    events = system["client"].get(f"/api/v1/soar/executions/{run['id']}/audit").json()["items"]
    assert "soar.succeeded" in {e["action"] for e in events}


def test_duplicate_dry_run_and_cancel(system):
    book, source, _ = setup(system)
    first = submit(system, book, source).json()
    assert submit(system, book, source).json()["id"] == first["id"]
    assert submit(system, book, source, idempotency_key="another-key").json()["id"] == first["id"]
    assert submit(system, book, source, dry_run=False).status_code == 409
    tick(system, 3)
    with system["app"].state.sessions() as db:
        assert not list(db.scalars(select(CaseNote)))
    other = submit(system, book, source, dry_run=False, idempotency_key="live-key-01").json()
    assert (
        system["client"]
        .post(f"/api/v1/soar/executions/{other['id']}/decision", json={"decision": "cancel"})
        .json()["status"]
        == "CANCELLED"
    )
    tick(system)
    assert get(system, other["id"])["status"] == "CANCELLED"


def test_approval_simulation_and_tenant(system):
    doc = DOC | {
        "input_schema": {"target_id": "entity"},
        "steps": [{"id": "block", "action": "simulate_block_ip"}],
    }
    book, source, target = setup(system, doc)
    run = submit(system, book, source, dry_run=False, inputs={"target_id": target}).json()
    tick(system)
    assert get(system, run["id"])["status"] == "WAITING_FOR_APPROVAL"
    path = f"/api/v1/soar/executions/{run['id']}/decision"
    assert system["client"].post(path, json={"decision": "approve"}).status_code == 403
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert system["client"].get(f"/api/v1/soar/executions/{run['id']}").status_code == 404
    assert system["client"].post(path, json={"decision": "approve"}).status_code == 404
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    assert system["client"].post(path, json={"decision": "approve"}).status_code == 200
    tick(system)
    result = get(system, run["id"])
    assert result["status"] == "SUCCEEDED"
    assert result["history"][0]["output"]["simulated"] is True
    assert result["history"][0]["output"]["external_changed"] is False
    with system["app"].state.sessions() as db:
        assert db.get(Entity, target).attributes == {}


def test_failure_retry_and_timeout(system, monkeypatch):
    class Broken:
        def execute(self, *args):
            raise RuntimeError("secret-do-not-leak")

    doc = DOC | {"steps": [{"id": "first", "action": "enrich", "retries": 1}]}
    book, source, _ = setup(system, doc)
    run = submit(system, book, source).json()
    original = ADAPTERS["enrich"]
    monkeypatch.setitem(ADAPTERS, "enrich", Broken())
    tick(system)
    result = get(system, run["id"])
    assert result["status"] == "RUNNING"
    assert "secret-do-not-leak" not in str(result)
    with system["app"].state.sessions.begin() as db:
        db.get(WorkflowRun, run["id"]).available_at = 0
    monkeypatch.setitem(ADAPTERS, "enrich", original)
    tick(system)
    assert get(system, run["id"])["status"] == "SUCCEEDED"
    other = submit(system, book, source, dry_run=False, idempotency_key="timeout-01").json()
    with system["app"].state.sessions.begin() as db:
        db.get(WorkflowRun, other["id"]).deadline = time.time() - 1
    tick(system)
    assert get(system, other["id"])["status"] == "TIMED_OUT"


def test_concurrent_enqueue_and_workers(system):
    from aegis.soar import RunInput

    book, source, _ = setup(system)
    principal = SimpleNamespace(organization_id=system["org"], user=system["users"]["SUPER_ADMIN"])

    def add(_):
        with system["app"].state.sessions.begin() as db:
            return enqueue(
                db,
                system["settings"],
                principal,
                book["id"],
                RunInput(
                    source_type="incident", source_id=source, dry_run=False, idempotency_key="concurrent-key"
                ),
            ).id

    with ThreadPoolExecutor(max_workers=3) as pool:
        ids = list(pool.map(add, range(3)))
    assert len(set(ids)) == 1
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: tick(system, 3), range(3)))
    assert get(system, ids[0])["status"] == "SUCCEEDED"
    with system["app"].state.sessions() as db:
        assert len(list(db.scalars(select(CaseNote)))) == 1


def test_rbac_and_foreign_source(system):
    book, source, _ = setup(system)
    with system["app"].state.sessions.begin() as db:
        foreign = Incident(organization_id=system["other"], title="foreign", severity="high")
        db.add(foreign)
        db.flush()
        identifier = foreign.id
    assert submit(system, book, identifier).status_code == 404
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["VIEWER"]
    assert submit(system, book, source).status_code == 403
    assert (
        system["client"].post("/api/v1/soar/playbooks", json={"name": "No", "definition": DOC}).status_code
        == 403
    )


def test_cli(monkeypatch):
    from aegis import cli

    calls = []
    monkeypatch.setattr(cli, "call", lambda ctx, method, path, **kw: calls.append((method, path, kw)) or {})
    result = CliRunner().invoke(cli.app, ["soar", "execute", "book", "incident", "source", "request-key"])
    assert result.exit_code == 0, result.output
    assert calls[0][2]["json"]["dry_run"] is True
    assert CliRunner().invoke(cli.app, ["soar", "approve", "run"]).exit_code == 0
    assert calls[-1][1] == "soar/executions/run/decision"


def test_trigger_filters_capacity_and_disabled(system):
    doc = DOC | {
        "trigger": {
            "source": "incident",
            "conditions": [{"field": "severity", "op": "gte", "value": "critical"}],
        }
    }
    book, source, _ = setup(system, doc)
    assert submit(system, book, source).status_code == 409
    updated = system["client"].post(
        "/api/v1/soar/playbooks",
        json={"name": "Review", "definition": DOC, "enabled": False, "expected_version": 1},
    )
    assert updated.status_code == 200
    assert submit(system, book, source).status_code == 409
    system["client"].post(
        "/api/v1/soar/playbooks",
        json={"name": "Review", "definition": DOC, "enabled": True, "expected_version": 2},
    )
    system["settings"].soar_queue_capacity = 1
    assert submit(system, book, source).status_code == 200
    with system["app"].state.sessions.begin() as db:
        another = Incident(organization_id=system["org"], title="Second", severity="high")
        db.add(another)
        db.flush()
        identifier = another.id
    assert submit(system, book, identifier, idempotency_key="queue-full").status_code == 429


def test_step_timeout_rolls_back_local_effects(system, monkeypatch):
    from aegis import soar

    original_time = time.time
    doc = DOC | {"steps": [{"id": "note", "action": "incident_note", "timeout_seconds": 1}]}
    book, source, _ = setup(system, doc)
    run = submit(system, book, source, dry_run=False).json()
    adapter = ADAPTERS["incident_note"]

    class Slow:
        def execute(self, db, run, step):
            result = adapter.execute(db, run, step)
            monkeypatch.setattr(soar.time, "time", lambda: original_time() + 2)
            return result

    monkeypatch.setitem(ADAPTERS, "incident_note", Slow())
    tick(system)
    assert get(system, run["id"])["status"] == "TIMED_OUT"
    with system["app"].state.sessions() as db:
        assert not list(db.scalars(select(CaseNote)))


def test_rejection_and_revoked_approval(system):
    from aegis.db import User

    doc = DOC | {
        "input_schema": {"target_id": "entity"},
        "steps": [{"id": "block", "action": "simulate_block_ip"}],
    }
    book, source, target = setup(system, doc)
    run = submit(system, book, source, dry_run=False, inputs={"target_id": target}).json()
    tick(system)
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    path = f"/api/v1/soar/executions/{run['id']}/decision"
    assert system["client"].post(path, json={"decision": "approve"}).status_code == 200
    with system["app"].state.sessions.begin() as db:
        db.get(User, system["users"]["SOC_MANAGER"].id).role = "VIEWER"
    tick(system)
    assert get(system, run["id"])["status"] == "WAITING_FOR_APPROVAL"
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["SECURITY_ADMIN"]
    assert system["client"].post(path, json={"decision": "reject"}).json()["status"] == "CANCELLED"
    tick(system)
    assert get(system, run["id"])["history"] == []


def test_terminal_failure_manual_retry_budget(system, monkeypatch):
    class Broken:
        def execute(self, *args):
            raise ValueError("never log this")

    book, source, _ = setup(system)
    run = submit(system, book, source).json()
    monkeypatch.setitem(ADAPTERS, "enrich", Broken())
    for attempt in range(4):
        tick(system)
        result = get(system, run["id"])
        assert result["status"] == "FAILED"
        assert result["attempts"] == attempt + 1
        response = system["client"].post(
            f"/api/v1/soar/executions/{run['id']}/decision", json={"decision": "retry"}
        )
        assert response.status_code == (200 if attempt < 3 else 409)


def test_version_is_pinned_and_foreign_target_rejected(system):
    doc = DOC | {
        "input_schema": {"target_id": "entity"},
        "steps": [{"id": "block", "action": "simulate_block_ip"}],
    }
    book, source, _ = setup(system, doc)
    with system["app"].state.sessions.begin() as db:
        target = Entity(organization_id=system["other"], type="ip", value="198.51.100.1")
        db.add(target)
        db.flush()
        target_id = target.id
    assert submit(system, book, source, inputs={"target_id": target_id}).status_code == 404
    system["client"].post(
        "/api/v1/soar/playbooks",
        json={"name": "Review", "definition": DOC, "enabled": True, "expected_version": 1},
    )
    run = submit(system, book, source).json()
    system["client"].post(
        "/api/v1/soar/playbooks",
        json={"name": "Review", "definition": doc, "enabled": True, "expected_version": 2},
    )
    tick(system, 3)
    result = get(system, run["id"])
    assert result["status"] == "SUCCEEDED"
    assert result["version"] == 2
    assert len(result["history"]) == 3


@pytest.mark.parametrize("kind", ["alert", "storyline"])
def test_existing_sources_and_evidence_fields(system, kind):
    from tests.test_storylines import run as correlate
    from tests.test_storylines import seed

    seed(system, [("a", 0, True), ("b", 10, True)])
    source = "ALT-a"
    if kind == "storyline":
        correlate(system)
        source = system["client"].get("/api/v1/storylines").json()["items"][0]["id"]
    doc = {
        "description": "Source enrichment",
        "trigger": {"source": kind, "conditions": [{"field": "severity", "op": "gte", "value": "high"}]},
        "steps": [{"id": "enrich", "action": "enrich"}],
    }
    if kind == "alert":
        doc["trigger"]["conditions"].append({"field": "rule_id", "value": "a"})
    else:
        doc["trigger"]["conditions"].append({"field": "risk_score", "op": "gte", "value": 0})
    book = (
        system["client"]
        .post("/api/v1/soar/playbooks", json={"name": "Source", "definition": doc, "enabled": True})
        .json()
    )
    response = system["client"].post(
        f"/api/v1/soar/playbooks/{book['id']}/execute",
        json={"source_type": kind, "source_id": source, "idempotency_key": "source-key"},
    )
    assert response.status_code == 200, response.text
    tick(system)
    assert get(system, response.json()["id"])["status"] == "SUCCEEDED"
    doc["trigger"]["required_evidence_fields"] = ["source_ip"]
    system["client"].post(
        "/api/v1/soar/playbooks",
        json={"name": "Source", "definition": doc, "enabled": True, "expected_version": 1},
    )
    assert (
        system["client"]
        .post(
            f"/api/v1/soar/playbooks/{book['id']}/execute",
            json={"source_type": kind, "source_id": source, "idempotency_key": "evidence-key"},
        )
        .status_code
        == 409
    )
