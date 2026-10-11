import base64
import json

from sqlalchemy import select

from aegis.db import EventRecord, SearchJob
from aegis.simulation import simulate
from tests.conftest import drain


def attack_chain(system):
    client = system["client"]
    assert (
        client.post(
            "/api/v1/iocs", json={"type": "ip", "value": "203.0.113.10", "source": "synthetic"}
        ).status_code
        == 201
    )
    events = simulate("attack-chain")
    response = client.post(
        "/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]}
    )
    assert response.status_code == 202, response.text
    drain(system)
    return events


def test_acceptance_chain_and_evidence(system):
    events = attack_chain(system)
    client = system["client"]
    alerts = client.get("/api/v1/alerts").json()["items"]
    rules = {alert["rule_id"] for alert in alerts}
    assert {
        "AEGIS-AUTH-001",
        "AEGIS-AUTH-003",
        "AEGIS-PRIV-001",
        "AEGIS-PROC-001",
        "AEGIS-NET-003",
        "AEGIS-CORR-001",
    } <= rules
    incidents = client.get("/api/v1/incidents").json()["items"]
    assert len(incidents) == 1
    investigation = client.get(f"/api/v1/investigations/{incidents[0]['id']}").json()
    assert len(investigation["evidence"]) == len(events)
    assert investigation["entities"] and investigation["relationships"] and investigation["iocs"]
    for alert in alerts:
        assert alert["risk_score"] == min(100, sum(alert["risk_factors"].values()))
        assert alert["event_count"] > 0 and alert["explanation"]["matched_fields"]
    ai = client.post(f"/api/v1/investigations/{incidents[0]['id']}/ai")
    assert ai.status_code == 200, ai.text
    assert ai.json()["provider"] == "local-deterministic"
    report = client.post(f"/api/v1/reports/{incidents[0]['id']}")
    assert report.status_code == 200, report.text
    assert len(report.json()["content"]["evidence"]) == len(events)
    assert client.get(f"/api/v1/reports/{report.json()['id']}/html").status_code == 200
    assert client.get("/api/v1/audit/verify").json() == {"valid": True}


def test_ingestion_and_processing_are_idempotent(system):
    events = attack_chain(system)
    client = system["client"]
    before = client.get("/api/v1/dashboard").json()
    response = client.post(
        "/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]}
    )
    assert len(response.json()["duplicates"]) == len(events)
    assert response.json()["accepted"] == []
    drain(system)
    after = client.get("/api/v1/dashboard").json()
    assert before["alerts"] == after["alerts"] and before["events"] == after["events"]
    changed = events[0].model_copy(update={"raw_event": {"message": "changed evidence"}})
    assert (
        client.post("/api/v1/events/ingest", json={"events": [changed.model_dump(mode="json")]}).status_code
        == 422
    )


def test_search_pagination_tenant_boundary_and_query_validation(system):
    attack_chain(system)
    client = system["client"]
    query = {
        "filters": [{"field": "event_category", "value": "authentication"}],
        "limit": 3,
        "aggregate": "outcome",
    }
    page = client.post("/api/v1/events/search", json=query)
    assert page.status_code == 200, page.text
    assert page.json()["total"] == 13
    assert page.json()["aggregations"] == {"failure": 12, "success": 1}
    second = client.post("/api/v1/events/search", json=query | {"cursor": page.json()["next_cursor"]}).json()
    assert not {item["event_id"] for item in second["items"]} & {
        item["event_id"] for item in page.json()["items"]
    }
    assert client.post("/api/v1/events/search", json=query | {"cursor": "invalid!"}).status_code == 422
    malformed_cursor = base64.urlsafe_b64encode(json.dumps(["not-a-timestamp", "event-id"]).encode()).decode()
    assert client.post("/api/v1/events/search", json=query | {"cursor": malformed_cursor}).status_code == 422
    assert (
        client.post(
            "/api/v1/events/search", json={"filters": [{"field": "raw_event", "op": "regex", "value": ".*"}]}
        ).status_code
        == 422
    )
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert client.post("/api/v1/events/search", json=query).json()["total"] == 0


def test_search_outage_dead_letters_projection_without_stopping_detection(system):
    from aegis.worker import process_once

    class FailedStorage:
        def index(self, org, events):
            raise ConnectionError("search unavailable")

    client = system["client"]
    response = client.post(
        "/api/v1/events/ingest",
        json={"events": [event.model_dump(mode="json") for event in simulate("benign")]},
    )
    app = system["app"]
    for _ in range(system["settings"].worker_max_attempts):
        process_once(system["settings"], app.state.sessions, FailedStorage())
        with app.state.sessions.begin() as db:
            for row in db.scalars(select(SearchJob)):
                row.available_at = 0
    with app.state.sessions() as db:
        records = list(db.scalars(select(EventRecord)))
        assert all(row.state == "PROCESSED" and row.payload["raw_event"] for row in records)
        assert all(row.state == "DEAD" for row in db.scalars(select(SearchJob)))
    for event_id in response.json()["accepted"]:
        assert client.post(f"/api/v1/system/search-jobs/{event_id}/retry").status_code == 200
    drain(system)
    assert client.get("/api/v1/dashboard").json()["events_processed"] == 3


def test_benign_events_do_not_create_alerts(system):
    events = simulate("benign")
    client = system["client"]
    assert (
        client.post(
            "/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]}
        ).status_code
        == 202
    )
    drain(system)
    assert client.get("/api/v1/alerts").json()["items"] == []


def test_incident_updates_are_versioned_and_transactional(system):
    attack_chain(system)
    client = system["client"]
    incident = client.get("/api/v1/incidents").json()["items"][0]
    path = f"/api/v1/incidents/{incident['id']}/status"
    assert client.patch(path, json={"status": "CLOSED", "revision": 1}).status_code == 409
    assert client.patch(path, json={"status": "TRIAGED", "revision": 1}).status_code == 200
    assert client.patch(path, json={"status": "INVESTIGATING", "revision": 1}).status_code == 409
    assert client.patch(path, json={"status": "INVESTIGATING", "revision": 2}).status_code == 200
