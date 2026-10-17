import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

from aegis.cli import app
from aegis.db import Alert, AuditLog, Entity, Storyline, StorylineMember
from aegis.storylines import reasons
from tests.test_pipeline import attack_chain

BASE = datetime(2026, 1, 1, tzinfo=UTC)


def seed(system, specs):
    with system["app"].state.sessions.begin() as db:
        host = db.scalar(
            select(Entity).where(Entity.organization_id == system["org"], Entity.value == "host-a")
        )
        if host is None:
            host = Entity(organization_id=system["org"], type="host", value="host-a")
            db.add(host)
            db.flush()
        for name, seconds, identified in specs:
            db.add(
                Alert(
                    id="ALT-" + name,
                    organization_id=system["org"],
                    title=name,
                    severity="high",
                    rule_id=name,
                    rule_version=1,
                    fingerprint=name,
                    correlation_key=name,
                    confidence=80,
                    risk_score=70,
                    risk_factors={},
                    explanation={},
                    mitre_techniques=["T1110"],
                    entity_ids=[host.id] if identified else [],
                    first_seen=BASE + timedelta(seconds=seconds),
                    last_seen=BASE + timedelta(seconds=seconds),
                )
            )


def run(system, window=1800):
    response = system["client"].post(f"/api/v1/storylines/correlate?window_seconds={window}")
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("distance,expected", [(0, 1), (1799, 1), (1800, 1), (1801, 0)])
def test_window_boundary(system, distance, expected):
    seed(system, [("b", distance, True), ("a", 0, True)])
    assert run(system)["storylines"] == expected


def test_no_time_only_or_transitive_correlation(system):
    seed(system, [("a", 0, True), ("b", 1500, True), ("c", 3000, True), ("d", 10, False)])
    assert run(system) == {"changed": 1, "storylines": 1, "unassigned_alerts": 2}
    story = system["client"].get("/api/v1/storylines").json()["items"][0]
    assert story["summary"]["alert_count"] == 2
    assert story["summary"]["confidence"] != story["summary"]["risk_score"]


def test_late_arrival_idempotency_and_persistence(system):
    seed(system, [("b", 100, True), ("c", 200, True)])
    run(system)
    client = system["client"]
    first = client.get("/api/v1/storylines").json()["items"][0]
    seed(system, [("a", 0, True)])
    assert run(system)["changed"] == 1
    assert run(system)["changed"] == 0
    # Every request opens a fresh DB session; no in-memory correlation state.
    story = client.get(f"/api/v1/storylines/{first['id']}").json()
    assert story["id"] == first["id"]
    assert [a["alert_id"] for a in story["summary"]["timeline"]] == ["ALT-a", "ALT-b", "ALT-c"]
    assert len(story["members"]) == 3
    with system["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(StorylineMember)) == 3
        assert (
            db.scalar(
                select(func.count()).select_from(AuditLog).where(AuditLog.action == "storylines.correlate")
            )
            == 2
        )
    assert client.get("/api/v1/audit/verify").json() == {"valid": True}


def test_tenant_and_rbac(system):
    seed(system, [("a", 0, True), ("b", 1, True)])
    run(system)
    client = system["client"]
    identifier = client.get("/api/v1/storylines").json()["items"][0]["id"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert client.get("/api/v1/storylines").json()["items"] == []
    assert client.get(f"/api/v1/storylines/{identifier}").status_code == 404
    assert run(system)["storylines"] == 0
    client.headers["Authorization"] = "Bearer " + system["tokens"]["VIEWER"]
    assert client.post("/api/v1/storylines/correlate").status_code == 403
    client.headers.pop("Authorization")
    assert client.get("/api/v1/storylines").status_code == 401


def test_malformed_and_foreign_identifiers(system):
    seed(system, [("a", 0, True), ("b", 1, True)])
    with system["app"].state.sessions.begin() as db:
        foreign = Entity(organization_id=system["other"], type="host", value="foreign-host")
        invalid = Entity(organization_id=system["org"], type="ip", value="invalid-ip")
        db.add_all([foreign, invalid])
        db.flush()
        for a in db.scalars(select(Alert)):
            a.entity_ids = [foreign.id, invalid.id, {}, None]
    assert run(system)["storylines"] == 0


@pytest.mark.parametrize("window", [0, -1, 86401, "oops"])
def test_invalid_window(system, window):
    assert system["client"].post(f"/api/v1/storylines/correlate?window_seconds={window}").status_code == 422


def test_synthetic_detection_to_resolved_incident(system):
    attack_chain(system)
    assert run(system)["storylines"] >= 1
    client = system["client"]
    story = client.get("/api/v1/storylines").json()["items"][0]
    detail = client.get(f"/api/v1/storylines/{story['id']}").json()
    investigation = detail["investigation"]
    assert investigation["evidence"] and investigation["entities"]
    incident = investigation["resource"]
    identifier = incident["id"]
    assert (
        client.post(
            f"/api/v1/incidents/{identifier}/notes", json={"text": "Validated synthetic evidence"}
        ).status_code
        == 200
    )
    for status in ["TRIAGED", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY", "RESOLVED"]:
        response = client.patch(
            f"/api/v1/incidents/{identifier}/status",
            json={
                "status": status,
                "revision": incident["revision"],
                "assignee": system["users"]["ANALYST"].id,
                "resolution": "Synthetic exercise completed",
            },
        )
        assert response.status_code == 200, response.text
        incident = response.json()
    assert client.get("/api/v1/storylines?status=RESOLVED").json()["items"]
    assert client.get("/api/v1/audit/verify").json() == {"valid": True}


def test_cli_uses_authenticated_api(system, monkeypatch):
    import aegis.cli as cli

    seed(system, [("a", 0, True), ("b", 1, True)])

    def call(ctx, method, path, **kwargs):
        response = system["client"].request(method, "/api/v1/" + path, **kwargs)
        response.raise_for_status()
        return response.json()

    monkeypatch.setattr(cli, "call", call)
    runner = CliRunner()
    assert runner.invoke(app, ["storylines", "correlate"]).exit_code == 0
    result = runner.invoke(app, ["storylines", "list"])
    assert result.exit_code == 0 and "STL-" in result.stdout
    identifier = system["client"].get("/api/v1/storylines").json()["items"][0]["id"]
    assert runner.invoke(app, ["storylines", "show", identifier]).exit_code == 0


def test_representative_dataset(system):
    seed(system, [(f"a-{i:04}", i, True) for i in range(1000)])
    started = time.perf_counter()
    result = run(system)
    elapsed = time.perf_counter() - started
    assert result == {"changed": 1, "storylines": 1, "unassigned_alerts": 0}
    assert elapsed < 15, f"1000-alert correlation took {elapsed:.2f}s"


def test_pair_order_symmetry():
    entity = Entity(id="host", type="host", value="host-a")
    a = Alert(id="a", first_seen=BASE, entity_ids=["host"])
    b = Alert(id="b", first_seen=BASE - timedelta(seconds=1800), entity_ids=["host"])
    assert reasons(a, b, {"host": entity}, 1800)
    assert reasons(b, a, {"host": entity}, 1800)


def test_scoped_key_cannot_read_or_correlate_evidence(system):
    seed(system, [("a", 0, True), ("b", 1, True)])
    run(system)
    client = system["client"]
    identifier = client.get("/api/v1/storylines").json()["items"][0]["id"]
    key = client.post(
        "/api/v1/auth/api-keys",
        json={
            "name": "incidents-only",
            "permissions": ["incidents.read", "incidents.create"],
            "days": 1,
        },
    ).json()
    client.headers["Authorization"] = "Bearer " + key["key"]
    assert client.get("/api/v1/storylines").status_code == 403
    assert client.get(f"/api/v1/storylines/{identifier}").status_code == 403
    assert client.post("/api/v1/storylines/correlate").status_code == 403


def test_survives_application_restart(system):
    from fastapi.testclient import TestClient

    from aegis.api import create_app

    seed(system, [("a", 0, True), ("b", 1, True)])
    run(system)
    expected = system["client"].get("/api/v1/storylines").json()
    with TestClient(create_app(system["settings"])) as restarted:
        restarted.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
        assert restarted.get("/api/v1/storylines").json() == expected
        assert restarted.post("/api/v1/storylines/correlate").json()["changed"] == 0


def test_closed_incident_does_not_absorb_new_alerts(system):
    from aegis.db import Incident

    seed(system, [("a", 0, True), ("b", 1, True)])
    run(system)
    with system["app"].state.sessions.begin() as db:
        db.scalar(select(Incident)).status = "CLOSED"
    seed(system, [("c", 2, True)])
    assert run(system) == {"changed": 0, "storylines": 1, "unassigned_alerts": 1}


def test_over_limit_is_rejected_without_partial_writes(system, monkeypatch):
    import aegis.storylines as storylines

    seed(system, [("a", 0, True), ("b", 1, True)])
    monkeypatch.setattr(storylines, "MAX_ALERTS", 1)
    assert system["client"].post("/api/v1/storylines/correlate").status_code == 422
    assert system["client"].get("/api/v1/storylines").json()["items"] == []


def test_risk_and_confidence_caps_are_independent():
    from aegis.storylines import summarize

    alerts = [
        Alert(
            id=str(i),
            first_seen=BASE,
            last_seen=BASE,
            severity="critical",
            rule_id=str(i),
            title="test",
            mitre_techniques=[],
        )
        for i in range(20)
    ]
    members = [StorylineMember(reasons=[{"type": kind} for kind in ["ip", "host", "user"]])]
    summary = summarize(alerts, members)
    assert summary["risk_score"] == 100
    assert summary["confidence"] == 95
    assert sum(summary["risk_factors"].values()) == 110


def test_correlate_resilience_missing_anchor_alert_or_incident(system):
    """Verify correlate handles purged anchor alert or deleted incident without unhandled KeyError."""
    from sqlalchemy import text

    seed(system, [("a", 0, True), ("b", 10, True)])
    res1 = run(system)
    assert res1["storylines"] == 1

    # Simulate anchor alert missing from by_id map (e.g. purged or beyond retained window)
    with system["app"].state.sessions.begin() as db:
        db.execute(text("PRAGMA foreign_keys = OFF"))
        story = db.scalar(select(Storyline))
        story.anchor_alert_id = "ALT-purged"

    # Seed a new alert ALT-c that attempts correlation
    seed(system, [("c", 20, True)])

    # Correlate should safely skip missing anchor rather than raising KeyError: 'ALT-purged'
    res2 = run(system)
    assert res2["storylines"] >= 1

