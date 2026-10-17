from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

from aegis.db import BehaviorEvidence, BehaviorFinding, BehaviorJob, BehaviorProfile, EventRecord
from aegis.ueba import DETECTORS, analyze, baseline, config, detect, features, key, process_jobs, score


def end():
    return datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def observation(when, index, **kwargs):
    return {
        "id": str(index),
        "hash": key(index),
        "time": when,
        "entities": [("user", "alice")],
        "ip": "192.0.2.1",
        "host": "host-a",
        "auth": True,
        "outcome": "success",
        **kwargs,
    }


def fixture_rows():
    start = end() - timedelta(days=15)
    history = [
        observation(start + timedelta(days=d, hours=9, minutes=m), f"h{d}-{m}")
        for d in range(14)
        for m in range(3)
    ]
    current = [
        observation(
            end() - timedelta(hours=22) + timedelta(minutes=m),
            f"c{m}",
            ip="192.0.2.99",
            host="host-b",
            outcome="failure" if m < 11 else "success",
        )
        for m in range(12)
    ]
    return start, history, current


def seed(system, org=None):
    _, history, current = fixture_rows()
    with system["app"].state.sessions.begin() as db:
        for r in history + current:
            db.add(
                EventRecord(
                    id=key(org or system["org"], r["id"]),
                    organization_id=org or system["org"],
                    timestamp=r["time"],
                    evidence_hash=r["hash"],
                    source="test-source",
                    state="PROCESSED",
                    payload={
                        "username": "alice",
                        "host": r["host"],
                        "source_ip": r["ip"],
                        "event_category": "authentication",
                        "outcome": r["outcome"],
                    },
                )
            )


def run(system):
    with system["app"].state.sessions.begin() as db:
        return analyze(db, system["org"], end(), config(system["settings"]))


def test_baseline_cold_start_and_mad():
    start, history, current = fixture_rows()
    base = baseline(history, start, 14, 20, 7)
    assert base["daily_median"] == 3 and base["daily_mad"] == 0
    assert base["observations"] == 42 and base["active_days"] == 14
    assert list(detect("user", current, baseline(history[:3], start, 14, 20, 7))) == []


@pytest.mark.parametrize("detector", DETECTORS)
def test_each_supported_detector(detector):
    start, history, current = fixture_rows()
    values = {r[0]: r for r in detect("user", current, baseline(history, start, 14, 20, 7))}
    assert detector in values
    assert values[detector][-1]


def test_risk_is_stable_and_bounded():
    assert score(75, 6, 1) == 75
    assert score(35, 3, 0.5) == 20
    assert 0 <= score(10000, 50, 1) <= 100


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"source_ip": "invalid"},
        {"username": ["bad"], "host": {"bad": 1}, "outcome": []},
        {"username": "alice", "collector": "synthetic"},
        {"username": "alice", "tags": ["replay"]},
    ],
)
def test_malformed_and_synthetic_events(payload):
    record = EventRecord(id="x", payload=payload, timestamp=end(), evidence_hash="h")
    result = features(record)
    assert result is None or result["entities"] == []


def test_persistence_dedup_out_of_order_and_evidence(system):
    seed(system)
    first = run(system)
    assert first["new_findings"] >= 6
    with system["app"].state.sessions.begin() as db:
        original = db.scalar(select(EventRecord).where(EventRecord.organization_id == system["org"]))
        db.add(
            EventRecord(
                id="duplicate",
                organization_id=system["org"],
                timestamp=original.timestamp,
                evidence_hash=original.evidence_hash,
                payload=original.payload,
                source=original.source,
            )
        )
    assert run(system)["new_findings"] == 0
    with system["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(BehaviorFinding)) == first["new_findings"]
        evidence = list(db.scalars(select(BehaviorEvidence)))
        assert evidence and not any(r.event_id == "duplicate" for r in evidence)
        assert all(r.organization_id == system["org"] for r in evidence)


def test_api_lifecycle_isolation_validation_and_pagination(system):
    seed(system)
    run(system)
    client = system["client"]
    data = client.get("/api/v1/ueba/findings?limit=1").json()["items"]
    assert len(data) == 1
    fid = data[0]["id"]
    assert client.get("/api/v1/ueba/findings?limit=101").status_code == 422
    assert client.post("/api/v1/ueba/analyze", json={"window_end": "2026-01-01"}).status_code == 422
    detail = client.get(f"/api/v1/ueba/findings/{fid}").json()
    assert detail["evidence"] and "payload" not in str(detail)
    for status in ["ACKNOWLEDGED", "RESOLVED", "SUPPRESSED", "NEW"]:
        response = client.post(
            f"/api/v1/ueba/findings/{fid}/status", json={"status": status, "reason": "Reviewed logs"}
        )
        assert response.status_code == 200 and response.json()["status"] == status
    assert run(system)["new_findings"] == 0
    assert len(client.get(f"/api/v1/ueba/findings/{fid}").json()["lifecycle"]) == 4
    client.headers["Authorization"] = "Bearer " + system["tokens"]["VIEWER"]
    assert (
        client.post(
            f"/api/v1/ueba/findings/{fid}/status", json={"status": "RESOLVED", "reason": "review"}
        ).status_code
        == 403
    )
    assert client.post("/api/v1/ueba/analyze", json={"window_end": end().isoformat()}).status_code == 403
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert client.get("/api/v1/ueba/findings").json() == {"items": []}
    assert client.get(f"/api/v1/ueba/findings/{fid}").status_code == 404
    assert client.get(f"/api/v1/ueba/profiles/{detail['profile_id']}").status_code == 404
    assert (
        client.post(
            f"/api/v1/ueba/findings/{fid}/status", json={"status": "RESOLVED", "reason": "review"}
        ).status_code
        == 404
    )


def test_job_idempotency_worker_and_refresh(system):
    seed(system)
    client = system["client"]
    body = {"window_end": end().isoformat()}
    first = client.post("/api/v1/ueba/analyze", json=body)
    assert first.status_code == 202
    assert client.post("/api/v1/ueba/analyze", json=body).json()["id"] == first.json()["id"]
    assert process_jobs(system["settings"], system["app"].state.sessions) == 1
    assert process_jobs(system["settings"], system["app"].state.sessions) == 0
    assert client.get("/api/v1/ueba/jobs/" + first.json()["id"]).json()["state"] == "COMPLETED"
    body["refresh_only"] = True
    client.post("/api/v1/ueba/analyze", json=body)
    assert process_jobs(system["settings"], system["app"].state.sessions) == 1
    with system["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(BehaviorJob)) == 2


def test_bound_rolls_back_and_worker_recovers(system, monkeypatch):
    seed(system)
    sessions = system["app"].state.sessions
    client = system["client"]
    jid = client.post("/api/v1/ueba/analyze", json={"window_end": end().isoformat()}).json()["id"]
    import aegis.ueba as module

    real = module.analyze

    def fail(*args, **kwargs):
        real(*args, **kwargs)
        raise RuntimeError("transient failure")

    monkeypatch.setattr(module, "analyze", fail)
    process_jobs(system["settings"], sessions)
    with sessions.begin() as db:
        assert db.scalar(select(func.count()).select_from(BehaviorFinding)) == 0
        job = db.get(BehaviorJob, jid)
        assert job.state == "RETRY"
        job.available_at = 0
    monkeypatch.setattr(module, "analyze", real)
    process_jobs(system["settings"], sessions)
    assert client.get(f"/api/v1/ueba/jobs/{jid}").json()["state"] == "COMPLETED"
    with sessions.begin() as db:
        with pytest.raises(ValueError, match="Event limit"):
            analyze(db, system["org"], end(), {**config(system["settings"]), "event_limit": 10})


def test_cli_uses_authenticated_api(monkeypatch):
    from aegis.cli import app

    calls = []
    monkeypatch.setattr(
        "aegis.cli.call",
        lambda ctx, method, path, **kwargs: calls.append((method, path, kwargs)) or {"items": []},
    )
    runner = CliRunner()
    for args in [
        ["profiles"],
        ["findings"],
        ["profile", "abc"],
        ["evidence", "abc"],
        ["detectors"],
        ["jobs"],
        ["analyze", end().isoformat(), "--refresh-only"],
    ]:
        result = runner.invoke(app, ["--format", "json", "ueba", *args])
        assert result.exit_code == 0, result.output
    assert calls[-1][2]["json"]["refresh_only"] is True


def test_refresh_does_not_create_findings(system):
    seed(system)
    with system["app"].state.sessions.begin() as db:
        result = analyze(db, system["org"], end(), config(system["settings"]), True)
        assert result["new_findings"] == 0
        assert db.scalar(select(func.count()).select_from(BehaviorProfile)) > 0


def test_investigation_context_and_audit(system):
    from aegis.db import AlertEvent, Incident, IncidentAlert, Storyline
    from tests.test_storylines import seed as seed_alerts

    seed(system)
    run(system)
    seed_alerts(system, [("ueba-related", 0, True)])
    with system["app"].state.sessions.begin() as db:
        evidence = db.scalar(select(BehaviorEvidence))
        fid, eid = evidence.finding_id, evidence.event_id
        db.add(AlertEvent(alert_id="ALT-ueba-related", event_id=eid))
        incident = Incident(organization_id=system["org"], title="Related investigation", severity="high")
        db.add(incident)
        db.flush()
        db.add(IncidentAlert(incident_id=incident.id, alert_id="ALT-ueba-related"))
        story = Storyline(
            organization_id=system["org"],
            incident_id=incident.id,
            anchor_alert_id="ALT-ueba-related",
            window_seconds=1800,
            summary={},
        )
        db.add(story)
        db.flush()
        sid = story.id
    client = system["client"]
    assert sid in client.get(f"/api/v1/ueba/findings/{fid}").json()["related"]["storylines"]
    assert fid in {r["id"] for r in client.get(f"/api/v1/ueba/context/storyline/{sid}").json()["items"]}
    client.post(f"/api/v1/ueba/findings/{fid}/status", json={"status": "ACKNOWLEDGED", "reason": "reviewed"})
    assert client.get("/api/v1/audit/verify").json() == {"valid": True}
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert client.get(f"/api/v1/ueba/context/storyline/{sid}").status_code == 404


def test_0011_real_upgrade(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect, text

    from aegis.config import get_settings
    from aegis.db import Base

    url = f"sqlite:///{tmp_path / 'upgrade.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(
        engine, tables=[t for t in Base.metadata.sorted_tables if not t.name.startswith("ueba_")]
    )
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        command.stamp(Config("alembic.ini"), "0010")
        command.upgrade(Config("alembic.ini"), "head")
        assert {"ueba_profiles", "ueba_findings", "ueba_evidence", "ueba_jobs"} <= set(
            inspect(engine).get_table_names()
        )
        with engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0011"
        assert any(
            f["constrained_columns"] == ["organization_id", "profile_id"]
            for f in inspect(engine).get_foreign_keys("ueba_findings")
        )
    finally:
        engine.dispose()
        get_settings.cache_clear()


def test_deterministic_order_and_tenant_independent_baselines(system):
    seed(system)
    seed(system, system["other"])
    run(system)
    with system["app"].state.sessions.begin() as db:
        result = analyze(db, system["other"], end(), config(system["settings"]))
        assert result["new_findings"] >= 6
        a = list(
            db.scalars(
                select(BehaviorFinding)
                .where(BehaviorFinding.organization_id == system["org"])
                .order_by(BehaviorFinding.detector, BehaviorFinding.risk_score)
            )
        )
        b = list(
            db.scalars(
                select(BehaviorFinding)
                .where(BehaviorFinding.organization_id == system["other"])
                .order_by(BehaviorFinding.detector, BehaviorFinding.risk_score)
            )
        )
        assert [(r.detector, r.risk_score, r.comparison) for r in a] == [
            (r.detector, r.risk_score, r.comparison) for r in b
        ]
        assert {r.id for r in a}.isdisjoint({r.id for r in b})


def test_recurrence_and_failed_job_retry(system):
    seed(system)
    run(system)
    client = system["client"]
    first = client.get("/api/v1/ueba/findings?entity=alice").json()["items"][0]
    assert first["repeated"] is False
    with system["app"].state.sessions.begin() as db:
        source = db.get(BehaviorFinding, first["id"])
        db.add(
            BehaviorFinding(
                id="earlier",
                organization_id=source.organization_id,
                profile_id=source.profile_id,
                detector=source.detector,
                version=1,
                first_seen=source.first_seen - timedelta(days=1),
                last_seen=source.last_seen - timedelta(days=1),
                window_end=source.window_end - timedelta(days=1),
                risk_score=source.risk_score,
                severity=source.severity,
                confidence=source.confidence,
                comparison=source.comparison,
                explanation=source.explanation,
            )
        )
    detail = client.get("/api/v1/ueba/findings/" + first["id"]).json()
    assert detail["repeated"] is True and detail["prior_occurrences"] == 1
    jid = client.post("/api/v1/ueba/analyze", json={"window_end": end().isoformat()}).json()["id"]
    with system["app"].state.sessions.begin() as db:
        job = db.get(BehaviorJob, jid)
        job.config = {**job.config, "event_limit": 1}
    process_jobs(system["settings"], system["app"].state.sessions)
    assert client.get(f"/api/v1/ueba/jobs/{jid}").json()["state"] == "FAILED"
    assert client.post(f"/api/v1/ueba/jobs/{jid}/retry").status_code == 200
    process_jobs(system["settings"], system["app"].state.sessions)
    assert client.get(f"/api/v1/ueba/jobs/{jid}").json()["state"] == "COMPLETED"


def test_cross_tenant_profile_constraint(system):
    from sqlalchemy.exc import IntegrityError

    seed(system)
    run(system)
    with system["app"].state.sessions.begin() as db:
        fid = db.scalar(select(BehaviorFinding.id))
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                BehaviorEvidence(
                    organization_id=system["other"], finding_id=fid, event_id="foreign", evidence_hash="hash"
                )
            )
            db.flush()


def test_bounded_large_window_has_no_partial_results(system):
    with system["app"].state.sessions.begin() as db:
        db.add_all(
            [
                EventRecord(
                    id=f"bulk-{i}",
                    organization_id=system["org"],
                    timestamp=end() - timedelta(hours=1),
                    evidence_hash=key(i),
                    source="bulk",
                    payload={"username": "alice"},
                )
                for i in range(1001)
            ]
        )
    with system["app"].state.sessions.begin() as db:
        with pytest.raises(ValueError, match="Event limit"), db.begin_nested():
            analyze(db, system["org"], end(), {**config(system["settings"]), "event_limit": 1000})
        assert db.scalar(select(func.count()).select_from(BehaviorProfile)) == 0
        assert db.scalar(select(func.count()).select_from(BehaviorFinding)) == 0


def test_identical_raw_messages_at_different_times_are_not_duplicates(system):
    with system["app"].state.sessions.begin() as db:
        db.add_all(
            [
                EventRecord(
                    id=f"same-raw-{i}",
                    organization_id=system["org"],
                    timestamp=end() - timedelta(days=2, minutes=i),
                    evidence_hash="same-raw-hash",
                    source="auth-log",
                    payload={"username": "alice"},
                )
                for i in range(20)
            ]
        )
    assert run(system)["unique_observations"] == 20
    with system["app"].state.sessions() as db:
        profile = db.scalar(select(BehaviorProfile).where(BehaviorProfile.entity == "alice"))
        assert profile.baseline["observations"] == 20


def test_failed_job_retry_obeys_tenant_queue_limit(system):
    with system["app"].state.sessions.begin() as db:
        for day in range(11):
            db.add(
                BehaviorJob(
                    id=f"queue-{day}",
                    organization_id=system["org"],
                    window_end=end() - timedelta(days=day),
                    refresh_only=False,
                    state="FAILED" if day == 10 else "PENDING",
                    config=config(system["settings"]),
                )
            )
    response = system["client"].post("/api/v1/ueba/jobs/queue-10/retry")
    assert response.status_code == 429
    with system["app"].state.sessions() as db:
        assert db.get(BehaviorJob, "queue-10").state == "FAILED"


def test_failure_sequence_window_boundary_and_sorting():
    start, history, _ = fixture_rows()
    base = baseline(history, start, 14, 20, 7)
    stamp = end() - timedelta(hours=1)
    rows = [observation(stamp, f"f-{i}", outcome="failure") for i in range(5)]
    success = observation(stamp + timedelta(minutes=15), "success")
    assert "failure_then_success" in {r[0] for r in detect("user", [success, *reversed(rows)], base)}
    success["time"] += timedelta(microseconds=1)
    assert "failure_then_success" not in {r[0] for r in detect("user", [*rows, success], base)}
