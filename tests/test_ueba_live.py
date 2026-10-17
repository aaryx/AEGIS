"""Live PostgreSQL/Redis/OpenSearch UEBA acceptance; use a disposable database only."""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from aegis.api import create_app
from aegis.config import Settings
from aegis.db import (
    BehaviorEvidence,
    BehaviorFinding,
    BehaviorJob,
    BehaviorProfile,
    EventRecord,
    Organization,
    User,
)
from aegis.parsers import digest
from aegis.pipeline import seed_rules
from aegis.schemas import EventInput, SearchQuery
from aegis.security import issue_session
from aegis.simulation import simulate
from aegis.ueba import process_jobs
from aegis.worker import process_once
from tests.test_postgres_integration import pg_engine  # noqa: F401 - shared live fixture

pytestmark = pytest.mark.integration


def window_end():
    return datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def telemetry():
    end = window_end()
    history = [
        EventInput(
            source="ueba-validation",
            collector="validation-auth",
            source_sequence=f"h-{d}-{m}",
            timestamp=end - timedelta(days=15 - d) + timedelta(hours=9, minutes=m),
            raw_event={
                "username": "synthetic-admin",
                "host": "BASELINE-HOST",
                "source_ip": "192.0.2.1",
                "event_category": "authentication",
                "outcome": "success",
            },
        )
        for d in range(14)
        for m in range(3)
    ]
    # Explicitly untagged fixture telemetry in an isolated test tenant exercises the real engine.
    current = [
        e.model_copy(update={"collector": "validation-auth"})
        for e in simulate("attack-chain", end - timedelta(hours=22))
    ]
    return history + current


@pytest.fixture
def live(request):
    engine = request.getfixturevalue("pg_engine")
    settings = Settings(
        environment="testing",
        database_url=engine.url.render_as_string(hide_password=False),
        redis_url=os.environ.get("REDIS_URL"),
        opensearch_url=os.environ.get("OPENSEARCH_URL"),
        opensearch_username=os.environ.get("OPENSEARCH_USERNAME", "aegis"),
        opensearch_password=os.environ.get("OPENSEARCH_PASSWORD", ""),
        audit_secret=os.environ.get("AUDIT_SECRET", "ueba-validation-audit-key-32-characters"),
        _env_file=None,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.sessions.begin() as db:
            org, other = Organization(name="UEBA live validation"), Organization(name="UEBA foreign tenant")
            db.add_all([org, other])
            db.flush()
            tokens = {}
            for role, tenant in [("SUPER_ADMIN", org.id), ("VIEWER", org.id), ("OUTSIDER", other.id)]:
                user = User(
                    organization_id=tenant,
                    username="ueba-" + uuid4().hex,
                    password_hash="not-a-password-hash",
                    role="SUPER_ADMIN" if role == "OUTSIDER" else role,
                )
                db.add(user)
                db.flush()
                tokens[role], _ = issue_session(db, user, settings)
            seed_rules(db, org.id)
        client.headers["Authorization"] = "Bearer " + tokens["SUPER_ADMIN"]
        yield {
            "app": app,
            "client": client,
            "settings": settings,
            "org": org.id,
            "other": other.id,
            "tokens": tokens,
        }


def ingest_fixture(live):
    response = live["client"].post(
        "/api/v1/events/ingest", json={"events": [e.model_dump(mode="json") for e in telemetry()]}
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_live_ingest_to_ueba_evidence_actions_and_storyline(live, record_property):
    assert live["app"].state.redis.ping()
    assert live["app"].state.storage.health() == "HEALTHY"
    start = time.perf_counter()
    accepted = ingest_fixture(live)
    repeated = ingest_fixture(live)
    assert len(accepted["accepted"]) == 58
    assert not repeated["accepted"] and len(repeated["duplicates"]) == 58
    app, settings, client = live["app"], live["settings"], live["client"]
    for _ in range(30):
        process_once(settings, app.state.sessions, app.state.storage, app.state.redis)
        with app.state.sessions() as db:
            pending = db.scalar(
                select(func.count())
                .select_from(EventRecord)
                .where(EventRecord.organization_id == live["org"], EventRecord.state != "PROCESSED")
            )
        if pending == 0:
            break
    assert pending == 0
    app.state.storage.client.indices.refresh(index="aegis-events*")
    assert (
        app.state.storage.search(
            live["org"], SearchQuery(limit=100, start=window_end() - timedelta(days=16), end=window_end())
        )["total"]
        == 58
    )
    assert client.post("/api/v1/storylines/correlate").status_code == 200
    response = client.post("/api/v1/ueba/analyze", json={"window_end": window_end().isoformat()})
    assert response.status_code == 202
    job_id = response.json()["id"]
    assert process_jobs(settings, app.state.sessions) == 1
    assert client.get(f"/api/v1/ueba/jobs/{job_id}").json()["state"] == "COMPLETED"
    findings = client.get("/api/v1/ueba/findings?entity=synthetic-admin").json()["items"]
    assert {f["detector"] for f in findings} == {
        "activity_volume",
        "failure_burst",
        "new_source_ip",
        "new_host",
        "unusual_hour",
        "failure_then_success",
    }
    f = next(f for f in findings if f["detector"] == "failure_then_success")
    detail = client.get("/api/v1/ueba/findings/" + f["id"]).json()
    assert detail["related"]["storylines"] and detail["related"]["incidents"]
    with app.state.sessions() as db:
        for ref in detail["evidence"]:
            event = db.get(EventRecord, ref["event_id"])
            assert event.organization_id == live["org"]
            assert ref["evidence_hash"] == event.evidence_hash == digest(event.payload["raw_event"])
    for sid in detail["related"]["storylines"]:
        assert f["id"] in {
            r["id"] for r in client.get(f"/api/v1/ueba/context/storyline/{sid}").json()["items"]
        }
    for status in ("ACKNOWLEDGED", "SUPPRESSED", "RESOLVED"):
        assert (
            client.post(
                f"/api/v1/ueba/findings/{f['id']}/status",
                json={"status": status, "reason": "Live validation"},
            ).status_code
            == 200
        )
    assert client.get("/api/v1/audit/verify").json() == {"valid": True}
    client.headers["Authorization"] = "Bearer " + live["tokens"]["OUTSIDER"]
    assert client.get("/api/v1/ueba/findings/" + f["id"]).status_code == 404
    assert client.get("/api/v1/ueba/profiles/" + f["profile_id"]).status_code == 404
    assert client.get(f"/api/v1/ueba/jobs/{job_id}").status_code == 404
    assert (
        client.post(
            f"/api/v1/ueba/findings/{f['id']}/status", json={"status": "NEW", "reason": "Foreign attempt"}
        ).status_code
        == 404
    )
    client.headers["Authorization"] = "Bearer " + live["tokens"]["VIEWER"]
    assert (
        client.post("/api/v1/ueba/analyze", json={"window_end": window_end().isoformat()}).status_code == 403
    )
    del client.headers["Authorization"]
    assert client.get("/api/v1/ueba/findings").status_code == 401
    record_property("pipeline_seconds", round(time.perf_counter() - start, 3))


def test_live_concurrent_submission_and_workers(live, record_property):
    ingest_fixture(live)
    client, app = live["client"], live["app"]
    body = {"window_end": window_end().isoformat()}

    def submit(_):
        response = client.post("/api/v1/ueba/analyze", json=body)
        assert response.status_code == 202, response.text
        return response.json()["id"]

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(submit, range(16)))
    assert len(set(ids)) == 1
    # Different jobs for the same tenant must serialize profile writes without deadlock.
    for days in (1, 2):
        assert (
            client.post(
                "/api/v1/ueba/analyze", json={"window_end": (window_end() - timedelta(days=days)).isoformat()}
            ).status_code
            == 202
        )
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(process_jobs, live["settings"], app.state.sessions) for _ in range(4)]
        assert sum(f.result(timeout=30) for f in futures) == 3
    assert all(j["state"] == "COMPLETED" for j in client.get("/api/v1/ueba/jobs").json()["items"])
    before = client.get("/api/v1/ueba/findings").json()
    submit(0)
    assert process_jobs(live["settings"], app.state.sessions) == 0
    assert client.get("/api/v1/ueba/findings").json() == before
    record_property("concurrent_seconds", round(time.perf_counter() - start, 3))


def test_live_worker_rollback_and_retry(live, monkeypatch):
    import aegis.ueba as module

    ingest_fixture(live)
    app, client = live["app"], live["client"]
    jid = client.post("/api/v1/ueba/analyze", json={"window_end": window_end().isoformat()}).json()["id"]
    original = module.analyze

    def fail_after_writes(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("injected transient failure")

    monkeypatch.setattr(module, "analyze", fail_after_writes)
    process_jobs(live["settings"], app.state.sessions)
    with app.state.sessions.begin() as db:
        for model in (BehaviorProfile, BehaviorFinding, BehaviorEvidence):
            assert (
                db.scalar(select(func.count()).select_from(model).where(model.organization_id == live["org"]))
                == 0
            )
        job = db.get(BehaviorJob, jid)
        assert job.state == "RETRY" and job.attempts == 1
        job.available_at = 0
    monkeypatch.setattr(module, "analyze", original)
    process_jobs(live["settings"], app.state.sessions)
    assert client.get(f"/api/v1/ueba/jobs/{jid}").json()["state"] == "COMPLETED"


def test_live_scoped_keys_and_composite_tenant_constraints(live):
    from sqlalchemy.exc import IntegrityError

    ingest_fixture(live)
    client, app = live["client"], live["app"]
    client.post("/api/v1/ueba/analyze", json={"window_end": window_end().isoformat()})
    process_jobs(live["settings"], app.state.sessions)
    finding = client.get("/api/v1/ueba/findings").json()["items"][0]
    with app.state.sessions.begin() as db:
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                BehaviorEvidence(
                    organization_id=live["other"],
                    finding_id=finding["id"],
                    event_id="foreign",
                    evidence_hash="0" * 64,
                )
            )
            db.flush()
    response = client.post(
        "/api/v1/auth/api-keys", json={"name": "limited UEBA", "permissions": ["ueba.read"], "days": 1}
    )
    assert response.status_code == 200, response.text
    client.headers["Authorization"] = "Bearer " + response.json()["key"]
    assert client.get("/api/v1/ueba/detectors").status_code == 200
    assert client.get("/api/v1/ueba/profiles").status_code == 403
    assert client.get("/api/v1/ueba/findings/" + finding["id"]).status_code == 403
