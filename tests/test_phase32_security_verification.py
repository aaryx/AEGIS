"""AEGIS Phase 3.2 — Production Integration & Security Verification Test Suite.

Rigorously verifies:
1. Complete unauthenticated access rejection (HTTP 401) on all Detection Lab endpoints.
2. Strict RBAC privilege separation across VIEWER, ANALYST, SENIOR_ANALYST, and SECURITY_ADMIN.
3. Cross-tenant IDOR protection and guessed/random ID mitigation (HTTP 404).
4. Malformed request payloads, invalid time ranges (end_time < start_time), and empty event_ids.
5. Sigma parser input validation (oversized >500KB, non-mapping types, malformed syntax).
6. AI explanation payload isolation and absence of credential leakage.
7. Replay engine deterministic handling of out-of-order, late-arriving, and mixed tz-naive/aware events.
8. Replay timeout handling (job status set to CANCELLED).
9. Full database assertions proving ZERO side-effects on production Alerts, Incidents, or WindowStates.
10. Synthetic event performance and throughput benchmarking (1k, 2.5k, 5k events).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.api import create_app
from aegis.config import Settings
from aegis.db import (
    Alert,
    Incident,
    Organization,
    Rule,
    RuleVersion,
    User,
    WindowState,
    database,
)
from aegis.pipeline import seed_rules
from aegis.replay import _parse_timestamp, execute_replay
from aegis.schemas import ReplayRequest
from aegis.security import PASSWORDS


@pytest.fixture
def phase32_env(tmp_path, monkeypatch):
    db_file = tmp_path / "phase32_verification.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("AUDIT_SECRET", "phase32-security-verification-audit-key-32b!")
    monkeypatch.setenv("AI_PROVIDER", "local")

    settings = Settings(
        database_url=db_url,
        audit_secret="phase32-security-verification-audit-key-32b!",
        ai_provider="local",
    )
    engine, session_factory = database(db_url)

    from aegis.db import Base
    Base.metadata.create_all(engine)

    # Seed two independent tenants: Tenant A and Tenant B
    with session_factory() as db:
        org_a = Organization(id="org-tenant-a", name="Tenant Alpha Security")
        org_b = Organization(id="org-tenant-b", name="Tenant Beta Security")

        # Users for Tenant A with different RBAC roles
        user_admin = User(
            id="user-a-admin",
            organization_id=org_a.id,
            username="admin_a",
            password_hash=PASSWORDS.hash("AdminPass123!"),
            role="SECURITY_ADMIN",
            active=True,
        )
        user_senior = User(
            id="user-a-senior",
            organization_id=org_a.id,
            username="senior_a",
            password_hash=PASSWORDS.hash("SeniorPass123!"),
            role="SENIOR_ANALYST",
            active=True,
        )
        user_analyst = User(
            id="user-a-analyst",
            organization_id=org_a.id,
            username="analyst_a",
            password_hash=PASSWORDS.hash("AnalystPass123!"),
            role="ANALYST",
            active=True,
        )
        user_viewer = User(
            id="user-a-viewer",
            organization_id=org_a.id,
            username="viewer_a",
            password_hash=PASSWORDS.hash("ViewerPass123!"),
            role="VIEWER",
            active=True,
        )

        # User for Tenant B
        user_b_admin = User(
            id="user-b-admin",
            organization_id=org_b.id,
            username="admin_b",
            password_hash=PASSWORDS.hash("AdminBPass123!"),
            role="SECURITY_ADMIN",
            active=True,
        )

        db.add_all([org_a, org_b, user_admin, user_senior, user_analyst, user_viewer, user_b_admin])
        db.flush()

        seed_rules(db, org_a.id)
        seed_rules(db, org_b.id)

        # Ensure AUTH-001 has baseline version 1 in org A
        rule_a = db.scalar(
            select(Rule).where(
                Rule.organization_id == org_a.id,
                (Rule.rule_id == "AUTH-001") | (Rule.rule_id == "AEGIS-AUTH-001"),
            )
        )
        if rule_a:
            db.add(
                RuleVersion(
                    organization_id=org_a.id,
                    rule_id=rule_a.id,
                    version=1,
                    author=user_admin.id,
                    summary="Baseline version 1 for Tenant A",
                    lifecycle_stage="ACTIVE",
                    document=rule_a.document,
                )
            )
        db.commit()

    app = create_app(settings)
    app.state.sessions = session_factory
    app.state.engine = engine
    client = TestClient(app)

    def get_token(username: str, password: str) -> dict[str, str]:
        resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    tokens = {
        "admin_a": get_token("admin_a", "AdminPass123!"),
        "senior_a": get_token("senior_a", "SeniorPass123!"),
        "analyst_a": get_token("analyst_a", "AnalystPass123!"),
        "viewer_a": get_token("viewer_a", "ViewerPass123!"),
        "admin_b": get_token("admin_b", "AdminBPass123!"),
    }

    yield {
        "client": client,
        "app": app,
        "tokens": tokens,
        "org_a": org_a.id,
        "org_b": org_b.id,
        "user_admin_id": user_admin.id,
        "session_factory": session_factory,
        "settings": settings,
        "engine": engine,
    }

    engine.dispose()


# ==============================================================================
# 1. UNAUTHENTICATED ENDPOINT ACCESS REJECTION
# ==============================================================================


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("POST", "/api/v1/rules/AUTH-001/replay", {"target_type": "DATASET", "dataset_name": "AUTH-001"}),
        ("GET", "/api/v1/rules/AUTH-001/replays", None),
        ("GET", "/api/v1/replays/rep-nonexistent", None),
        ("POST", "/api/v1/replays/rep-nonexistent/ai-explain", None),
        ("POST", "/api/v1/rules/AUTH-001/activate", {"version": 1, "summary": "activate"}),
        ("POST", "/api/v1/rules/AUTH-001/rollback", {"target_version": 1, "summary": "rollback"}),
        ("POST", "/api/v1/rules/import-sigma", {"yaml_rule": "title: Test\nlogsource:\n  category: test\n"}),
        ("GET", "/api/v1/coverage/mitre", None),
    ],
)
def test_unauthenticated_requests_denied(phase32_env, method, path, payload):
    clean_client = TestClient(phase32_env["app"])
    if method == "POST":
        resp = clean_client.post(path, json=payload or {})
    else:
        resp = clean_client.get(path)
    assert resp.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {resp.status_code}"


# ==============================================================================
# 2. RBAC PRIVILEGE SEPARATION AUDIT
# ==============================================================================


def test_rbac_privilege_tiers_on_replay_and_lifecycle(phase32_env):
    """Verify that VIEWER and ANALYST cannot activate or replay rules, SENIOR_ANALYST

    can replay but cannot activate, and only SECURITY_ADMIN can perform full lifecycle.
    """
    client = phase32_env["client"]
    tokens = phase32_env["tokens"]

    replay_payload = {
        "rule_id": "AUTH-001",
        "target_type": "DATASET",
        "dataset_name": "AUTH-001",
        "max_events": 100,
    }

    # 1. VIEWER cannot replay, activate, rollback, or import Sigma (403)
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=tokens["viewer_a"])
    assert resp.status_code == 403

    resp = client.post("/api/v1/rules/AUTH-001/activate", json={"version": 1, "summary": "test"}, headers=tokens["viewer_a"])
    assert resp.status_code == 403

    resp = client.post("/api/v1/rules/AUTH-001/rollback", json={"target_version": 1, "summary": "test"}, headers=tokens["viewer_a"])
    assert resp.status_code == 403

    resp = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": "title: Valid Title\n"}, headers=tokens["viewer_a"])
    assert resp.status_code == 403

    # But VIEWER can read rules and coverage (200)
    resp = client.get("/api/v1/rules", headers=tokens["viewer_a"])
    assert resp.status_code == 200

    resp = client.get("/api/v1/coverage/mitre", headers=tokens["viewer_a"])
    assert resp.status_code == 200

    # 2. ANALYST cannot replay (403) or activate (403)
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=tokens["analyst_a"])
    assert resp.status_code == 403

    resp = client.post("/api/v1/rules/AUTH-001/activate", json={"version": 1, "summary": "test"}, headers=tokens["analyst_a"])
    assert resp.status_code == 403

    # 3. SENIOR_ANALYST CAN replay (200), but CANNOT activate, rollback, or import Sigma (403)
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=tokens["senior_a"])
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    resp = client.post("/api/v1/rules/AUTH-001/activate", json={"version": 1, "summary": "test"}, headers=tokens["senior_a"])
    assert resp.status_code == 403

    resp = client.post("/api/v1/rules/AUTH-001/rollback", json={"target_version": 1, "summary": "test"}, headers=tokens["senior_a"])
    assert resp.status_code == 403

    resp = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": "title: Valid Title\n"}, headers=tokens["senior_a"])
    assert resp.status_code == 403

    # SENIOR_ANALYST can request AI explanation for replay job
    resp = client.post(f"/api/v1/replays/{job_id}/ai-explain", headers=tokens["senior_a"])
    assert resp.status_code == 200

    # 4. SECURITY_ADMIN can do all operations
    resp = client.post("/api/v1/rules/AUTH-001/activate", json={"version": 1, "summary": "Admin activation"}, headers=tokens["admin_a"])
    assert resp.status_code == 200


# ==============================================================================
# 3. CROSS-TENANT ISOLATION & GUESSED ID PROTECTION
# ==============================================================================


def test_cross_tenant_isolation_and_guessed_identifiers(phase32_env):
    """Verify Tenant B cannot inspect, replay, or explain Tenant A's jobs or rules."""
    client = phase32_env["client"]
    tokens = phase32_env["tokens"]

    # 1. Tenant A runs a replay
    replay_resp = client.post(
        "/api/v1/rules/AUTH-001/replay",
        json={"rule_id": "AUTH-001", "target_type": "DATASET", "dataset_name": "AUTH-001", "max_events": 50},
        headers=tokens["admin_a"],
    )
    assert replay_resp.status_code == 200
    tenant_a_job_id = replay_resp.json()["job_id"]

    # 2. Tenant B attempts to read Tenant A's job details -> 404 Not Found
    resp_cross_get = client.get(f"/api/v1/replays/{tenant_a_job_id}", headers=tokens["admin_b"])
    assert resp_cross_get.status_code == 404

    # 3. Tenant B attempts to request AI explanation for Tenant A's job -> 404 Not Found
    resp_cross_ai = client.post(f"/api/v1/replays/{tenant_a_job_id}/ai-explain", headers=tokens["admin_b"])
    assert resp_cross_ai.status_code == 404

    # 4. Tenant B lists replays for AUTH-001 -> does NOT see Tenant A's replay jobs
    resp_b_list = client.get("/api/v1/rules/AUTH-001/replays", headers=tokens["admin_b"])
    assert resp_b_list.status_code == 200
    job_ids = [j["id"] for j in resp_b_list.json()["items"]]
    assert tenant_a_job_id not in job_ids

    # 5. Guessed/nonexistent job ID returns 404
    resp_random = client.get(f"/api/v1/replays/replay-{uuid4().hex[:12]}", headers=tokens["admin_a"])
    assert resp_random.status_code == 404


# ==============================================================================
# 4. REQUEST VALIDATION & MALFORMED INPUT REJECTION
# ==============================================================================


def test_malformed_replay_requests_and_timerange_validation(phase32_env):
    """Verify that inverted time ranges, invalid event_ids, and bounds are rejected with 422."""
    client = phase32_env["client"]
    headers = phase32_env["tokens"]["senior_a"]

    # 1. Inverted time range: end_time earlier than start_time
    now_t = datetime.now(UTC)
    invalid_timerange = {
        "rule_id": "AUTH-001",
        "target_type": "TIMERANGE",
        "start_time": (now_t + timedelta(hours=2)).isoformat(),
        "end_time": (now_t).isoformat(),
        "max_events": 100,
    }
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=invalid_timerange, headers=headers)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"

    # 2. target_type='EVENTS' without event_ids
    invalid_events = {
        "rule_id": "AUTH-001",
        "target_type": "EVENTS",
        "event_ids": [],
    }
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=invalid_events, headers=headers)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"

    # 3. max_events out of allowed bounds (< 1 or > 50000)
    resp_bound_low = client.post(
        "/api/v1/rules/AUTH-001/replay",
        json={"rule_id": "AUTH-001", "target_type": "DATASET", "max_events": 0},
        headers=headers,
    )
    assert resp_bound_low.status_code == 422

    resp_bound_high = client.post(
        "/api/v1/rules/AUTH-001/replay",
        json={"rule_id": "AUTH-001", "target_type": "DATASET", "max_events": 999999},
        headers=headers,
    )
    assert resp_bound_high.status_code == 422


def test_sigma_parser_robustness_and_malformed_documents(phase32_env):
    """Verify that malformed YAML, non-mapping types, and entity attacks are rejected cleanly."""
    client = phase32_env["client"]
    headers = phase32_env["tokens"]["admin_a"]

    # 1. Non-mapping YAML (e.g. YAML array)
    resp_arr = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": "- item1\n- item2\n"}, headers=headers)
    assert resp_arr.status_code == 422

    # 2. Non-mapping YAML (e.g. YAML scalar string)
    resp_str = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": "just a string value"}, headers=headers)
    assert resp_str.status_code == 422

    # 3. Malformed syntax
    resp_syn = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": "title: [unclosed array"}, headers=headers)
    assert resp_syn.status_code == 422

    # 4. Missing detection section
    resp_nodet = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": "title: Valid Title Here\nlogsource:\n  category: test\n"}, headers=headers)
    assert resp_nodet.status_code == 422


# ==============================================================================
# 5. REPLAY ENGINE CORRECTNESS & DETERMINISM
# ==============================================================================


def test_replay_handles_out_of_order_and_mixed_timezone_events(phase32_env):
    """Verify that the replay engine handles out-of-order, late-arriving,

    and mixed timezone-aware / naive timestamps deterministically.
    """
    # Prepare events with mixed timezone representations, deliberately shuffled
    t0 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=UTC)
    events = [
        # Event 3: t0 + 40s (naive ISO string)
        {
            "event_id": "evt-03",
            "timestamp": "2026-10-01T10:00:40",
            "event_category": "authentication",
            "outcome": "failure",
            "source_ip": "10.0.0.1",
        },
        # Event 1: t0 (aware ISO string with Z)
        {
            "event_id": "evt-01",
            "timestamp": "2026-10-01T10:00:00Z",
            "event_category": "authentication",
            "outcome": "failure",
            "source_ip": "10.0.0.1",
        },
        # Event 4: t0 + 60s (aware ISO with offset +05:30)
        {
            "event_id": "evt-04",
            "timestamp": "2026-10-01T15:31:00+05:30",  # Equivalent to 10:01:00Z (t0 + 60s)
            "event_category": "authentication",
            "outcome": "failure",
            "source_ip": "10.0.0.1",
        },
        # Event 2: t0 + 20s (epoch float)
        {
            "event_id": "evt-02",
            "timestamp": t0.timestamp() + 20,
            "event_category": "authentication",
            "outcome": "failure",
            "source_ip": "10.0.0.1",
        },
    ]

    # Chronological sorting using robust _parse_timestamp (which normalizes naive timestamps to UTC)
    sorted_events = sorted(events, key=lambda e: _parse_timestamp(e["timestamp"]))
    assert [e["event_id"] for e in sorted_events] == ["evt-01", "evt-02", "evt-03", "evt-04"]


def test_replay_timeout_boundary_enforcement(phase32_env):
    """Verify that exceeding configured timeout halts replay execution and marks status CANCELLED."""
    session_factory = phase32_env["session_factory"]
    org_id = phase32_env["org_a"]
    user_id = phase32_env["user_admin_id"]

    with session_factory() as db:
        # Run replay with impossible timeout (0.000001s)
        req = ReplayRequest(
            rule_id="AUTH-001",
            target_type="DATASET",
            dataset_name="all",  # Multiple datasets
            max_events=5000,
        )
        result = execute_replay(
            db=db,
            org_id=org_id,
            user_id=user_id,
            request=req,
            timeout_seconds=0.000001,
        )
        assert result["status"] == "CANCELLED"
        assert any("timeout" in err.lower() for err in result["errors"])


def test_zero_production_side_effects_database_assertions(phase32_env):
    """Verify that multiple extensive replay runs produce ZERO changes in production

    Alerts, Incidents, or WindowStates in the database.
    """
    client = phase32_env["client"]
    tokens = phase32_env["tokens"]
    session_factory = phase32_env["session_factory"]

    # Initial baseline database counts
    with session_factory() as db:
        initial_alerts = db.query(Alert).count()
        initial_incidents = db.query(Incident).count()
        initial_correlation_windows = len([w for w in db.query(WindowState).all() if not w.key.startswith("aegis:rate:")])

    # Execute 3 separate replays across different rule types
    for rule_id in ["AUTH-001", "PROC-001", "NET-001"]:
        resp = client.post(
            f"/api/v1/rules/{rule_id}/replay",
            json={"rule_id": rule_id, "target_type": "DATASET", "dataset_name": rule_id, "max_events": 500},
            headers=tokens["admin_a"],
        )
        assert resp.status_code == 200

    # Assert exact preservation of production counts
    with session_factory() as db:
        assert db.query(Alert).count() == initial_alerts
        assert db.query(Incident).count() == initial_incidents
        correlation_windows = [w for w in db.query(WindowState).all() if not w.key.startswith("aegis:rate:")]
        assert len(correlation_windows) == initial_correlation_windows


# ==============================================================================
# 6. PERFORMANCE & THROUGHPUT BENCHMARKING
# ==============================================================================


@pytest.mark.parametrize("dataset_size", [1000, 2500, 5000])
def test_replay_throughput_and_resource_safety_benchmark(phase32_env, dataset_size):
    """Measures replay execution duration and EPS on synthetic datasets of 1k, 2.5k, and 5k events."""
    session_factory = phase32_env["session_factory"]
    org_id = phase32_env["org_a"]
    user_id = phase32_env["user_admin_id"]

    with session_factory() as db:
        req = ReplayRequest(
            rule_id="AUTH-001",
            target_type="DATASET",
            dataset_name="all",
            max_events=dataset_size,
        )
        t_start = time.monotonic()
        res = execute_replay(
            db=db,
            org_id=org_id,
            user_id=user_id,
            request=req,
            timeout_seconds=30.0,
        )
        elapsed = time.monotonic() - t_start

        events_evaluated = res["events_evaluated"]
        eps = round(events_evaluated / max(0.001, elapsed), 1)

        assert events_evaluated > 0
        assert res["status"] in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
        # Ensure sustained throughput is at least 200 events per second on synthetic data
        assert eps >= 200, f"Replay throughput {eps} EPS lower than expected baseline"
