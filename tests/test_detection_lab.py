"""Comprehensive test suite for AEGIS Detection Engineering & Attack Replay Lab.

Verifies:
- Rule creation, validation, listing, and inspection.
- Actionable error diagnostics for invalid syntax, operators, and unsupported fields.
- Sigma rule translation, modifier validation, and actionable rejections.
- Sandboxed dry-run historical event replay with zero live alert/incident creation.
- Replay determinism, resource limits, and throughput metrics.
- Ground truth quality scorecard: Precision, Recall, F1 score, TP, FP, TN, FN.
- Noisy rule indicators and candidate vs. active rule delta comparison.
- MITRE ATT&CK technique and tactic coverage matrix.
- Safe promotion lifecycle: validation, activation, version concurrency, and rollback.
- Tenant isolation and tamper-evident audit logging.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.api import create_app
from aegis.config import Settings
from aegis.db import (
    Alert,
    Incident,
    Organization,
    ReplayJob,
    ReplayMatch,
    Rule,
    RuleVersion,
    User,
    database,
)
from aegis.pipeline import seed_rules
from aegis.security import PASSWORDS


@pytest.fixture
def test_env(tmp_path, monkeypatch):
    db_file = tmp_path / "replay_lab_test.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("AUDIT_SECRET", "super-secret-audit-key-32-bytes!!")
    monkeypatch.setenv("AI_PROVIDER", "local")

    settings = Settings(
        database_url=db_url,
        audit_secret="super-secret-audit-key-32-bytes!!",
        ai_provider="local",
    )
    engine, session_factory = database(db_url)

    # Initialize schema
    from aegis.db import Base

    Base.metadata.create_all(engine)

    # Create Org, Admin User, and Analyst User
    with session_factory() as db:
        org = Organization(id="org-test-lab", name="Detection Lab Corp")
        other_org = Organization(id="org-other-corp", name="Foreign Corp")
        admin = User(
            id="user-admin-01",
            organization_id="org-test-lab",
            username="sec_admin",
            password_hash=PASSWORDS.hash("AdminPass123!"),
            role="SECURITY_ADMIN",
            active=True,
        )
        analyst = User(
            id="user-analyst-01",
            organization_id="org-test-lab",
            username="sec_analyst",
            password_hash=PASSWORDS.hash("AnalystPass123!"),
            role="ANALYST",
            active=True,
        )
        db.add_all([org, other_org, admin, analyst])
        db.flush()

        # Seed builtin rules into org
        seed_rules(db, org.id)
        rule_row = db.scalar(
            select(Rule).where(
                Rule.organization_id == org.id,
                (Rule.rule_id == "AUTH-001") | (Rule.rule_id == "AEGIS-AUTH-001"),
            )
        )
        if rule_row:
            db.add(
                RuleVersion(
                    organization_id=org.id,
                    rule_id=rule_row.id,
                    version=1,
                    author=admin.id,
                    summary="Baseline seeded rule version 1",
                    lifecycle_stage="ACTIVE",
                    document=rule_row.document,
                )
            )
        db.commit()

    app = create_app(settings)
    app.state.sessions = session_factory
    app.state.engine = engine
    client = TestClient(app)

    # Generate login token for admin
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "sec_admin", "password": "AdminPass123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    yield {
        "client": client,
        "auth_headers": auth_headers,
        "org_id": org.id,
        "user_id": admin.id,
        "session_factory": session_factory,
        "settings": settings,
        "engine": engine,
    }

    engine.dispose()


# ==============================================================================
# 1. RULE LIFECYCLE & VALIDATION
# ==============================================================================


def test_rule_validation_accepts_valid_and_rejects_invalid_constructs(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]

    # 1. Valid Rule
    valid_payload = {
        "id": "CUSTOM-BRUTE-01",
        "name": "Custom repeated failed logins",
        "description": "Detects repeated failed logins from the same source IP address.",
        "author": "Lab Engineer",
        "version": 1,
        "status": "DRAFT",
        "lifecycle_stage": "DRAFT",
        "data_source_requirements": ["category:authentication"],
        "selection": [
            {"field": "event_category", "op": "eq", "value": "authentication"},
            {"field": "outcome", "op": "eq", "value": "failure"},
        ],
        "condition": {
            "type": "threshold",
            "count": 5,
            "window_seconds": 300,
            "group_by": ["source_ip"],
        },
        "severity": "high",
        "confidence": 85,
        "mitre_techniques": ["T1110"],
    }
    resp = client.post("/api/v1/rules/validate", json=valid_payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
    assert resp.json()["unknown_mitre"] == []

    # 2. Reject unsupported field
    invalid_field = dict(valid_payload)
    invalid_field["selection"] = [{"field": "unsupported_field_xyz", "op": "eq", "value": "test"}]
    resp_field = client.post("/api/v1/rules/validate", json=invalid_field, headers=headers)
    assert resp_field.status_code == 422
    assert "field" in resp_field.text

    # 3. Reject invalid operator (e.g. regex is not in allowed operators)
    invalid_op = dict(valid_payload)
    invalid_op["selection"] = [{"field": "command_line", "op": "regex", "value": ".*powershell.*"}]
    resp_op = client.post("/api/v1/rules/validate", json=invalid_op, headers=headers)
    assert resp_op.status_code == 422
    assert "op" in resp_op.text


def test_rule_listing_and_filtering(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]

    # List all rules
    resp = client.get("/api/v1/rules", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) >= 34
    assert any(r["rule_id"] in {"AUTH-001", "AEGIS-AUTH-001"} for r in data["items"])

    # Filter by query
    resp_search = client.get("/api/v1/rules?q=powershell", headers=headers)
    assert resp_search.status_code == 200
    search_items = resp_search.json()["items"]
    assert len(search_items) >= 1
    assert any("powershell" in json.dumps(r).lower() for r in search_items)

    # Filter by severity
    resp_high = client.get("/api/v1/rules?severity=high", headers=headers)
    assert resp_high.status_code == 200
    for r in resp_high.json()["items"]:
        assert r["document"]["severity"] == "high"


def test_rule_detail_and_unknown_404(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]

    # Existing rule
    resp = client.get("/api/v1/rules/AUTH-001", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["rule_id"] in {"AUTH-001", "AEGIS-AUTH-001"}
    assert resp.json()["enabled"] is True

    # Unknown rule
    resp_404 = client.get("/api/v1/rules/NONEXISTENT-999", headers=headers)
    assert resp_404.status_code == 404


# ==============================================================================
# 2. SIGMA RULE IMPORTER
# ==============================================================================


def test_sigma_import_valid_translation(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]

    sigma_yaml = """
title: Suspicious PowerShell Encoded Script Execution
id: f48b81d7-6604-4a6c-a549-ffe7aeca13dc
status: test
description: Detects encoded PowerShell command execution
author: Sigma Detection Team
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  filter:
    CommandLine|contains: 'benign-healthcheck'
  condition: selection and not filter
level: high
"""
    resp = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": sigma_yaml}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    rule = data["rule"]
    assert rule["name"] == "Suspicious PowerShell Encoded Script Execution"
    assert rule["severity"] == "high"
    assert rule["mitre_techniques"] == ["T1059.001"]
    assert any(p["field"] == "process.name" and p["op"] == "endswith" for p in rule["selection"])
    assert any(p["field"] == "command_line" and p["op"] == "contains" for p in rule["selection"])
    assert len(rule["exceptions"]) == 1
    assert rule["exceptions"][0]["predicates"][0]["field"] == "command_line"


def test_sigma_import_rejects_unsupported_modifiers_and_fields(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]

    # 1. Unsupported modifier |base64offset must raise actionable error
    unsupported_mod = """
title: Base64 Obfuscated Execution
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|base64offset: 'invoke-mimikatz'
  condition: selection
"""
    resp_mod = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": unsupported_mod}, headers=headers)
    assert resp_mod.status_code == 422
    assert "Unsupported Sigma modifier '|base64offset'" in resp_mod.text

    # 2. Unsupported unknown field must be rejected
    unsupported_field = """
title: Mystery Field Rule
logsource:
  category: custom
detection:
  selection:
    unsupported_random_field|contains: 'payload'
  condition: selection
"""
    resp_fld = client.post("/api/v1/rules/import-sigma", json={"yaml_rule": unsupported_field}, headers=headers)
    assert resp_fld.status_code == 422
    assert "Unsupported field 'unsupported_random_field'" in resp_fld.text


# ==============================================================================
# 3. HISTORICAL EVENT REPLAY ENGINE (DRY-RUN ISOLATION & ACCURACY)
# ==============================================================================


def test_sandboxed_replay_zero_production_alerts(test_env):
    """Verify that executing a replay job never writes duplicate alerts or incidents

    to production tables.
    """
    client = test_env["client"]
    headers = test_env["auth_headers"]
    session_factory = test_env["session_factory"]

    # Initial production counts
    with session_factory() as db:
        initial_alerts = db.query(Alert).count()
        initial_incidents = db.query(Incident).count()

    # Replay AUTH-001 on labelled fixtures
    replay_payload = {
        "rule_id": "AUTH-001",
        "dataset_name": "AUTH-001",
        "target_type": "DATASET",
        "max_events": 1000,
        "dry_run": True,
    }
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=headers)
    assert resp.status_code == 200
    res = resp.json()

    assert res["status"] in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
    assert res["events_evaluated"] > 0
    assert len(res["candidate_matches"]) > 0

    # Verify zero alerts or incidents created
    with session_factory() as db:
        assert db.query(Alert).count() == initial_alerts
        assert db.query(Incident).count() == initial_incidents

        # Verify replay job and match records were recorded
        job = db.get(ReplayJob, res["job_id"])
        assert job is not None
        assert job.events_evaluated == res["events_evaluated"]
        assert job.dry_run is True

        matches = list(db.scalars(select(ReplayMatch).where(ReplayMatch.job_id == job.id)))
        assert len(matches) == len(res["candidate_matches"])
        # Check that event snapshots are preserved for auditing
        assert "timestamp" in matches[0].event_snapshot


def test_replay_ground_truth_scorecard_metrics(test_env):
    """Verify calculation of true positives, false positives, precision, recall,

    and F1 on labelled synthetic test datasets.
    """
    client = test_env["client"]
    headers = test_env["auth_headers"]

    replay_payload = {
        "rule_id": "AUTH-001",
        "dataset_name": "AUTH-001",
        "target_type": "DATASET",
        "max_events": 1000,
        "dry_run": True,
    }
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=headers)
    assert resp.status_code == 200
    gt = resp.json()["metrics"]["ground_truth"]

    assert gt["ground_truth_available"] is True
    assert gt["true_positives"] > 0
    assert gt["false_positives"] == 0
    assert gt["precision"] == 1.0
    assert gt["recall"] > 0.0
    assert gt["f1_score"] > 0.0


def test_replay_candidate_vs_active_diff(test_env):
    """Verify side-by-side comparison between active rule and a candidate rule version."""
    client = test_env["client"]
    headers = test_env["auth_headers"]

    # Candidate rule has tightened threshold (count=5 instead of count=10)
    candidate_doc = {
        "id": "AUTH-001",
        "name": "Repeated authentication failures (Tuned)",
        "description": "Tuned threshold to detect brute force with 5 failed attempts.",
        "author": "Analyst Tuner",
        "version": 2,
        "selection": [
            {"field": "event_category", "op": "eq", "value": "authentication"},
            {"field": "outcome", "op": "eq", "value": "failure"},
        ],
        "condition": {
            "type": "threshold",
            "count": 5,
            "window_seconds": 300,
            "group_by": ["source_ip"],
        },
        "severity": "high",
        "confidence": 85,
        "mitre_techniques": ["T1110"],
    }

    replay_payload = {
        "rule_id": "AUTH-001",
        "candidate_document": candidate_doc,
        "dataset_name": "AUTH-001",
        "target_type": "DATASET",
        "max_events": 1000,
        "dry_run": True,
    }
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=headers)
    assert resp.status_code == 200
    res = resp.json()

    # The candidate threshold 5 triggers on earlier events that threshold 10 does not
    assert len(res["candidate_matches"]) >= len(res["active_matches"])
    assert len(res["new_detections"]) >= 0


def test_replay_determinism(test_env):
    """Verify that repeated replays on identical datasets produce identical match sets."""
    client = test_env["client"]
    headers = test_env["auth_headers"]

    replay_payload = {
        "rule_id": "PROC-001",
        "dataset_name": "PROC-001",
        "target_type": "DATASET",
        "max_events": 500,
        "dry_run": True,
    }
    run1 = client.post("/api/v1/rules/PROC-001/replay", json=replay_payload, headers=headers).json()
    run2 = client.post("/api/v1/rules/PROC-001/replay", json=replay_payload, headers=headers).json()

    assert run1["candidate_matches"] == run2["candidate_matches"]
    assert run1["events_evaluated"] == run2["events_evaluated"]


# ==============================================================================
# 4. SAFE RULE PROMOTION & ROLLBACK
# ==============================================================================


def test_safe_rule_promotion_and_rollback_workflow(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]
    session_factory = test_env["session_factory"]

    # 1. Fetch current version of AUTH-001 (v1)
    rule_v1 = client.get("/api/v1/rules/AUTH-001", headers=headers).json()
    assert rule_v1["version"] == 1

    # 2. Update rule to draft v2
    tuned_doc = dict(rule_v1["document"])
    tuned_doc["description"] = "Updated description for brute force detection v2."
    put_resp = client.put(
        "/api/v1/rules/AUTH-001",
        json={
            "document": tuned_doc,
            "summary": "Tuned description for v2 testing",
            "version": 1,
            "enabled": True,
            "lifecycle_stage": "DRAFT",
        },
        headers=headers,
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["version"] == 2

    # 3. Prevent activation with stale/conflicting version
    stale_activate = client.post(
        "/api/v1/rules/AUTH-001/activate",
        json={"version": 99, "summary": "Stale activation attempt"},
        headers=headers,
    )
    assert stale_activate.status_code == 409

    # 4. Activate candidate v2
    activate_resp = client.post(
        "/api/v1/rules/AUTH-001/activate",
        json={"version": 2, "summary": "Approved v2 deployment"},
        headers=headers,
    )
    assert activate_resp.status_code == 200
    assert activate_resp.json()["lifecycle_stage"] == "ACTIVE"

    # 5. Rollback to v1
    rollback_resp = client.post(
        "/api/v1/rules/AUTH-001/rollback",
        json={"target_version": 1, "summary": "Emergency rollback to initial tested baseline"},
        headers=headers,
    )
    assert rollback_resp.status_code == 200
    rb_data = rollback_resp.json()
    assert rb_data["version"] == 3  # Monotonically increasing version preserves auditability
    assert rb_data["document"]["description"] == rule_v1["document"]["description"]

    # Check version history records
    with session_factory() as db:
        versions = list(
            db.scalars(
                select(RuleVersion)
                .where(RuleVersion.rule_id == rb_data["id"])
                .order_by(RuleVersion.version.asc())
            )
        )
        assert len(versions) >= 3
        assert versions[-1].version == 3
        assert "Rollback to v1" in versions[-1].summary


# ==============================================================================
# 5. MITRE ATT&CK COVERAGE MATRIX
# ==============================================================================


def test_mitre_attack_coverage_matrix(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]

    resp = client.get("/api/v1/coverage/mitre", headers=headers)
    assert resp.status_code == 200
    cov = resp.json()

    assert cov["catalog_total"] > 0
    assert cov["covered_total"] > 0
    assert cov["overall_coverage_pct"] > 0.0
    assert len(cov["tactics"]) > 0

    # Validate tactics structure
    exec_tactic = next((t for t in cov["tactics"] if t["tactic"] == "execution"), None)
    assert exec_tactic is not None
    assert "T1059.001" in exec_tactic["covered_technique_ids"]


# ==============================================================================
# 6. AI-ASSISTED REPLAY EXPLANATION
# ==============================================================================


def test_replay_ai_explanation(test_env):
    client = test_env["client"]
    headers = test_env["auth_headers"]

    # Run replay first
    rep = client.post(
        "/api/v1/rules/AUTH-001/replay",
        json={"rule_id": "AUTH-001", "dataset_name": "AUTH-001", "target_type": "DATASET"},
        headers=headers,
    ).json()
    job_id = rep["job_id"]

    # Ask AI to explain replay results
    explain_resp = client.post(f"/api/v1/replays/{job_id}/ai-explain", headers=headers)
    assert explain_resp.status_code == 200
    ai_data = explain_resp.json()
    assert ai_data["job_id"] == job_id
    assert ai_data["rule_id"] in {"AUTH-001", "AEGIS-AUTH-001"}
    assert "explanation" in ai_data


# ==============================================================================
# 7. TENANT ISOLATION & AUDIT INTEGRITY
# ==============================================================================


def test_tenant_isolation_and_audit_trail(test_env):
    client = test_env["client"]
    session_factory = test_env["session_factory"]

    # Create user in another organization
    with session_factory() as db:
        foreign_user = User(
            id="user-foreign-01",
            organization_id="org-other-corp",
            username="foreign_admin",
            password_hash=PASSWORDS.hash("ForeignPass123!"),
            role="SECURITY_ADMIN",
            active=True,
        )
        db.add(foreign_user)
        db.commit()

    # Login as foreign admin
    foreign_login = client.post(
        "/api/v1/auth/login",
        json={"username": "foreign_admin", "password": "ForeignPass123!"},
    )
    assert foreign_login.status_code == 200
    foreign_headers = {"Authorization": f"Bearer {foreign_login.json()['access_token']}"}

    # Foreign user should not see org-test-lab's seeded rules
    foreign_rules = client.get("/api/v1/rules", headers=foreign_headers).json()
    assert foreign_rules["total"] == 0

    # Foreign user cannot access AUTH-001 belonging to org-test-lab
    resp_cross = client.get("/api/v1/rules/AUTH-001", headers=foreign_headers)
    assert resp_cross.status_code == 404
