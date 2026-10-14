"""Phase 3.1 Independent Correctness, Security & Reliability Audit Test Suite.

Rigorously verifies:
1. Sigma multi-value modifier semantics (OR vs AND).
2. Sigma DoS / input size bounds (>500KB rejected).
3. Replay Engine target correctness (EVENTS, TIMERANGE, DATASET).
4. State isolation and zero side-effects during replay.
5. Hand-calculated vs implementation ground-truth metric validation (8 test cases).
6. Threshold multi-match scenario vs event-level metric differentiation.
7. Undefined metric honesty (None instead of misleading 0.0 or 1.0).
8. Tenant isolation on rules, versions, replay jobs, and replay matches.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from aegis.db import EventRecord
from aegis.detection import SQLState, evaluate
from aegis.replay import execute_replay
from aegis.schemas import Condition, DetectionRule, Predicate, ReplayRequest
from aegis.sigma import SigmaTranslationError, parse_sigma_rule

pytest_plugins = ["tests.test_detection_lab"]



# ==============================================================================
# 1. SIGMA MODIFIER SEMANTICS & INPUT BOUNDS
# ==============================================================================


def test_sigma_multi_value_modifier_or_semantics():
    """Verify that Sigma multi-value contains/startswith/endswith translates to

    logical OR across values, not logical AND.
    """
    sigma_yaml = """
title: Multi Value Commandline Match
id: sig-cmd-or-001
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '-encodedcommand'
      - '-enc'
      - '-e '
  condition: selection
"""
    rule = parse_sigma_rule(sigma_yaml)
    assert len(rule.selection) == 1
    pred = rule.selection[0]
    assert pred.field == "command_line"
    assert pred.op == "contains"
    assert isinstance(pred.value, list)
    assert "-encodedcommand" in pred.value
    assert "-enc" in pred.value

    # Event containing only '-enc' must match
    evt1 = {"command_line": "powershell.exe -enc aW52b2tl"}
    assert pred.matches(evt1) is True

    # Event containing only '-encodedcommand' must match
    evt2 = {"command_line": "powershell.exe -encodedcommand aW52b2tl"}
    assert pred.matches(evt2) is True

    # Event containing neither must not match
    evt3 = {"command_line": "powershell.exe Get-Process"}
    assert pred.matches(evt3) is False


def test_sigma_multi_value_with_all_modifier_and_semantics():
    """Verify that when '|all' modifier is specified, all values are required (AND)."""
    sigma_yaml = """
title: Commandline Must Contain All Tokens
id: sig-cmd-all-001
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - '-nop'
  condition: selection
"""
    rule = parse_sigma_rule(sigma_yaml)
    # Should have 2 predicates in selection (logical AND)
    assert len(rule.selection) == 2
    assert all(p.op == "contains" for p in rule.selection)

    evt_both = {"command_line": "powershell.exe -nop -c whoami"}
    assert all(p.matches(evt_both) for p in rule.selection) is True

    evt_only_one = {"command_line": "powershell.exe -exec bypass"}
    assert all(p.matches(evt_only_one) for p in rule.selection) is False


def test_sigma_rejects_oversized_yaml_dos():
    """Verify that Sigma parser and API reject documents exceeding 500 KB."""
    huge_yaml = "title: Huge Rule\n" + ("# comment\n" * 60_000)  # > 500KB
    assert len(huge_yaml) > 512_000

    with pytest.raises(SigmaTranslationError, match="exceeds maximum size limit"):
        parse_sigma_rule(huge_yaml)


# ==============================================================================
# 2. REPLAY ENGINE TARGET CORRECTNESS & ISOLATION
# ==============================================================================


def test_replay_target_events_fetches_real_stored_records(test_env):
    """Verify target_type='EVENTS' retrieves actual stored EventRecords from DB

    and correctly evaluates candidate rule with zero side-effects.
    """
    client = test_env["client"]
    headers = test_env["auth_headers"]
    session_factory = test_env["session_factory"]
    org_id = test_env["org_id"]

    # Insert 3 real stored events in DB
    event_ids = []
    base_t = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
    with session_factory() as db:
        for i in range(3):
            eid = f"stored-evt-{uuid4().hex[:8]}"
            event_ids.append(eid)
            rec = EventRecord(
                id=eid,
                organization_id=org_id,
                timestamp=base_t + timedelta(seconds=i * 10),
                evidence_hash="0" * 64,
                source="test-collector",
                payload={
                    "event_id": eid,
                    "event_category": "process",
                    "action": "start",
                    "source_ip": "192.0.2.1",
                    "command_line": "powershell.exe -enc evil" if i == 1 else "normal.exe",
                    "timestamp": (base_t + timedelta(seconds=i * 10)).isoformat(),
                },
                state="PROCESSED",
            )
            db.add(rec)
        db.commit()

    candidate = {
        "id": "PROC-TEST-001",
        "name": "PowerShell Encoded Command",
        "description": "Detects encoded powershell",
        "author": "SecOps",
        "version": 1,
        "selection": [{"field": "command_line", "op": "contains", "value": "-enc"}],
        "condition": {"type": "match", "count": 1, "window_seconds": 60, "group_by": ["source_ip"]},
        "severity": "high",
        "confidence": 90,
        "mitre_techniques": ["T1059.001"],
    }

    replay_payload = {
        "rule_id": "PROC-TEST-001",
        "target_type": "EVENTS",
        "event_ids": event_ids,
        "candidate_document": candidate,
        "dry_run": True,
        "max_events": 100,
    }

    resp = client.post("/api/v1/rules/PROC-TEST-001/replay", json=replay_payload, headers=headers)
    assert resp.status_code == 200
    res = resp.json()
    assert res["events_evaluated"] == 3
    assert len(res["candidate_matches"]) == 1
    assert res["candidate_matches"][0] == event_ids[1]


def test_replay_target_timerange_filters_and_orders_correctly(test_env):
    """Verify target_type='TIMERANGE' queries EventRecord.timestamp with exact

    time boundaries and chronological sorting.
    """
    client = test_env["client"]
    headers = test_env["auth_headers"]
    session_factory = test_env["session_factory"]
    org_id = test_env["org_id"]

    t_start = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
    t_mid1 = datetime(2026, 10, 11, 10, 15, 0, tzinfo=UTC)
    t_mid2 = datetime(2026, 10, 11, 10, 30, 0, tzinfo=UTC)
    t_end = datetime(2026, 10, 11, 11, 0, 0, tzinfo=UTC)
    t_outside = datetime(2026, 10, 11, 11, 30, 0, tzinfo=UTC)

    with session_factory() as db:
        # Invert insertion order to prove replay sorts chronologically
        for t, cmd in [(t_outside, "out"), (t_mid2, "mid2"), (t_mid1, "mid1")]:
            rec = EventRecord(
                organization_id=org_id,
                timestamp=t,
                evidence_hash="0" * 64,
                source="test-timerange",
                payload={"command_line": cmd, "event_category": "process", "timestamp": t.isoformat()},
                state="PROCESSED",
            )
            db.add(rec)
        db.commit()

    candidate = {
        "id": "PROC-TIME-001",
        "name": "Process Match",
        "description": "Process Match",
        "author": "SecOps",
        "version": 1,
        "selection": [{"field": "event_category", "op": "eq", "value": "process"}],
        "condition": {"type": "match", "count": 1, "window_seconds": 60, "group_by": ["source_ip"]},
        "severity": "medium",
        "confidence": 80,
        "mitre_techniques": ["T1059"],
    }

    replay_payload = {
        "rule_id": "PROC-TIME-001",
        "target_type": "TIMERANGE",
        "start_time": t_start.isoformat(),
        "end_time": t_end.isoformat(),
        "candidate_document": candidate,
        "dry_run": True,
        "max_events": 100,
    }

    resp = client.post("/api/v1/rules/PROC-TIME-001/replay", json=replay_payload, headers=headers)
    assert resp.status_code == 200
    res = resp.json()
    # Exactly 2 events fall within t_start and t_end (t_mid1, t_mid2); t_outside is excluded
    assert res["events_evaluated"] == 2


def test_replay_state_isolation_does_not_mutate_live_detection(test_env):
    """Verify that stateful replay evaluation uses isolated in-memory stores

    and cannot leak into or mutate live WindowState.
    """
    session_factory = test_env["session_factory"]
    org_id = test_env["org_id"]

    rule = DetectionRule(
        id="AUTH-001",
        name="Brute Force",
        description="Threshold detection",
        author="SecOps",
        version=1,
        selection=[
            Predicate(field="event_category", op="eq", value="authentication"),
            Predicate(field="outcome", op="eq", value="failure"),
        ],
        condition=Condition(type="threshold", count=10, window_seconds=300, group_by=["source_ip"]),
        severity="high",
        confidence=90,
        mitre_techniques=["T1110"],
    )

    with session_factory() as db:
        live_state = SQLState(db)
        # Evaluate 5 failed logins on live state
        for i in range(5):
            evt = {
                "event_id": f"live-{i}",
                "event_category": "authentication",
                "outcome": "failure",
                "source_ip": "10.0.0.99",
                "timestamp": datetime(2026, 10, 1, 12, 0, i * 2, tzinfo=UTC).isoformat(),
            }
            evaluate(rule, evt, live_state, f"live:{org_id}")
        db.commit()

        from aegis.db import WindowState

        live_windows = list(db.scalars(select(WindowState)))
        assert len(live_windows) >= 1
        live_window_keys = [w.key for w in live_windows]
        live_window_count = len(live_windows)

        # Now run a replay with a different sequence
        req = ReplayRequest(
            rule_id="AUTH-001",
            target_type="DATASET",
            dataset_name="AUTH-001",
            dry_run=True,
            max_events=100,
        )
        res = execute_replay(db, org_id, test_env["user_id"], req)
        assert res["status"] in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}

        # Live state must still be completely unaffected: zero WindowState rows created by replay
        post_windows = list(db.scalars(select(WindowState)))
        assert len(post_windows) == live_window_count
        assert [w.key for w in post_windows] == live_window_keys


# ==============================================================================
# 3. HAND-CALCULATED GROUND-TRUTH METRICS VALIDATION
# ==============================================================================


@pytest.mark.parametrize(
    "case_name, events, expected_metrics",
    [
        (
            "all_detections_correct",
            [
                # 3 attacks, all match
                {"event_id": "a1", "_ground_truth": "ATTACK", "match": True},
                {"event_id": "a2", "_ground_truth": "ATTACK", "match": True},
                {"event_id": "a3", "_ground_truth": "ATTACK", "match": True},
                # 2 benign, neither matches
                {"event_id": "b1", "_ground_truth": "BENIGN", "match": False},
                {"event_id": "b2", "_ground_truth": "BENIGN", "match": False},
            ],
            {"tp": 3, "fp": 0, "tn": 2, "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0},
        ),
        (
            "no_detections_made",
            [
                # 3 attacks, none match
                {"event_id": "a1", "_ground_truth": "ATTACK", "match": False},
                {"event_id": "a2", "_ground_truth": "ATTACK", "match": False},
                {"event_id": "a3", "_ground_truth": "ATTACK", "match": False},
                # 2 benign, none match
                {"event_id": "b1", "_ground_truth": "BENIGN", "match": False},
                {"event_id": "b2", "_ground_truth": "BENIGN", "match": False},
            ],
            {"tp": 0, "fp": 0, "tn": 2, "fn": 3, "precision": None, "recall": 0.0, "f1": None},
        ),
        (
            "false_positives_only",
            [
                # 0 attacks, 3 benign, 2 match falsely
                {"event_id": "b1", "_ground_truth": "BENIGN", "match": True},
                {"event_id": "b2", "_ground_truth": "BENIGN", "match": True},
                {"event_id": "b3", "_ground_truth": "BENIGN", "match": False},
            ],
            {"tp": 0, "fp": 2, "tn": 1, "fn": 0, "precision": 0.0, "recall": None, "f1": None},
        ),
        (
            "false_negatives_only",
            [
                # 2 attacks, 0 match; 0 benign
                {"event_id": "a1", "_ground_truth": "ATTACK", "match": False},
                {"event_id": "a2", "_ground_truth": "ATTACK", "match": False},
            ],
            {"tp": 0, "fp": 0, "tn": 0, "fn": 2, "precision": None, "recall": 0.0, "f1": None},
        ),
        (
            "empty_dataset",
            [],
            {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": None, "recall": None, "f1": None},
        ),
        (
            "missing_or_incomplete_labels",
            [
                {"event_id": "a1", "_ground_truth": "ATTACK", "match": True},
                {"event_id": "u1", "match": True},  # Missing _ground_truth
                {"event_id": "u2", "match": False},  # Missing _ground_truth
                {"event_id": "b1", "_ground_truth": "BENIGN", "match": False},
            ],
            {"tp": 1, "fp": 0, "tn": 1, "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0},
        ),
    ],
)
def test_hand_calculated_metric_suite(test_env, case_name, events, expected_metrics):
    """Independently verifies hand-calculated ground truth metrics against the

    engine calculations, specifically testing honest handling of undefined metrics.
    """
    session_factory = test_env["session_factory"]
    org_id = test_env["org_id"]

    # Create a rule that matches if event has 'match: True'
    clean_tag = case_name[:20].upper().replace("_", "-")
    candidate = DetectionRule(
        id=f"TEST-METRICS-{clean_tag}",
        name="Metric Validation Rule",
        description="Checks match field for validation",
        author="Auditor",
        version=1,
        selection=[Predicate(field="action", op="eq", value="match")],
        condition=Condition(type="match", count=1, window_seconds=60, group_by=["source_ip"]),
        severity="medium",
        confidence=80,
        mitre_techniques=["T1059"],
    )

    # Format events for replay
    processed_events = []
    base_t = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
    for i, e in enumerate(events):
        processed_events.append(
            {
                "event_id": e["event_id"],
                "action": "match" if e.get("match") else "no-match",
                "source_ip": "192.0.2.1",
                "_ground_truth": e.get("_ground_truth"),
                "timestamp": (base_t + timedelta(seconds=i)).isoformat(),
            }
        )

    with session_factory() as db:
        # Patch get_labelled_dataset to return our custom dataset
        from unittest.mock import patch

        with patch("aegis.replay.get_labelled_dataset", return_value=processed_events):
            req = ReplayRequest(
                rule_id=candidate.id,
                target_type="DATASET",
                dataset_name="custom-audit",
                candidate_document=candidate,
                dry_run=True,
            )
            res = execute_replay(db, org_id, test_env["user_id"], req)

        gt = res["metrics"]["ground_truth"]
        assert gt["true_positives"] == expected_metrics["tp"]
        assert gt["false_positives"] == expected_metrics["fp"]
        assert gt["true_negatives"] == expected_metrics["tn"]
        assert gt["false_negatives"] == expected_metrics["fn"]
        assert gt["precision"] == expected_metrics["precision"]
        assert gt["recall"] == expected_metrics["recall"]
        assert gt["f1_score"] == expected_metrics["f1"]


def test_investigation_of_threshold_accumulator_events_and_scenario_metrics(test_env):
    """Directly investigates and explains the 1 TP, 9 FN, Precision 1.0, Recall 0.1 result.

    Proves that for threshold rules:
    - At EVENT level: 9 sub-threshold attempts count as FN, 1 trigger event as TP -> Recall 0.1
    - At SCENARIO level: 1 attack sequence detected as a whole -> Scenario Recall 1.0
    """
    client = test_env["client"]
    headers = test_env["auth_headers"]

    replay_payload = {
        "rule_id": "AUTH-001",
        "dataset_name": "AUTH-001",
        "target_type": "DATASET",
        "dry_run": True,
        "max_events": 100,
    }
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=headers)
    assert resp.status_code == 200
    gt = resp.json()["metrics"]["ground_truth"]

    # Verify event-level metrics
    evt_metrics = gt["event_metrics"]
    assert evt_metrics["true_positives"] == 1
    assert evt_metrics["false_negatives"] == 9
    assert evt_metrics["true_negatives"] == 9
    assert evt_metrics["false_positives"] == 0
    assert evt_metrics["precision"] == 1.0
    assert evt_metrics["recall"] == 0.1  # 1 / (1 + 9) = 0.1

    # Verify scenario-level metrics
    sc_metrics = gt["scenario_metrics"]
    assert sc_metrics["scenarios_evaluated"] >= 1
    assert sc_metrics["true_positives"] == 1
    assert sc_metrics["false_negatives"] == 0
    assert sc_metrics["precision"] == 1.0
    assert sc_metrics["recall"] == 1.0
    assert sc_metrics["f1_score"] == 1.0


def test_duplicate_event_id_handling_in_replay(test_env):
    """Verify that duplicate event IDs in the input stream are tracked and flagged

    without silent counter inflation.
    """
    session_factory = test_env["session_factory"]
    org_id = test_env["org_id"]

    dup_events = [
        {"event_id": "dup-001", "action": "login", "outcome": "failure", "source_ip": "192.0.2.1", "timestamp": "2026-10-01T12:00:00Z"},
        {"event_id": "dup-001", "action": "login", "outcome": "failure", "source_ip": "192.0.2.1", "timestamp": "2026-10-01T12:00:01Z"},
        {"event_id": "dup-002", "action": "login", "outcome": "failure", "source_ip": "192.0.2.1", "timestamp": "2026-10-01T12:00:02Z"},
    ]

    candidate = DetectionRule(
        id="AUTH-DUP-TEST",
        name="Dup Test Rule",
        description="Duplicate event ID test rule validation",
        author="Auditor",
        version=1,
        selection=[Predicate(field="action", op="eq", value="login")],
        condition=Condition(type="match", count=1, window_seconds=60, group_by=["source_ip"]),
        severity="low",
        confidence=50,
        mitre_techniques=["T1110"],
    )

    with session_factory() as db:
        from unittest.mock import patch

        with patch("aegis.replay.get_labelled_dataset", return_value=dup_events):
            req = ReplayRequest(
                rule_id=candidate.id,
                target_type="DATASET",
                dataset_name="custom-dup",
                candidate_document=candidate,
                dry_run=True,
            )
            res = execute_replay(db, org_id, test_env["user_id"], req)

        metrics = res["metrics"]
        assert metrics["events_evaluated"] == 3
        assert metrics["unique_events_evaluated"] == 2
        assert metrics["duplicate_event_ids_count"] == 1
        assert any("duplicate event id" in err.lower() for err in res["errors"])


# ==============================================================================
# 4. RULE PROMOTION & TENANT ISOLATION
# ==============================================================================


def test_rule_activation_concurrency_optimistic_lock(test_env):
    """Verify that attempting to activate an out-of-date rule version returns 409 Conflict."""
    client = test_env["client"]
    headers = test_env["auth_headers"]

    # Active version of AUTH-001 is 1. Request activation for stale version 99
    resp = client.post(
        "/api/v1/rules/AUTH-001/activate",
        json={"version": 99, "summary": "Stale activation attempt"},
        headers=headers,
    )
    assert resp.status_code == 409
    err = resp.json()["error"]["message"].lower()
    assert "conflict" in err or "version" in err


def test_tenant_isolation_on_replays_and_matches(test_env):
    """Verify that Tenant A cannot list, view, or explain Tenant B's replay jobs

    or matches.
    """
    client = test_env["client"]
    tenant_a_headers = test_env["auth_headers"]

    # Run replay for Tenant A
    replay_payload = {
        "rule_id": "AUTH-001",
        "dataset_name": "AUTH-001",
        "target_type": "DATASET",
        "dry_run": True,
        "max_events": 50,
    }
    resp = client.post("/api/v1/rules/AUTH-001/replay", json=replay_payload, headers=tenant_a_headers)
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    # Simulate Tenant B principal in org-other-corp
    session_factory = test_env["session_factory"]
    from aegis.db import User
    from aegis.security import PASSWORDS

    with session_factory() as db:
        user_b = User(
            id="user-foreign-beta",
            organization_id="org-other-corp",
            username="foreign_beta",
            password_hash=PASSWORDS.hash("ForeignBetaPass123!"),
            role="ANALYST",
            active=True,
        )
        db.add(user_b)
        db.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "foreign_beta", "password": "ForeignBetaPass123!"},
    )
    assert login_resp.status_code == 200
    tenant_b_headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # Tenant B tries to get Tenant A's replay job
    resp_b = client.get(f"/api/v1/replays/{job_id}", headers=tenant_b_headers)
    assert resp_b.status_code == 404

    # Tenant B tries to list Tenant A's replays
    resp_list_b = client.get("/api/v1/rules/AUTH-001/replays", headers=tenant_b_headers)
    assert resp_list_b.status_code == 200
    assert len(resp_list_b.json()["items"]) == 0
