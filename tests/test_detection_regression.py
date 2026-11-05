"""Automated detection regression suite and multi-rule coverage validation.

Exercises:
1. Complete 34-rule matrix against all labelled attack and benign control scenarios.
2. Zero missed attack detections across all bundled threat categories.
3. Zero false-positive candidate detections across all benign baseline sequences.
4. Evidence structure validation: why, condition, matched fields, measured values, event IDs.
5. Boundary conditions: duplicate events, timezone-naive stamps, cross-tenant isolation,
   oversized exports, and malformed inputs.
6. Sensitivity and regression protection when detection thresholds are altered.
"""

from __future__ import annotations

import copy

import pytest

from aegis.replay import get_labelled_dataset
from aegis.rule_checks import fixtures
from aegis.rules import builtin_rules
from aegis.tuning import run_simulation


def test_full_detection_matrix_all_rules_against_bundled_corpus():
    """Evaluate all 34 bundled detection rules against the complete labelled scenario corpus."""
    rules = builtin_rules()
    assert len(rules) == 34, f"Expected 34 bundled rules, found {len(rules)}"
    all_fixtures = fixtures()
    assert len(all_fixtures) == 34, f"Expected 34 bundled fixtures, found {len(all_fixtures)}"

    dataset_events = get_labelled_dataset("all", "regression-lab")
    assert len(dataset_events) > 400

    result = run_simulation(dataset_events, rules, "regression-lab", labelled_fixture=True)

    assert result["errors"] == [], f"Simulation encountered unexpected errors: {result['errors']}"
    assert result["events_processed"] == len(dataset_events)
    assert result["fixture_quality"] is not None

    quality = result["fixture_quality"]
    assert quality["missed_attack_rules"] == [], (
        f"Regressions detected: Attack scenarios were missed for: {quality['missed_attack_rules']}"
    )
    assert quality["false_positive_candidates"] == [], (
        f"Regressions detected: False positive candidates found: {quality['false_positive_candidates']}"
    )
    assert len(quality["scenarios_evaluated"]) == 34


@pytest.mark.parametrize(
    "rule_prefix",
    ["AUTH", "PRIV", "PROC", "PERSIST", "NET", "WEB", "DATA", "CLOUD", "CORR"],
)
def test_category_rule_isolation_and_evidence(rule_prefix: str):
    """Verify each detection category produces valid evidence on attack and zero matches on benign."""
    category_fixtures = [k for k in fixtures() if k.startswith(rule_prefix)]
    assert category_fixtures, f"No fixtures found for category {rule_prefix}"

    for fixture_id in category_fixtures:
        rule_id = f"AEGIS-{fixture_id}"
        matching_rules = [r for r in builtin_rules() if r.id == rule_id]
        assert len(matching_rules) == 1, f"Rule {rule_id} not found"
        rule = matching_rules[0]

        events = get_labelled_dataset(fixture_id, "category-lab")
        result = run_simulation(events, [rule], "category-lab", labelled_fixture=True)

        assert result["errors"] == []
        assert result["rule_match_counts"][rule_id] >= 1
        quality = result["fixture_quality"]
        assert quality is not None
        assert quality["missed_attack_rules"] == []
        assert quality["false_positive_candidates"] == []

        # Validate structured evidence on positive matches
        match = result["matches"][0]
        assert match["rule_id"] == rule_id
        evidence = match["evidence"]
        assert "why" in evidence and evidence["why"]
        assert "condition" in evidence and isinstance(evidence["condition"], dict)
        assert "matched_fields" in evidence and isinstance(evidence["matched_fields"], list)
        assert "event_ids" in evidence and len(evidence["event_ids"]) >= 1
        assert "state_key" in evidence and len(evidence["state_key"]) == 64


def test_boundary_duplicate_events_skipped():
    """Duplicate event IDs within a batch are recorded and skipped without corrupting state."""
    events = get_labelled_dataset("AUTH-001", "lab")[:5]
    for ev in events:
        ev.pop("_ground_truth", None)
        ev.pop("_target_rule", None)

    # Re-insert the first event at the end
    duplicate = dict(events[0])
    batch = [*events, duplicate]

    rule = builtin_rules()[0]
    result = run_simulation(batch, [rule], "lab")

    assert result["events_processed"] == 5
    assert len(result["errors"]) == 1
    assert "Duplicate event ID" in result["errors"][0]["error"]


def test_boundary_missing_timezone_and_cross_tenant_rejection():
    """Timezone-naive timestamps, missing explicit timestamps, and mismatched tenant IDs are rejected."""
    rule = builtin_rules()[0]
    base_event = dict(get_labelled_dataset("AUTH-001", "tenant-target")[0])
    base_event.pop("_ground_truth", None)
    base_event.pop("_target_rule", None)

    # 1. Missing timezone on normalized event
    naive_event = dict(base_event, event_id="naive-01", timestamp="2026-10-01T12:00:00")

    # 2. EventInput missing explicit timestamp
    no_stamp_input = {
        "source": "lab",
        "raw_event": {"action": "login"},
    }

    # 3. Cross-tenant event
    foreign_event = dict(base_event, event_id="foreign-01", organization_id="tenant-other")

    result = run_simulation([naive_event, no_stamp_input, foreign_event], [rule], "tenant-target")
    assert result["events_processed"] == 0
    assert len(result["errors"]) == 3
    err_msgs = [e["error"] for e in result["errors"]]
    assert any("Event requires an ID and timezone-aware timestamp" in m for m in err_msgs)
    assert any("Offline events require an explicit timestamp" in m for m in err_msgs)
    assert any("Event belongs to another tenant" in m for m in err_msgs)


def test_boundary_oversized_export_rejection():
    """Simulation strictly enforces a 10,000 event limit to bound resource consumption."""
    dummy_event = {
        "event_id": "dummy-01",
        "timestamp": "2026-10-01T12:00:00Z",
        "source": "lab",
        "raw_event": {"action": "test"},
    }
    with pytest.raises(ValueError, match="at most 10000 events"):
        run_simulation([dummy_event] * 10001, builtin_rules()[:1], "lab")


def test_regression_detection_on_altered_threshold():
    """Modifying rule conditions must trigger measurable detection regressions."""
    rule = copy.deepcopy(builtin_rules()[0])
    events = get_labelled_dataset("AUTH-001", "lab")

    # Baseline pass
    baseline = run_simulation(events, [rule], "lab", labelled_fixture=True)
    assert baseline["fixture_quality"]["missed_attack_rules"] == []
    assert baseline["fixture_quality"]["false_positive_candidates"] == []

    # Regression A: Increasing threshold causes missed attack
    rule.condition.count = 11
    missed = run_simulation(events, [rule], "lab", labelled_fixture=True)
    assert missed["fixture_quality"]["missed_attack_rules"] == [rule.id]

    # Regression B: Lowering threshold causes false-positive candidate detection on benign control
    rule.condition.count = 9
    noisy = run_simulation(events, [rule], "lab", labelled_fixture=True)
    assert len(noisy["fixture_quality"]["false_positive_candidates"]) == 1
    assert noisy["fixture_quality"]["false_positive_candidates"][0]["rule_id"] == rule.id
