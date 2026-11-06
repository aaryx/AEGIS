import copy
import json

import pytest
from typer.testing import CliRunner

from aegis.cli import app
from aegis.replay import get_labelled_dataset
from aegis.rules import builtin_rules
from aegis.tuning import run_simulation


def test_threshold_fixture_and_tuning():
    rule = builtin_rules()[0]
    events = get_labelled_dataset("AUTH-001", "a")
    original = copy.deepcopy(events)
    result = run_simulation(events, [rule], "a", labelled_fixture=True)
    assert result["events_processed"] == 19
    assert result["rule_match_counts"] == {rule.id: 1}
    assert result["fixture_quality"]["missed_attack_rules"] == []
    assert result["fixture_quality"]["false_positive_candidates"] == []
    assert len(result["matches"][0]["evidence"]["event_ids"]) == 10
    assert events == original
    rule.condition.count = 11
    missed = run_simulation(events, [rule], "a", labelled_fixture=True)
    assert missed["fixture_quality"]["missed_attack_rules"] == [rule.id]
    rule.condition.count = 9
    noisy = run_simulation(events, [rule], "a", labelled_fixture=True)
    assert len(noisy["fixture_quality"]["false_positive_candidates"]) == 1


def test_empty_malformed_and_tenant_isolation():
    rule = builtin_rules()[0]
    empty = run_simulation([], [rule], "a")
    assert empty["detections_generated"] == empty["events_processed"] == 0
    assert empty["fixture_quality"] is None
    events = get_labelled_dataset("AUTH-001", "a")[:10]
    for event in events:
        event.pop("_ground_truth")
        event.pop("_target_rule")
    events[-1]["organization_id"] = "b"
    result = run_simulation([*events, None, {"timestamp": "bad"}], [rule], "a")
    assert result["events_processed"] == 9
    assert result["detections_generated"] == 0
    assert len(result["errors"]) == 3
    events[-1]["organization_id"] = "a"
    assert run_simulation(events, [rule], "a")["detections_generated"] == 1
    assert run_simulation(events[:1], [rule], "a")["detections_generated"] == 0


def test_cli_offline_no_side_effects(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline simulator attempted external IO")

    monkeypatch.setattr("aegis.cli.call", forbidden)
    monkeypatch.setattr("aegis.cli.send_events", forbidden)
    monkeypatch.setattr("sqlalchemy.engine.Engine.connect", forbidden)
    monkeypatch.setattr("httpx.Client.request", forbidden)
    result = CliRunner().invoke(app, ["--format", "json", "rules", "simulate", "--dataset", "AUTH-001"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["detections_generated"] == 1
    assert report["processing_seconds"] >= 0
    path = tmp_path / "events.json"
    path.write_text(json.dumps([{
        "source": "lab", "timestamp": "2026-10-01T12:00:00Z",
        "raw_event": {"host": "LAB", "action": "sudo"},
    }, None]), encoding="utf-8")
    result = CliRunner().invoke(app, ["rules", "simulate", "--events", str(path)])
    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["events_processed"] == 1
    assert report["rule_match_counts"]["AEGIS-PRIV-001"] == 1
    assert report["fixture_quality"] is None


@pytest.mark.parametrize("args", [[], ["--dataset", "typo"], ["--dataset", "AUTH-001", "--events", "x"]])
def test_cli_input_errors(args):
    result = CliRunner().invoke(app, ["rules", "simulate", *args])
    assert result.exit_code == 2


def test_invalid_timestamp_duplicate_and_limits():
    event = get_labelled_dataset("AUTH-001", "a")[0]
    event.pop("_ground_truth")
    event.pop("_target_rule")
    invalid = dict(event, timestamp="2026-10-01T12:00:00")
    result = run_simulation([event, event, invalid], builtin_rules(), "a")
    assert len(result["errors"]) == 2
    with pytest.raises(ValueError, match="10000"):
        run_simulation([event] * 10001, builtin_rules(), "a")


def test_evaluation_error_withholds_quality(monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("evaluation failed")

    monkeypatch.setattr("aegis.tuning.evaluate", fail)
    result = run_simulation(get_labelled_dataset("AUTH-001", "a"),
                            [builtin_rules()[0]], "a", labelled_fixture=True)
    assert len(result["errors"]) == 19
    assert result["fixture_quality"] is None


def test_cli_candidate_and_empty_file(tmp_path):
    candidate = builtin_rules()[0].model_dump()
    candidate["condition"]["count"] = 11
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(candidate), encoding="utf-8")
    result = CliRunner().invoke(app, ["rules", "simulate", "--dataset", "AUTH-001", "--rule", str(path)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["fixture_quality"]["missed_attack_rules"] == [candidate["id"]]
    path.write_text("[]", encoding="utf-8")
    result = CliRunner().invoke(app, ["rules", "simulate", "--events", str(path)])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["events_processed"] == 0


def test_metadata_fixture_net003():
    result = CliRunner().invoke(app, ["--format", "json", "rules", "simulate", "--dataset", "NET-003"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["detections_generated"] == 1
    assert report["rule_match_counts"]["AEGIS-NET-003"] == 1
    assert report["fixture_quality"]["missed_attack_rules"] == []
    assert report["fixture_quality"]["false_positive_candidates"] == []


def test_whitespace_event_id_and_empty_tenant():
    rule = builtin_rules()[0]
    with pytest.raises(ValueError, match="Tenant must not be empty"):
        run_simulation([], [rule], "   ")
    result_cli = CliRunner().invoke(app, ["rules", "simulate", "--dataset", "AUTH-001", "--tenant", "   "])
    assert result_cli.exit_code == 2

    event = get_labelled_dataset("AUTH-001", "a")[0]
    event.pop("_ground_truth")
    event.pop("_target_rule")
    blank_id = dict(event, event_id="   ")
    res = run_simulation([blank_id], [rule], "a")
    assert len(res["errors"]) == 1
    assert "Event requires an ID" in res["errors"][0]["error"]


def test_custom_events_with_candidate_rule_and_bom(tmp_path):
    candidate = builtin_rules()[0].model_dump()
    candidate["status"] = "DRAFT"
    candidate["lifecycle_stage"] = "DRAFT"
    rule_path = tmp_path / "candidate.yml"
    rule_path.write_text(json.dumps(candidate), encoding="utf-8")

    events = [
        {
            "source": "lab",
            "timestamp": f"2026-10-01T12:00:{i:02d}Z",
            "raw_event": {
                "host": "LAB",
                "source_ip": "192.0.2.100",
                "event_category": "authentication",
                "outcome": "failure",
            },
        }
        for i in range(10)
    ]
    events_path = tmp_path / "events_bom.json"
    events_path.write_bytes(b"\xef\xbb\xbf" + json.dumps(events).encode("utf-8"))

    result = CliRunner().invoke(app, ["--format", "json", "rules", "simulate", "--events", str(events_path), "--rule", str(rule_path)])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["events_processed"] == 10
    assert report["detections_generated"] == 1
    assert report["rule_match_counts"][candidate["id"]] == 1


def test_file_size_limits_and_malformed_yaml(tmp_path, monkeypatch):
    events_path = tmp_path / "events_big.json"
    events_path.write_text("[]", encoding="utf-8")
    rule_path = tmp_path / "rule_big.yml"
    rule_path.write_text("id: BIG", encoding="utf-8")

    from pathlib import Path
    orig_stat = Path.stat

    def fake_stat(self, *args, **kwargs):
        if self == events_path:
            return type("Stat", (), {"st_size": 21 * 1024 * 1024})()
        if self == rule_path:
            return type("Stat", (), {"st_size": 6 * 1024 * 1024})()
        return orig_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)

    res = CliRunner().invoke(app, ["rules", "simulate", "--events", str(events_path)])
    assert res.exit_code == 2

    res2 = CliRunner().invoke(app, ["rules", "simulate", "--dataset", "AUTH-001", "--rule", str(rule_path)])
    assert res2.exit_code == 2

    bad_rule = tmp_path / "bad_rule.yml"
    bad_rule.write_text("::invalid yaml::", encoding="utf-8")
    res3 = CliRunner().invoke(app, ["rules", "simulate", "--dataset", "AUTH-001", "--rule", str(bad_rule)])
    assert res3.exit_code == 2


def test_empty_events_labelled_fixture_quality():
    res = run_simulation([], [builtin_rules()[0]], "offline-lab", labelled_fixture=True)
    assert res["events_processed"] == 0
    assert res["fixture_quality"] is None


def test_cli_simulate_dataset_all():
    result = CliRunner().invoke(app, ["--format", "json", "rules", "simulate", "--dataset", "ALL"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["events_processed"] > 400
    assert len(report["fixture_quality"]["scenarios_evaluated"]) == 34
    assert report["fixture_quality"]["missed_attack_rules"] == []
    assert report["fixture_quality"]["false_positive_candidates"] == []


def test_raw_metadata_preservation_trust_boundary():
    """Raw metadata from untrusted input cannot overwrite parser, classification, or tenant provenance."""
    raw_event_with_spoofed_metadata = {
        "host": "SRV-TEST",
        "action": "sudo",
        "metadata": {
            "parser": "SpoofedCustomParser",
            "classification": "UNCLASSIFIED",
            "tenant": "attacker-tenant",
            "organization_id": "malicious-org",
            "source": "spoofed-source",
            "asset_criticality": "critical",
            "custom_analyst_tag": "tag-123",
        },
    }
    input_record = {
        "source": "lab",
        "timestamp": "2026-10-01T12:00:00Z",
        "raw_event": raw_event_with_spoofed_metadata,
    }
    rules = builtin_rules()
    res = run_simulation([input_record], rules, "test-tenant")
    assert res["events_processed"] == 1
    assert res["errors"] == []
    # Verify via detection match evidence if triggered, or inspect evaluation
    rule = next(r for r in rules if r.id == "AEGIS-PRIV-001")
    res_priv = run_simulation([input_record], [rule], "test-tenant")
    assert res_priv["detections_generated"] == 1
    # Verify that parser and classification retain trusted values
    from aegis.parsers import ParserRegistry
    from aegis.schemas import EventInput
    reg = ParserRegistry()
    incoming = EventInput.model_validate(input_record)
    norm = reg.normalize(incoming, "test-tenant")
    assert norm.metadata["parser"] == "JSONParser"
    assert norm.metadata["classification"] == "SENSITIVE"
    # And simulation succeeds without provenance hijacking
    assert res_priv["matches"][0]["rule_id"] == "AEGIS-PRIV-001"


