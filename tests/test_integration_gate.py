"""Focused regression tests for CI integration release gate logic and failure behaviors."""

from pathlib import Path

import pytest

from aegis.db_safety import DatabaseSafetyError
from scripts.integration_gate import (
    DISTRIBUTED_TEST_NAMES,
    MANDATORY_INTEGRATION_TESTS,
    POSTGRES_MANDATORY_TESTS,
    parse_junit_report,
    prepare_test_database,
    verify_postgres_readiness,
    wait_for_port,
)


def test_mandatory_test_inventory_invariants():
    """Verify that mandatory test sets are well-defined, non-empty, and maintain expected partition invariants."""
    assert len(MANDATORY_INTEGRATION_TESTS) == 20
    assert len(DISTRIBUTED_TEST_NAMES) == 2
    assert len(POSTGRES_MANDATORY_TESTS) == 18
    assert DISTRIBUTED_TEST_NAMES.issubset(MANDATORY_INTEGRATION_TESTS)
    assert POSTGRES_MANDATORY_TESTS | DISTRIBUTED_TEST_NAMES == MANDATORY_INTEGRATION_TESTS


def test_parse_junit_report_all_passed(tmp_path: Path):
    """Verify structured parsing of an all-passed JUnit report."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" errors="0" failures="0" skipped="0" tests="3">
    <testcase classname="tests.test_database_safety" file="tests/test_database_safety.py" name="test_one" time="0.01" />
    <testcase classname="tests.test_postgres_integration" file="tests/test_postgres_integration.py" name="test_two" time="0.02" />
    <testcase classname="tests.test_phase4_postgres" file="tests/test_phase4_postgres.py" name="test_three" time="0.03" />
</testsuite>
"""
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(xml_content, encoding="utf-8")

    results = parse_junit_report(xml_path)
    assert results["total"] == 3
    assert results["passed"] == 3
    assert results["failed"] == 0
    assert results["errors"] == 0
    assert results["skipped"] == 0
    assert results["passed_names"] == {"test_one", "test_two", "test_three"}
    assert len(results["all_node_ids"]) == 3


def test_parse_junit_report_detects_skips_and_failures(tmp_path: Path):
    """Verify that skips, failures, and errors are identified and categorized."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="1" failures="1" skipped="1" tests="4">
    <testcase classname="tests.test_a" file="tests/test_a.py" name="test_pass" time="0.01" />
    <testcase classname="tests.test_a" file="tests/test_a.py" name="test_skip" time="0.01">
        <skipped message="Environment variable not set" />
    </testcase>
    <testcase classname="tests.test_b" file="tests/test_b.py" name="test_fail" time="0.01">
        <failure message="AssertionError: 1 != 2">Assertion details</failure>
    </testcase>
    <testcase classname="tests.test_c" file="tests/test_c.py" name="test_err" time="0.01">
        <error message="Fixture setup failed">Error details</error>
    </testcase>
  </testsuite>
</testsuites>
"""
    xml_path = tmp_path / "mixed_report.xml"
    xml_path.write_text(xml_content, encoding="utf-8")

    results = parse_junit_report(xml_path)
    assert results["total"] == 4
    assert results["passed"] == 1
    assert results["skipped"] == 1
    assert results["failed"] == 1
    assert results["errors"] == 1

    assert "test_skip" in results["skipped_dict"]
    assert "Environment variable not set" in results["skipped_dict"]["test_skip"]
    assert "test_fail" in results["failed_dict"]
    assert "AssertionError" in results["failed_dict"]["test_fail"]
    assert "test_err" in results["error_dict"]
    assert "Fixture setup failed" in results["error_dict"]["test_err"]


def test_parse_junit_report_missing_file():
    """Verify that parsing a non-existent report raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        parse_junit_report(Path("non_existent_results.xml"))


def test_wait_for_port_fails_on_closed_port():
    """Verify that wait_for_port returns False within the bounded timeout when port is closed."""
    # Port 59999 is closed on loopback
    assert wait_for_port("127.0.0.1", 59999, timeout_seconds=1) is False


def test_verify_postgres_readiness_fails_on_closed_port():
    """Verify that verify_postgres_readiness fails closed with a clear error when port is closed."""
    with pytest.raises(RuntimeError, match="PostgreSQL readiness verification failed"):
        verify_postgres_readiness("postgresql://aegis:test@127.0.0.1:59999/postgres", timeout_seconds=1)


def test_prepare_test_database_fails_closed_on_unsafe_production_url():
    """Verify that prepare_test_database rejects production database URLs before making connections."""
    unsafe_url = "postgresql+psycopg://aegis:secret@127.0.0.1:5432/aegis_production"
    admin_url = "postgresql+psycopg://aegis:secret@127.0.0.1:5432/postgres"
    with pytest.raises(DatabaseSafetyError):
        prepare_test_database(unsafe_url, admin_url, "aegis_production")
