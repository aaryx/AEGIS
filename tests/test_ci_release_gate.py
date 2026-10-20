"""Negative, boundary, and failure-mode validation for CI release gate (scripts/integration_gate.py).

Validates:
1. All services healthy and all 20 fixture cases passing -> Gate PASSES (exit 0).
2. PostgreSQL unavailable -> Gate FAILS (exit 1).
3. Redis unavailable -> Gate FAILS (exit 1).
4. OpenSearch unavailable -> Gate FAILS (exit 1).
5. Missing required configuration (.env absent or credentials missing) -> Gate FAILS (exit 1).
6. Deliberately failing integration test -> Gate FAILS (exit 1).
7. Deliberately skipped mandatory test -> Gate FAILS (exit 1).
8. No tests collected (passed < 20) -> Gate FAILS (exit 1).
9. Malformed or unexpected pytest output -> Gate FAILS (exit 1).
10. Pytest error during execution -> Gate FAILS (exit 1).
11. Secret preservation: Credentials are NEVER printed to stdout/stderr.
"""

import io
from unittest.mock import MagicMock, patch

import pytest

from scripts import integration_gate


@pytest.fixture
def mock_env_config(tmp_path, monkeypatch):
    """Provide a mock .env file with secret credentials."""
    env_file = tmp_path / ".env"
    secret_pass = "super-secret-pw-never-leak-999"
    env_file.write_text(
        f"POSTGRES_PASSWORD={secret_pass}\n"
        f"REDIS_PASSWORD={secret_pass}\n"
        f"OPENSEARCH_PASSWORD={secret_pass}\n"
    )
    monkeypatch.setattr(integration_gate, "ROOT", tmp_path)
    monkeypatch.setattr(integration_gate, "prepare_test_database", lambda *args, **kwargs: None)
    return {"path": env_file, "secret": secret_pass}


def test_gate_fails_when_env_file_missing(tmp_path, monkeypatch, capsys):
    """Condition: Missing .env configuration file."""
    monkeypatch.setattr(integration_gate, "ROOT", tmp_path)
    with pytest.raises(SystemExit) as exc_info:
        integration_gate.main()

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "ERROR: .env file not found" in err


def test_gate_fails_when_credentials_missing_in_env(tmp_path, monkeypatch, capsys):
    """Condition: .env exists but lacks required service passwords."""
    env_file = tmp_path / ".env"
    env_file.write_text("POSTGRES_PASSWORD=only_one_pass\n")
    monkeypatch.setattr(integration_gate, "ROOT", tmp_path)

    with pytest.raises(SystemExit) as exc_info:
        integration_gate.main()

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "ERROR: Missing required service credentials in .env" in err


def test_gate_fails_when_postgres_unavailable(mock_env_config, monkeypatch, capsys):
    """Condition: PostgreSQL service is unavailable on loopback port 5432."""
    def fake_wait(host, port, timeout_seconds=15):
        return port != 5432

    monkeypatch.setattr(integration_gate, "wait_for_port", fake_wait)
    monkeypatch.setenv("AEGIS_GATE_PORT_TIMEOUT", "1")

    with pytest.raises(SystemExit) as exc_info:
        integration_gate.main()

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "ERROR: Cannot connect to PostgreSQL at 127.0.0.1:5432" in err


def test_gate_fails_when_redis_unavailable(mock_env_config, monkeypatch, capsys):
    """Condition: Redis service is unavailable on loopback port 6379."""
    def fake_wait(host, port, timeout_seconds=15):
        return port != 6379

    monkeypatch.setattr(integration_gate, "wait_for_port", fake_wait)
    monkeypatch.setenv("AEGIS_GATE_PORT_TIMEOUT", "1")

    with pytest.raises(SystemExit) as exc_info:
        integration_gate.main()

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "ERROR: Cannot connect to Redis at 127.0.0.1:6379" in err


def test_gate_fails_when_opensearch_unavailable(mock_env_config, monkeypatch, capsys):
    """Condition: OpenSearch service is unavailable on loopback port 9200."""
    def fake_wait(host, port, timeout_seconds=15):
        return port != 9200

    monkeypatch.setattr(integration_gate, "wait_for_port", fake_wait)
    monkeypatch.setenv("AEGIS_GATE_PORT_TIMEOUT", "1")

    with pytest.raises(SystemExit) as exc_info:
        integration_gate.main()

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "ERROR: Cannot connect to OpenSearch at 127.0.0.1:9200" in err


def test_gate_fails_when_integration_test_fails(mock_env_config, monkeypatch, capsys):
    """Condition: Deliberately failing integration test."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 1
    mock_process.stdout = io.StringIO(
        "test_postgres_concurrent_rate_limiting FAILED\n"
        "=================== 1 failed, 12 passed in 10.50s ===================\n"
    )

    with patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(SystemExit) as exc_info:
            integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "RELEASE GATE FAILED: Integration tests encountered failures or errors." in captured.err


def test_gate_fails_when_mandatory_test_skipped(mock_env_config, monkeypatch, capsys):
    """Condition: Deliberately skipped mandatory integration test (Zero-Skip violation)."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = io.StringIO(
        "test_real_dependency_connectivity SKIPPED\n"
        "=================== 12 passed, 1 skipped in 8.20s ===================\n"
    )

    with patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(SystemExit) as exc_info:
            integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "RELEASE GATE FAILED: 1 test(s) were skipped." in captured.err
    assert "Mandatory integration tests must never be skipped in CI release gate!" in captured.err


def test_gate_fails_when_no_tests_collected(mock_env_config, monkeypatch, capsys):
    """Condition: Pytest collects zero tests or fewer than 20 tests."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = io.StringIO(
        "=================== 0 passed in 0.10s ===================\n"
    )

    with patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(SystemExit) as exc_info:
            integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "RELEASE GATE FAILED: Expected at least 20 integration tests, got 0." in captured.err


def test_gate_fails_when_pytest_output_malformed(mock_env_config, monkeypatch, capsys):
    """Condition: Pytest output is malformed or summary line is absent."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = io.StringIO(
        "Unexpected fatal error or incomplete pytest buffer.\n"
    )

    with patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(SystemExit) as exc_info:
            integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "RELEASE GATE FAILED: Pytest summary line could not be parsed or test output is malformed." in captured.err


def test_gate_fails_when_pytest_reports_error(mock_env_config, monkeypatch, capsys):
    """Condition: Pytest encounters a fixture or teardown error."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 1
    mock_process.stdout = io.StringIO(
        "=================== 12 passed, 1 error in 4.50s ===================\n"
    )

    with patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(SystemExit) as exc_info:
            integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "RELEASE GATE FAILED: Integration tests encountered failures or errors." in captured.err


ALL_PASSED_STDOUT = (
    "tests/test_postgres_integration.py::test_postgres_cerberus_concurrent_evidence_conflict[False] PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_cerberus_concurrent_evidence_conflict[True] PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_concurrent_rate_limiting PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_multiprocess_concurrent_audit_writes PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_concurrent_audit_writes_and_chain_integrity PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_concurrent_detection_window_appends PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_transaction_rollback_and_retry_behavior PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_worker_restart_and_duplicate_event_handling PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_simultaneous_duplicate_event_ingestion_race PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_multi_tenant_concurrent_audit_isolation PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_concurrent_entity_and_relationship_upserts PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_lock_timeout_and_abort_recovery PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_schema_migration_previous_to_current PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_concurrent_rule_activation_and_replay PASSED\n"
    "tests/test_postgres_integration.py::test_postgres_concurrent_storyline_correlation PASSED\n"
    "tests/test_integration.py::test_real_dependency_connectivity PASSED\n"
    "tests/test_integration.py::test_real_redis_queue_semantics_and_delivery PASSED\n"
    "tests/test_phase4_postgres.py::test_postgres_phase4_admission[False] PASSED\n"
    "tests/test_phase4_postgres.py::test_postgres_phase4_admission[True] PASSED\n"
    "tests/test_phase4_postgres.py::test_postgres_phase4_first_audit_head_gate PASSED\n"
    "=================== 20 passed in 15.20s ===================\n"
)


def test_gate_succeeds_when_all_healthy_and_20_pass(mock_env_config, monkeypatch, capsys):
    """Condition: All services healthy and all 20 fixture cases pass cleanly (Happy Path)."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = io.StringIO(ALL_PASSED_STDOUT)

    with patch("subprocess.Popen", return_value=mock_process):
        integration_gate.main()

    captured = capsys.readouterr()
    assert "Passed:     20" in captured.out
    assert "Failed:     0" in captured.out
    assert "Skipped:    0" in captured.out
    assert "Deselected: 0" in captured.out
    assert "RELEASE GATE PASSED: All mandatory external integration tests verified successfully (0 skips)." in captured.out


def test_gate_fails_when_mandatory_test_deselected(mock_env_config, monkeypatch, capsys):
    """Condition: One or more tests are deselected (e.g. via -k filter)."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = io.StringIO(
        "tests/test_postgres_integration.py::test_postgres_concurrent_rate_limiting PASSED\n"
        "=================== 12 passed, 1 deselected in 10.00s ===================\n"
    )

    with patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(SystemExit) as exc_info:
            integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Deselection of mandatory integration tests is strictly prohibited!" in captured.err


def test_gate_fails_when_mandatory_test_renamed_or_missing(mock_env_config, monkeypatch, capsys):
    """Condition: 20 fixture cases pass but a required mandatory test was renamed/omitted and replaced with dummy."""
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    # 20 fixture cases pass, but test_real_dependency_connectivity is missing, replaced by test_dummy_extra
    tampered_stdout = (
        "tests/test_postgres_integration.py::test_postgres_cerberus_concurrent_evidence_conflict[False] PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_cerberus_concurrent_evidence_conflict[True] PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_concurrent_rate_limiting PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_multiprocess_concurrent_audit_writes PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_concurrent_audit_writes_and_chain_integrity PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_concurrent_detection_window_appends PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_transaction_rollback_and_retry_behavior PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_worker_restart_and_duplicate_event_handling PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_simultaneous_duplicate_event_ingestion_race PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_multi_tenant_concurrent_audit_isolation PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_concurrent_entity_and_relationship_upserts PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_lock_timeout_and_abort_recovery PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_schema_migration_previous_to_current PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_concurrent_rule_activation_and_replay PASSED\n"
        "tests/test_postgres_integration.py::test_postgres_concurrent_storyline_correlation PASSED\n"
        "tests/test_integration.py::test_real_redis_queue_semantics_and_delivery PASSED\n"
        "tests/test_integration.py::test_dummy_extra PASSED\n"
        "tests/test_phase4_postgres.py::test_postgres_phase4_admission[False] PASSED\n"
        "tests/test_phase4_postgres.py::test_postgres_phase4_admission[True] PASSED\n"
        "tests/test_phase4_postgres.py::test_postgres_phase4_first_audit_head_gate PASSED\n"
        "=================== 20 passed in 15.20s ===================\n"
    )

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = io.StringIO(tampered_stdout)

    with patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(SystemExit) as exc_info:
            integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "The following mandatory integration test(s) did not execute and pass:" in captured.err
    assert "test_real_dependency_connectivity" in captured.err


@pytest.mark.parametrize("case", ["False", "True"])
def test_gate_requires_each_cerberus_parameter_case(mock_env_config, monkeypatch, capsys, case):
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda *args, **kwargs: True)
    name = f"test_postgres_cerberus_concurrent_evidence_conflict[{case}]"
    mock_process = MagicMock(returncode=0)
    mock_process.stdout = io.StringIO(ALL_PASSED_STDOUT.replace(name, "test_unrelated_extra"))
    with patch("subprocess.Popen", return_value=mock_process), pytest.raises(SystemExit) as failure:
        integration_gate.main()
    assert failure.value.code == 1
    assert name in capsys.readouterr().err


def test_gate_never_leaks_secrets_in_console_output(mock_env_config, monkeypatch, capsys):
    """Condition: Zero secret leakage across all console streams."""
    secret = mock_env_config["secret"]
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = io.StringIO(ALL_PASSED_STDOUT)

    with patch("subprocess.Popen", return_value=mock_process):
        integration_gate.main()

    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_gate_sanitizes_database_preparation_exception(mock_env_config, monkeypatch, capsys):
    """Condition: Database preparation exception must not leak credentials to stderr."""
    secret = mock_env_config["secret"]
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    def failing_prepare(test_url, admin_url, test_db_name):
        raise RuntimeError(f"Connection failed: {admin_url} password={secret}")

    monkeypatch.setattr(integration_gate, "prepare_test_database", failing_prepare)

    with pytest.raises(SystemExit) as exc_info:
        integration_gate.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert secret not in captured.err
    assert secret not in captured.out
    assert "******" in captured.err
    assert "RuntimeError" in captured.err


def test_gate_redacts_credentials_from_child_output(mock_env_config, monkeypatch, capsys):
    """Condition: Streamed child process output must have credentials redacted."""
    secret = mock_env_config["secret"]
    monkeypatch.setattr(integration_gate, "wait_for_port", lambda host, port, timeout_seconds=15: True)

    mock_process = MagicMock(returncode=1)
    mock_process.stdout = io.StringIO(f"Error during run: {secret} in connection string\n=== 1 failed ===")

    with patch("subprocess.Popen", return_value=mock_process), pytest.raises(SystemExit):
        integration_gate.main()

    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
    assert "******" in captured.out
