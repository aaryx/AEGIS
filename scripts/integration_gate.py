"""CI Release Gate: Enforces mandatory execution of PostgreSQL and distributed integration tests.

Zero-skip policy: fails if any integration test is skipped or fails.
Never prints or leaks credentials.
Guarantees database test safety by targeting exclusively isolated test databases (e.g., aegis_test).
"""

from __future__ import annotations

import os
import re
import socket
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from dotenv import dotenv_values

from aegis.db_safety import (
    ensure_isolated_test_database,
    validate_test_database_url,
)

ROOT = Path(__file__).resolve().parents[1]


MANDATORY_INTEGRATION_TESTS = {
    "test_postgres_cerberus_concurrent_evidence_conflict[False]",
    "test_postgres_cerberus_concurrent_evidence_conflict[True]",
    "test_postgres_concurrent_storyline_correlation",
    # PostgreSQL Concurrency & Isolation Suite (tests/test_postgres_integration.py)
    "test_postgres_concurrent_rate_limiting",
    "test_postgres_multiprocess_concurrent_audit_writes",
    "test_postgres_concurrent_audit_writes_and_chain_integrity",
    "test_postgres_concurrent_detection_window_appends",
    "test_postgres_transaction_rollback_and_retry_behavior",
    "test_postgres_worker_restart_and_duplicate_event_handling",
    "test_postgres_simultaneous_duplicate_event_ingestion_race",
    "test_postgres_multi_tenant_concurrent_audit_isolation",
    "test_postgres_concurrent_entity_and_relationship_upserts",
    "test_postgres_lock_timeout_and_abort_recovery",
    "test_postgres_schema_migration_previous_to_current",
    "test_postgres_concurrent_rule_activation_and_replay",
    # Distributed Services Suite (tests/test_integration.py)
    "test_real_dependency_connectivity",
    "test_real_redis_queue_semantics_and_delivery",
}


def wait_for_port(host: str, port: int, timeout_seconds: int = 30) -> bool:
    """Wait for TCP port to accept connections."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except (OSError, TimeoutError):
            time.sleep(1)
    return False


def prepare_test_database(test_url: str, admin_url: str, test_db_name: str) -> None:
    """Validate, auto-provision, and apply schema migrations to the dedicated test database."""
    print(f"Verifying database safety invariants for test database '{test_db_name}'...")
    validate_test_database_url(test_url, environment="testing")

    print(f"Ensuring isolated test database '{test_db_name}' exists...")
    ensure_isolated_test_database(admin_url, test_db_name)

    print(f"Applying schema migrations deterministically to '{test_db_name}'...")
    alembic_cfg = Config(str(ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", test_url)
    command.upgrade(alembic_cfg, "head")


def main() -> None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        print("ERROR: .env file not found. Run 'python scripts/configure.py' first.", file=sys.stderr)
        sys.exit(1)

    config = dotenv_values(env_file)
    postgres_pass = config.get("POSTGRES_PASSWORD")
    redis_pass = config.get("REDIS_PASSWORD")
    opensearch_pass = config.get("OPENSEARCH_PASSWORD")

    if not postgres_pass or not redis_pass or not opensearch_pass:
        print("ERROR: Missing required service credentials in .env.", file=sys.stderr)
        sys.exit(1)

    # 1. Verify loopback connectivity to external services
    print("=== CI Release Gate: Checking External Service Connectivity ===")
    services = [
        ("PostgreSQL", "127.0.0.1", 5432),
        ("Redis", "127.0.0.1", 6379),
        ("OpenSearch", "127.0.0.1", 9200),
    ]

    port_timeout = int(os.environ.get("AEGIS_GATE_PORT_TIMEOUT", "15"))
    for name, host, port in services:
        print(f"Waiting for {name} ({host}:{port})...")
        if not wait_for_port(host, port, timeout_seconds=port_timeout):
            print(
                f"ERROR: Cannot connect to {name} at {host}:{port}.\n"
                f"Ensure services are running: docker compose up -d --wait",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"  -> {name} is reachable on {host}:{port}.")

    # 2. Database Isolation: Explicitly target dedicated test database (never normal app DB)
    test_db_name = os.environ.get("AEGIS_POSTGRES_TEST_DB", "aegis_test")
    test_pg_url = f"postgresql+psycopg://aegis:{postgres_pass}@127.0.0.1:5432/{test_db_name}"
    admin_pg_url = f"postgresql://aegis:{postgres_pass}@127.0.0.1:5432/postgres"

    try:
        prepare_test_database(test_pg_url, admin_pg_url, test_db_name)
    except Exception as exc:
        err_msg = str(exc)
        if postgres_pass:
            err_msg = err_msg.replace(postgres_pass, "******")
        print(f"RELEASE GATE FAILED: Test database preparation error: {type(exc).__name__}: {err_msg}", file=sys.stderr)
        sys.exit(1)

    # 3. Build sanitized execution environment for integration test suite
    test_env = os.environ.copy()
    test_env.update(
        {
            "AEGIS_POSTGRES_TEST_URL": test_pg_url,
            "DATABASE_URL": test_pg_url,
            "ENVIRONMENT": "testing",
            "REDIS_URL": f"redis://:{redis_pass}@127.0.0.1:6379/0",
            "OPENSEARCH_URL": "http://127.0.0.1:9200",
            "OPENSEARCH_USERNAME": "aegis",
            "OPENSEARCH_PASSWORD": opensearch_pass,
            "AUDIT_SECRET": config.get("AUDIT_SECRET") or "pg-test-audit-integrity-key-32chars-min",
            "AEGIS_INTEGRATION": "1",
        }
    )

    # 4. Execute PostgreSQL concurrency and distributed connectivity test suites
    print("\n=== CI Release Gate: Executing Mandatory Integration Suites ===")
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/test_database_safety.py",
        "tests/test_postgres_integration.py",
        "tests/test_integration.py",
        "-v",
        "--tb=short",
        "-rA",
    ]

    process = subprocess.Popen(  # noqa: S603  # nosec B603
        cmd,
        cwd=ROOT,
        env=test_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    output_lines: list[str] = []
    assert process.stdout is not None
    for line in iter(process.stdout.readline, ""):
        sanitized_line = line
        if postgres_pass:
            sanitized_line = sanitized_line.replace(postgres_pass, "******")
        if redis_pass:
            sanitized_line = sanitized_line.replace(redis_pass, "******")
        if opensearch_pass:
            sanitized_line = sanitized_line.replace(opensearch_pass, "******")
        output_lines.append(sanitized_line)
        sys.stdout.write(sanitized_line)
        sys.stdout.flush()

    process.wait()
    full_output = "".join(output_lines)

    # 5. Enforce strict Zero-Skip policy
    summary_match = re.search(r"=+\s*(.+?)\s*in\s+[\d\.]+", full_output)
    if not summary_match:
        print(
            "RELEASE GATE FAILED: Pytest summary line could not be parsed or test output is malformed.",
            file=sys.stderr,
        )
        sys.exit(1)

    summary_str = summary_match.group(1)

    passed_match = re.search(r"(\d+)\s+passed", summary_str)
    skipped_match = re.search(r"(\d+)\s+skipped", summary_str)
    failed_match = re.search(r"(\d+)\s+failed", summary_str)
    error_match = re.search(r"(\d+)\s+error", summary_str)

    passed_count = int(passed_match.group(1)) if passed_match else 0
    skipped_count = int(skipped_match.group(1)) if skipped_match else 0
    failed_count = int(failed_match.group(1)) if failed_match else 0
    error_count = int(error_match.group(1)) if error_match else 0

    deselected_match = re.search(r"(\d+)\s+deselected", summary_str)
    deselected_count = int(deselected_match.group(1)) if deselected_match else 0

    print("\n=== CI Release Gate Verification Summary ===")
    print(f"Passed:     {passed_count}")
    print(f"Failed:     {failed_count}")
    print(f"Errors:     {error_count}")
    print(f"Skipped:    {skipped_count}")
    print(f"Deselected: {deselected_count}")

    if process.returncode != 0 or failed_count > 0 or error_count > 0:
        print("RELEASE GATE FAILED: Integration tests encountered failures or errors.", file=sys.stderr)
        sys.exit(1)

    if skipped_count > 0:
        print(
            f"RELEASE GATE FAILED: {skipped_count} test(s) were skipped.\n"
            f"Mandatory integration tests must never be skipped in CI release gate!",
            file=sys.stderr,
        )
        sys.exit(1)

    if deselected_count > 0:
        print(
            f"RELEASE GATE FAILED: {deselected_count} test(s) were deselected.\n"
            f"Deselection of mandatory integration tests is strictly prohibited!",
            file=sys.stderr,
        )
        sys.exit(1)

    if passed_count < len(MANDATORY_INTEGRATION_TESTS):
        print(
            f"RELEASE GATE FAILED: Expected at least {len(MANDATORY_INTEGRATION_TESTS)} integration tests, got {passed_count}.",
            file=sys.stderr,
        )
        sys.exit(1)

    # 6. Explicitly verify every single mandatory integration test by name was executed and PASSED
    passed_test_names = set(re.findall(r"::(\w+(?:\[[^\]\r\n]+\])?)\s+PASSED", full_output))
    missing_tests = MANDATORY_INTEGRATION_TESTS - passed_test_names
    if missing_tests:
        print(
            "RELEASE GATE FAILED: The following mandatory integration test(s) did not execute and pass:\n"
            + "\n".join(f"  - {t}" for t in sorted(missing_tests)),
            file=sys.stderr,
        )
        sys.exit(1)

    print("RELEASE GATE PASSED: All mandatory external integration tests verified successfully (0 skips).")


if __name__ == "__main__":
    main()
