"""CI Release Gate: Enforces mandatory execution of PostgreSQL and distributed integration tests.

Zero-skip policy: fails if any integration test is skipped or fails.
Never prints or leaks credentials.
Guarantees database test safety by targeting exclusively isolated test databases (e.g., aegis_test).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as ET
from alembic import command
from alembic.config import Config
from dotenv import dotenv_values

from aegis.db_safety import (
    ensure_isolated_test_database,
    validate_test_database_url,
)

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build"


MANDATORY_INTEGRATION_TESTS = {
    # Phase 4 Admission & Head Gate (tests/test_phase4_postgres.py)
    "test_postgres_phase4_admission[False]",
    "test_postgres_phase4_admission[True]",
    "test_postgres_phase4_first_audit_head_gate",
    # PostgreSQL Concurrency & Isolation Suite (tests/test_postgres_integration.py)
    "test_postgres_cerberus_concurrent_evidence_conflict[False]",
    "test_postgres_cerberus_concurrent_evidence_conflict[True]",
    "test_postgres_concurrent_storyline_correlation",
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

DISTRIBUTED_TEST_NAMES = {
    "test_real_dependency_connectivity",
    "test_real_redis_queue_semantics_and_delivery",
}

POSTGRES_MANDATORY_TESTS = MANDATORY_INTEGRATION_TESTS - DISTRIBUTED_TEST_NAMES


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


def verify_postgres_readiness(admin_url: str, timeout_seconds: int = 30) -> str:
    """Verify that PostgreSQL is actively authenticated, responsive, and running supported engine version."""
    from sqlalchemy import create_engine, text

    if admin_url.startswith("postgresql://"):
        admin_url = admin_url.replace("postgresql://", "postgresql+psycopg://", 1)

    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            engine = create_engine(admin_url, pool_pre_ping=True, connect_args={"connect_timeout": 3})
            with engine.connect() as conn:
                row = conn.execute(text("SELECT version(), current_database(), current_user")).fetchone()
                if row:
                    version_str = str(row[0])
                    if "PostgreSQL" not in version_str:
                        raise RuntimeError(f"Connected service on port is not PostgreSQL: {version_str}")
                    return version_str
        except Exception as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(
        f"PostgreSQL readiness verification failed after {timeout_seconds}s: {type(last_error).__name__}: {last_error}"
    )


def prepare_test_database(test_url: str, admin_url: str, test_db_name: str) -> None:
    """Validate, auto-provision, and apply schema migrations to the dedicated test database."""
    from sqlalchemy import create_engine, text

    print(f"Verifying database safety invariants for test database '{test_db_name}'...")
    validate_test_database_url(test_url, environment="testing")

    print(f"Ensuring isolated test database '{test_db_name}' exists...")
    psycopg_admin_dsn = admin_url.replace("postgresql+psycopg://", "postgresql://")
    ensure_isolated_test_database(psycopg_admin_dsn, test_db_name)

    # Active safety check: verify the target test database is isolated and matches test_db_name
    test_engine = create_engine(test_url, pool_pre_ping=True)
    with test_engine.connect() as conn:
        current_db = conn.execute(text("SELECT current_database()")).scalar()
        if current_db != test_db_name:
            raise RuntimeError(
                f"SAFETY VIOLATION: Test connection targeted '{current_db}' instead of isolated '{test_db_name}'"
            )

    print(f"Applying schema migrations deterministically to '{test_db_name}'...")
    alembic_cfg = Config(str(ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", test_url)
    command.upgrade(alembic_cfg, "head")


def parse_junit_report(report_path: Path) -> dict[str, Any]:
    """Parse structured pytest JUnit XML report defensively using defusedxml."""
    if not report_path.exists():
        raise FileNotFoundError(f"Structured test report not found: {report_path}")

    tree = ET.parse(report_path)
    root_elem = tree.getroot()

    testsuites = [root_elem] if root_elem.tag == "testsuite" else root_elem.findall("testsuite")
    total_tests = 0
    total_failures = 0
    total_errors = 0
    total_skipped = 0
    passed_names: set[str] = set()
    skipped_dict: dict[str, str] = {}
    failed_dict: dict[str, str] = {}
    error_dict: dict[str, str] = {}
    all_node_ids: list[str] = []

    for suite in testsuites:
        for case in suite.findall("testcase"):
            total_tests += 1
            name = case.get("name", "unknown")
            classname = case.get("classname", "unknown")
            file_path = case.get("file", classname)
            node_id = f"{file_path}::{name}"
            all_node_ids.append(node_id)

            skipped_elem = case.find("skipped")
            failure_elem = case.find("failure")
            error_elem = case.find("error")

            if skipped_elem is not None:
                total_skipped += 1
                skipped_dict[name] = skipped_elem.get("message", "skipped")
            elif failure_elem is not None:
                total_failures += 1
                failed_dict[name] = failure_elem.get("message", failure_elem.text or "failed")
            elif error_elem is not None:
                total_errors += 1
                error_dict[name] = error_elem.get("message", error_elem.text or "error")
            else:
                passed_names.add(name)

    passed_count = total_tests - total_failures - total_errors - total_skipped
    return {
        "total": total_tests,
        "passed": passed_count,
        "failed": total_failures,
        "errors": total_errors,
        "skipped": total_skipped,
        "passed_names": passed_names,
        "skipped_dict": skipped_dict,
        "failed_dict": failed_dict,
        "error_dict": error_dict,
        "all_node_ids": all_node_ids,
    }


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        if sys.argv and not any("pytest" in arg for arg in sys.argv):
            argv = sys.argv[1:]
        else:
            argv = []

    parser = argparse.ArgumentParser(description="AEGIS Integration Release Gate")
    parser.add_argument(
        "--postgres-only",
        action="store_true",
        help="Run only PostgreSQL integration tests (isolating database verification from Redis/OpenSearch)",
    )
    args, _ = parser.parse_known_args(argv)
    postgres_only = args.postgres_only or os.environ.get("AEGIS_GATE_POSTGRES_ONLY") == "1"

    env_file = ROOT / ".env"
    if not env_file.exists():
        print("ERROR: .env file not found. Run 'python scripts/configure.py' first.", file=sys.stderr)
        sys.exit(1)

    config = dotenv_values(env_file)
    postgres_pass = config.get("POSTGRES_PASSWORD") or os.environ.get("POSTGRES_PASSWORD")
    redis_pass = config.get("REDIS_PASSWORD") or os.environ.get("REDIS_PASSWORD")
    opensearch_pass = config.get("OPENSEARCH_PASSWORD") or os.environ.get("OPENSEARCH_PASSWORD")

    if not postgres_pass or not redis_pass or not opensearch_pass:
        print("ERROR: Missing required service credentials in .env.", file=sys.stderr)
        sys.exit(1)

    # 1. Verify loopback connectivity to external services
    print(f"=== CI Release Gate: Checking External Service Connectivity ({'PostgreSQL Only' if postgres_only else 'Full Distributed'}) ===")
    services = [("PostgreSQL", "127.0.0.1", 5432)]
    if not postgres_only:
        services.extend([
            ("Redis", "127.0.0.1", 6379),
            ("OpenSearch", "127.0.0.1", 9200),
        ])

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
    admin_pg_url = f"postgresql+psycopg://aegis:{postgres_pass}@127.0.0.1:5432/postgres"

    try:
        prepare_test_database(test_pg_url, admin_pg_url, test_db_name)
    except Exception as exc:
        sanitized_exc = f"{type(exc).__name__}: {exc}"
        if postgres_pass:
            sanitized_exc = sanitized_exc.replace(postgres_pass, "******")
        print(f"ERROR: Database preparation failed: {sanitized_exc}", file=sys.stderr)
        sys.exit(1)

    # 3. Build sanitized execution environment for integration test suite
    test_env = os.environ.copy()
    test_env.update(
        {
            "AEGIS_POSTGRES_TEST_URL": test_pg_url,
            "DATABASE_URL": test_pg_url,
            "ENVIRONMENT": "testing",
            "AUDIT_SECRET": os.environ.get("AUDIT_SECRET") or config.get("AUDIT_SECRET") or "pg-test-audit-integrity-key-32chars-min",
            "AEGIS_INTEGRATION": "1",
        }
    )
    if not postgres_only:
        test_env.update(
            {
                "REDIS_URL": f"redis://:{redis_pass}@127.0.0.1:6379/0",
                "OPENSEARCH_URL": "http://127.0.0.1:9200",
                "OPENSEARCH_USERNAME": os.environ.get("OPENSEARCH_USERNAME") or "aegis",
                "OPENSEARCH_PASSWORD": opensearch_pass or "",
            }
        )

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    report_xml = BUILD_DIR / "integration-results.xml"
    if report_xml.exists():
        report_xml.unlink()

    # 4. Execute PostgreSQL concurrency and distributed connectivity test suites
    print(f"\n=== CI Release Gate: Executing Mandatory Integration Suites ({'PostgreSQL Only' if postgres_only else 'Full Distributed'}) ===")
    cmd_base = [
        sys.executable,
        "-m",
        "pytest",
        "tests/test_database_safety.py",
        "tests/test_postgres_integration.py",
        "tests/test_phase4_postgres.py",
    ]
    if postgres_only:
        cmd = cmd_base + [
            "-k",
            "not opensearch and not ioc_cache",
            f"--junitxml={report_xml}",
            "-v",
            "--tb=short",
            "-rA",
        ]
        mandatory_target = POSTGRES_MANDATORY_TESTS
        min_expected_passed = len(POSTGRES_MANDATORY_TESTS)
    else:
        cmd = cmd_base + [
            "tests/test_integration.py",
            f"--junitxml={report_xml}",
            "-v",
            "--tb=short",
            "-rA",
        ]
        mandatory_target = MANDATORY_INTEGRATION_TESTS
        min_expected_passed = len(MANDATORY_INTEGRATION_TESTS)

    process = subprocess.Popen(  # noqa: S603  # nosec B603
        cmd,
        cwd=ROOT,
        env=test_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    output_lines: list[str] = []
    if process.stdout is None:
        raise RuntimeError("Subprocess stdout stream is not available")
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

    # 5. Extract test outcome metrics
    parsed_report: dict[str, Any] | None = None
    if report_xml.exists():
        try:
            parsed_report = parse_junit_report(report_xml)
            passed_count = parsed_report["passed"]
            failed_count = parsed_report["failed"]
            error_count = parsed_report["errors"]
            skipped_count = parsed_report["skipped"]
            passed_test_names = parsed_report["passed_names"]
        except Exception as exc:
            print(f"RELEASE GATE FAILED: Failed to parse structured test report: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
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
        passed_test_names = set(re.findall(r"::(\w+(?:\[[^\]\r\n]+\])?)\s+PASSED", full_output))

    deselected_match = re.search(r"(\d+)\s+deselected", full_output)
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

    max_allowed_deselected = 2 if postgres_only else 0
    if deselected_count > max_allowed_deselected:
        print(
            f"RELEASE GATE FAILED: {deselected_count} test(s) were deselected.\n"
            f"Deselection of mandatory integration tests is strictly prohibited!",
            file=sys.stderr,
        )
        sys.exit(1)

    if passed_count < min_expected_passed:
        print(
            f"RELEASE GATE FAILED: Expected at least {min_expected_passed} integration tests, got {passed_count}.",
            file=sys.stderr,
        )
        sys.exit(1)

    # 6. Explicitly verify every single mandatory integration test by name was executed and PASSED
    missing_tests = mandatory_target - passed_test_names
    if missing_tests:
        print(
            "RELEASE GATE FAILED: The following mandatory integration test(s) did not execute and pass:\n"
            + "\n".join(f"  - {t}" for t in sorted(missing_tests)),
            file=sys.stderr,
        )
        sys.exit(1)

    # 7. Persist structured qualification evidence artifact
    if parsed_report:
        qual_summary = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "mode": "postgres_only" if postgres_only else "full_distributed",
            "total_collected": parsed_report["total"],
            "passed": parsed_report["passed"],
            "failed": parsed_report["failed"],
            "errors": parsed_report["errors"],
            "skipped": parsed_report["skipped"],
            "deselected": deselected_count,
            "status": "PASS — LIVE POSTGRESQL QUALIFICATION COMPLETED",
            "node_ids": parsed_report["all_node_ids"],
        }
        summary_file = BUILD_DIR / "integration-qualification.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(qual_summary, f, indent=2)
        print(f"\nStructured qualification record saved to: {summary_file}")

    print("RELEASE GATE PASSED: All mandatory external integration tests verified successfully (0 skips).")


if __name__ == "__main__":
    main()
