"""Tests for AEGIS TITAN Phase 6 soak test harness reliability and correctness.

Verifies:
1. Windows 64-bit and POSIX RSS memory measurement contract (float | None).
2. Explicit unavailable-measurement handling without false-pass telemetry bypass.
3. Production shutdown-drain ordering (draining pending events before stop signal).
4. Production drain_pending_events timeout boundedness on stalled work.
5. Strict false-pass prevention (unprocessed work, reconciliation failure, worker timeout).
6. Worker process lifecycle cleanup, join timeout detection, and leak detection.
7. Safe stats queue draining without reliance on Queue.empty().
8. CLI exit code contract (0 on pass, 1 on fail).
"""

from __future__ import annotations

import multiprocessing as mp
import queue
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import func, select

from aegis.config import Settings
from aegis.db import (
    Base,
    EventRecord,
    Organization,
    User,
    database,
)
from aegis.pipeline import ingest, seed_rules
from aegis.schemas import EventInput
from aegis.security import PASSWORDS, audit, verify_audit
from scripts.soak_test import (
    drain_pending_events,
    generate_synthetic_event,
    get_process_rss_mb,
    main,
    run_soak_test,
    worker_process_loop,
)


def test_soak_test_harness_smoke_run(tmp_path):
    """Executes a short, bounded multi-worker soak test run to verify the entire pipeline."""
    db_file = tmp_path / "soak_smoke.db"
    out_file = tmp_path / "soak_smoke.json"
    chk_file = tmp_path / "soak_checkpoints.json"

    report = run_soak_test(
        workers=2,
        duration=2.0,
        rate=20.0,
        tenant_count=2,
        seed=42,
        db_url=f"sqlite:///{db_file}",
        output_path=out_file,
        checkpoint_interval=1.0,
        checkpoint_file=chk_file,
    )

    assert report["status"] == "PASSED"
    assert report["metrics"]["total_submitted"] > 0
    assert report["metrics"]["final_processed"] == report["metrics"]["total_accepted"]
    assert report["metrics"]["final_pending"] == 0
    assert report["metrics"]["final_dead"] == 0
    assert report["integrity"]["reconciliation_passed"] is True
    assert report["integrity"]["drain_succeeded"] is True
    assert report["integrity"]["worker_join_clean"] is True
    assert report["integrity"]["audit_chains_valid"] is True
    assert report["integrity"]["telemetry_passed"] is True
    assert report["metrics"]["peak_rss_valid"] is True
    assert report["metrics"]["peak_rss_mb"] is not None
    assert report["metrics"]["peak_rss_mb"] > 0.0
    assert out_file.exists()
    assert chk_file.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific ctypes memory test")
def test_get_process_rss_mb_live_windows():
    """Verifies that get_process_rss_mb returns a valid positive float on Windows."""
    rss = get_process_rss_mb()
    assert rss is not None
    assert isinstance(rss, float)
    assert rss > 1.0
    assert rss < 10000.0


def test_get_process_rss_mb_failure_returns_none():
    """Verifies that when process memory query fails, get_process_rss_mb returns None

    rather than 0.0, representing unavailable telemetry explicitly.
    """
    with patch.dict(sys.modules, {"psutil": None}):
        if sys.platform == "win32":
            with patch("ctypes.windll.psapi.GetProcessMemoryInfo", side_effect=RuntimeError("API failure")):
                val = get_process_rss_mb()
                assert val is None
        else:
            with patch("resource.getrusage", side_effect=RuntimeError("getrusage failure")):
                val = get_process_rss_mb()
                assert val is None


def test_get_process_rss_mb_linux_platform_and_fallback():
    """Verifies that Linux/Darwin platform branch scales correctly and returns None on error."""
    mock_resource = MagicMock()
    mock_usage = MagicMock()
    mock_usage.ru_maxrss = 204800.0  # 204,800 KB -> 200.0 MB on Linux
    mock_resource.getrusage.return_value = mock_usage
    mock_resource.RUSAGE_SELF = 0

    with patch.dict(sys.modules, {"resource": mock_resource, "psutil": None}):
        with patch("sys.platform", "linux"):
            rss = get_process_rss_mb()
            assert rss == pytest.approx(200.0, rel=1e-2)

        # Non-positive value returns None
        mock_usage.ru_maxrss = 0.0
        with patch("sys.platform", "linux"):
            rss_zero = get_process_rss_mb()
            assert rss_zero is None


def test_soak_test_telemetry_gate_failure_on_missing_rss(tmp_path):
    """Verifies that if memory telemetry is unavailable and require_telemetry=True,

    the run strictly fails the telemetry gate and returns status == 'FAILED'.
    """
    db_file = tmp_path / "soak_telem_fail.db"
    out_file = tmp_path / "soak_telem_fail.json"

    with patch("scripts.soak_test.get_process_rss_mb", return_value=None):
        report = run_soak_test(
            workers=1,
            duration=1.0,
            rate=10.0,
            tenant_count=1,
            seed=42,
            db_url=f"sqlite:///{db_file}",
            output_path=out_file,
            checkpoint_interval=0.5,
            require_telemetry=True,
        )

    assert report["status"] == "FAILED"
    assert report["metrics"]["peak_rss_mb"] is None
    assert report["metrics"]["peak_rss_valid"] is False
    assert report["integrity"]["telemetry_valid"] is False
    assert report["integrity"]["telemetry_passed"] is False


def test_soak_test_telemetry_gate_allow_missing(tmp_path):
    """Verifies that if require_telemetry=False, missing RSS telemetry records None

    without forcing overall status to FAILED.
    """
    db_file = tmp_path / "soak_telem_allow.db"
    out_file = tmp_path / "soak_telem_allow.json"

    with patch("scripts.soak_test.get_process_rss_mb", return_value=None):
        report = run_soak_test(
            workers=1,
            duration=1.0,
            rate=10.0,
            tenant_count=1,
            seed=42,
            db_url=f"sqlite:///{db_file}",
            output_path=out_file,
            checkpoint_interval=0.5,
            require_telemetry=False,
        )

    assert report["status"] == "PASSED"
    assert report["metrics"]["peak_rss_mb"] is None
    assert report["metrics"]["peak_rss_valid"] is False
    assert report["integrity"]["telemetry_valid"] is False
    assert report["integrity"]["telemetry_passed"] is True


def test_shutdown_drain_with_enqueued_work_immediately_before_shutdown(tmp_path):
    """Verifies that when a batch of events is ingested immediately before shutdown,

    the drain runs WHILE workers are still active, resulting in 0 pending events.
    """
    db_file = tmp_path / "soak_drain.db"
    db_url = f"sqlite:///{db_file}"
    audit_secret = "test-drain-secret-key-32chars-min"

    settings = Settings(
        environment="testing",
        database_url=db_url,
        audit_secret=audit_secret,
        _env_file=None,
    )
    engine, sessions = database(settings.database_url)
    Base.metadata.create_all(engine)

    # Initialize 1 tenant
    with sessions.begin() as db:
        org = Organization(name="Drain Tenant")
        db.add(org)
        db.flush()
        tenant_id = org.id
        seed_rules(db, org.id)
        user = User(
            organization_id=org.id,
            username="drain_admin",
            password_hash=PASSWORDS.hash("DrainPass123!"),
            role="ADMIN",
        )
        db.add(user)
        db.flush()
        user_id = user.id
        audit(db, settings, org.id, user.id, "soak.init", org.id, details={"tenant": "Drain Tenant"})

    # Launch 2 worker processes
    stop_event = mp.Event()
    stats_queue: mp.Queue = mp.Queue()
    worker_processes: list[mp.Process] = []

    for w_idx in range(2):
        w_id = f"drain-worker-{w_idx+1}"
        proc = mp.Process(
            target=worker_process_loop,
            args=(w_id, settings.database_url, settings.audit_secret, stop_event, stats_queue),
            name=w_id,
            daemon=True,
        )
        proc.start()
        worker_processes.append(proc)

    # Enqueue a burst of events immediately before shutdown
    event_batch = [
        EventInput(
            source="syslog",
            raw_event=generate_synthetic_event(tenant_id, idx),
        )
        for idx in range(20)
    ]
    with sessions.begin() as db:
        res = ingest(db, settings, tenant_id, event_batch, user_id)
    accepted_count = len(res.get("accepted", []))
    assert accepted_count == 20

    # 1. Drain pending events WHILE workers are active using production helper
    remaining = drain_pending_events(sessions, timeout=10.0, poll_interval=0.1)
    assert remaining == 0

    # 2. Stop and join workers
    stop_event.set()
    for p in worker_processes:
        p.join(timeout=10.0)

    # 3. Drain stats queue without relying on Queue.empty()
    worker_processed = 0
    worker_errors = 0
    while True:
        try:
            item = stats_queue.get_nowait()
        except (queue.Empty, Exception):
            break
        if item.get("type") == "worker_processed":
            worker_processed += item["count"]
        elif item.get("type") == "worker_error":
            worker_errors += 1

    # 4. Final assertions
    with sessions() as db:
        final_processed = db.scalar(select(func.count(EventRecord.id)).where(EventRecord.state == "PROCESSED")) or 0
        final_pending = db.scalar(
            select(func.count(EventRecord.id)).where(EventRecord.state.in_(["PENDING", "RETRY"]))
        ) or 0
        final_dead = db.scalar(select(func.count(EventRecord.id)).where(EventRecord.state == "DEAD")) or 0
        audit_valid = verify_audit(db, settings, tenant_id)

    engine.dispose()

    assert final_pending == 0, f"Pending events remaining after drain: {final_pending}"
    assert final_processed == accepted_count, f"Processed {final_processed} != accepted {accepted_count}"
    assert final_dead == 0
    assert worker_errors == 0
    assert audit_valid is True


def test_shutdown_drain_finite_timeout_on_stalled_work(tmp_path):
    """Invokes the real production drain_pending_events helper to verify that

    it enforces a finite bounded timeout and returns remaining unconsumed work
    instead of hanging indefinitely.
    """
    db_file = tmp_path / "soak_timeout.db"
    db_url = f"sqlite:///{db_file}"
    settings = Settings(
        environment="testing",
        database_url=db_url,
        audit_secret="timeout-test-secret-32chars-min",
        _env_file=None,
    )
    engine, sessions = database(settings.database_url)
    Base.metadata.create_all(engine)

    with sessions.begin() as db:
        org = Organization(name="Stall Tenant")
        db.add(org)
        db.flush()
        seed_rules(db, org.id)
        user = User(
            organization_id=org.id,
            username="stall_admin",
            password_hash=PASSWORDS.hash("StallPass123!"),
            role="ADMIN",
        )
        db.add(user)
        db.flush()
        res = ingest(
            db,
            settings,
            org.id,
            [EventInput(source="syslog", raw_event=generate_synthetic_event(org.id, 0))],
            user.id,
        )

    assert len(res.get("accepted", [])) == 1

    drain_timeout = 1.0
    drain_start = time.monotonic()
    remaining = drain_pending_events(sessions, timeout=drain_timeout, poll_interval=0.1)
    elapsed = time.monotonic() - drain_start
    engine.dispose()

    assert elapsed >= drain_timeout
    assert elapsed < drain_timeout + 1.0
    assert remaining == 1, f"Expected 1 remaining pending event, got {remaining}"


def test_soak_test_false_pass_prevention_on_unprocessed_work(tmp_path):
    """Verifies that if workers do not process events, run_soak_test rejects

    the run and returns status == 'FAILED', preventing false-pass reporting.
    """
    db_file = tmp_path / "soak_fail_prevention.db"
    out_file = tmp_path / "soak_fail_prevention.json"

    # Launch with 0 workers so admitted events cannot be processed
    report = run_soak_test(
        workers=0,
        duration=1.0,
        rate=10.0,
        tenant_count=1,
        seed=42,
        db_url=f"sqlite:///{db_file}",
        output_path=out_file,
        checkpoint_interval=1.0,
    )

    assert report["status"] == "FAILED"
    assert report["integrity"]["drain_succeeded"] is False
    assert report["metrics"]["final_pending"] > 0
    assert out_file.exists()


def test_soak_test_false_pass_on_reconciliation_mismatch(tmp_path):
    """Verifies that if accepted events do not equal processed + pending + dead,

    reconciliation fails and forces status == 'FAILED'.
    """
    db_file = tmp_path / "soak_reconcile_fail.db"
    out_file = tmp_path / "soak_reconcile_fail.json"

    with patch("scripts.soak_test.drain_pending_events", return_value=0):
        def mock_ingest(db, settings, target_org, raw_batch, target_user):
            return {"accepted": ["evt-1", "evt-2"], "duplicates": [], "rejected": []}

        with patch("scripts.soak_test.ingest", side_effect=mock_ingest):
            report = run_soak_test(
                workers=0,
                duration=0.5,
                rate=5.0,
                tenant_count=1,
                seed=42,
                db_url=f"sqlite:///{db_file}",
                output_path=out_file,
                checkpoint_interval=0.5,
            )

    assert report["status"] == "FAILED"
    assert report["integrity"]["reconciliation_passed"] is False


def test_worker_join_timeout_detection(tmp_path):
    """Verifies that a worker process that fails to join within timeout is captured

    in worker_join_timeouts and forces workers_clean == False and status == 'FAILED'.
    """
    db_file = tmp_path / "soak_join_timeout.db"
    out_file = tmp_path / "soak_join_timeout.json"

    class MockHangingProcess:
        def __init__(self, *args, **kwargs):
            self.name = "hanging-worker-1"
            self._alive = True
            self.exitcode = None

        def start(self):
            pass

        def join(self, timeout=None):
            pass

        def is_alive(self):
            return self._alive

        def terminate(self):
            self._alive = False

    with patch("multiprocessing.Process", side_effect=lambda *args, **kwargs: MockHangingProcess()):
        report = run_soak_test(
            workers=1,
            duration=0.5,
            rate=5.0,
            tenant_count=1,
            seed=42,
            db_url=f"sqlite:///{db_file}",
            output_path=out_file,
            checkpoint_interval=0.5,
        )

    assert report["status"] == "FAILED"
    assert "hanging-worker-1" in report["integrity"]["worker_join_timeouts"]
    assert report["integrity"]["worker_join_clean"] is False


def test_worker_cleanup_leak_detection(tmp_path):
    """Verifies that if a process remains alive even after terminate, it is recorded

    in worker_leak_detected and forces status == 'FAILED'.
    """
    db_file = tmp_path / "soak_leak.db"
    out_file = tmp_path / "soak_leak.json"

    class MockUnstoppableProcess:
        def __init__(self, *args, **kwargs):
            self.name = "unstoppable-worker"
            self.exitcode = None

        def start(self):
            pass

        def join(self, timeout=None):
            pass

        def is_alive(self):
            return True

        def terminate(self):
            pass

    with patch("multiprocessing.Process", side_effect=lambda *args, **kwargs: MockUnstoppableProcess()):
        report = run_soak_test(
            workers=1,
            duration=0.5,
            rate=5.0,
            tenant_count=1,
            seed=42,
            db_url=f"sqlite:///{db_file}",
            output_path=out_file,
            checkpoint_interval=0.5,
        )

    assert report["status"] == "FAILED"
    assert "unstoppable-worker" in report["integrity"]["worker_leak_detected"]
    assert report["integrity"]["worker_join_clean"] is False


def test_worker_unclean_exit_detection(tmp_path):
    """Verifies that a worker process exiting with non-zero exitcode is captured

    in worker_unclean_exits and forces status == 'FAILED'.
    """
    db_file = tmp_path / "soak_crash.db"
    out_file = tmp_path / "soak_crash.json"

    class MockCrashedProcess:
        def __init__(self, *args, **kwargs):
            self.name = "crashed-worker"
            self.exitcode = 1

        def start(self):
            pass

        def join(self, timeout=None):
            pass

        def is_alive(self):
            return False

        def terminate(self):
            pass

    with patch("multiprocessing.Process", side_effect=lambda *args, **kwargs: MockCrashedProcess()):
        report = run_soak_test(
            workers=1,
            duration=0.5,
            rate=5.0,
            tenant_count=1,
            seed=42,
            db_url=f"sqlite:///{db_file}",
            output_path=out_file,
            checkpoint_interval=0.5,
        )

    assert report["status"] == "FAILED"
    assert len(report["integrity"]["worker_unclean_exits"]) == 1
    assert report["integrity"]["worker_unclean_exits"][0]["worker"] == "crashed-worker"
    assert report["integrity"]["worker_unclean_exits"][0]["exitcode"] == 1
    assert report["integrity"]["worker_join_clean"] is False


def test_worker_exception_handling_and_cleanup(tmp_path):
    """Verifies that when process_once raises an exception, the worker process catches it,

    reports the error to the stats queue, disposes engine on shutdown, and sends worker_exit.
    """
    db_file = tmp_path / "soak_err.db"
    db_url = f"sqlite:///{db_file}"
    audit_secret = "error-test-secret-32chars-min"

    settings = Settings(
        environment="testing",
        database_url=db_url,
        audit_secret=audit_secret,
        _env_file=None,
    )
    engine, sessions = database(settings.database_url)
    Base.metadata.create_all(engine)
    engine.dispose()

    stop_event = threading.Event()
    stats_q = queue.Queue()

    call_count = 0

    def faulty_process_once(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            raise RuntimeError("Simulated worker error during process_once")
        time.sleep(0.01)
        return 0

    with patch("scripts.soak_test.process_once", side_effect=faulty_process_once):
        worker_thread = threading.Thread(
            target=worker_process_loop,
            args=("test-err-worker", db_url, audit_secret, stop_event, stats_q),
        )
        worker_thread.start()

        time.sleep(0.3)
        stop_event.set()
        worker_thread.join(timeout=3.0)

    assert not worker_thread.is_alive()

    items = []
    while True:
        try:
            items.append(stats_q.get_nowait())
        except (queue.Empty, Exception):
            break

    error_items = [it for it in items if it.get("type") == "worker_error"]
    exit_items = [it for it in items if it.get("type") == "worker_exit"]

    assert len(error_items) >= 2
    assert error_items[0]["error"] == "RuntimeError"
    assert len(exit_items) == 1
    assert exit_items[0]["total_errors"] >= 2


def test_soak_test_cli_main_exit_codes(tmp_path):
    """Verifies that the CLI entrypoint returns exit code 0 on passed run and 1 on failed run."""
    db_file_pass = tmp_path / "cli_pass.db"
    out_file_pass = tmp_path / "cli_pass.json"

    pass_args = [
        "soak_test.py",
        "--workers", "1",
        "--duration", "1.0",
        "--rate", "10.0",
        "--tenants", "1",
        "--database-url", f"sqlite:///{db_file_pass}",
        "--output", str(out_file_pass),
        "--checkpoint-interval", "0.5",
    ]

    with patch("sys.argv", pass_args):
        ret_pass = main()
    assert ret_pass == 0

    db_file_fail = tmp_path / "cli_fail.db"
    out_file_fail = tmp_path / "cli_fail.json"

    fail_args = [
        "soak_test.py",
        "--workers", "0",
        "--duration", "1.0",
        "--rate", "10.0",
        "--tenants", "1",
        "--database-url", f"sqlite:///{db_file_fail}",
        "--output", str(out_file_fail),
        "--checkpoint-interval", "0.5",
    ]

    with patch("sys.argv", fail_args):
        ret_fail = main()
    assert ret_fail == 1


def test_get_process_rss_mb_target_pid_never_returns_current_process():
    """Verifies that when another PID is requested, get_process_rss_mb queries that

    specific PID and NEVER returns the calling process's memory.
    """
    # 1. Non-existent PID on Windows / generic platform returns None, not current process RSS
    non_existent_pid = 99999999
    val = get_process_rss_mb(non_existent_pid)
    assert val is None

    # 2. Linux /proc/{pid}/status query returns specific PID memory
    mock_pid = 12345
    mock_status_content = "Name:\tworker\nVmRSS:\t51200 kB\nThreads:\t1\n"
    with patch.dict(sys.modules, {"psutil": None}):
        with patch("sys.platform", "linux"):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.read_text", return_value=mock_status_content):
                    pid_rss = get_process_rss_mb(mock_pid)
                    assert pid_rss == pytest.approx(50.0, rel=1e-2)

            # Missing /proc/{pid}/status returns None, does not fall back to RUSAGE_SELF
            with patch("pathlib.Path.exists", return_value=False):
                missing_rss = get_process_rss_mb(mock_pid)
                assert missing_rss is None


def test_soak_test_non_vacuous_audit_and_tenant_checks(tmp_path):
    """Verifies that audit-chain verification and cross-tenant checks cannot pass vacuously."""
    db_file = tmp_path / "soak_vacuous.db"
    out_file = tmp_path / "soak_vacuous.json"

    # With 2 tenants and normal execution, both tenants must have received events
    report = run_soak_test(
        workers=1,
        duration=1.0,
        rate=10.0,
        tenant_count=2,
        seed=42,
        db_url=f"sqlite:///{db_file}",
        output_path=out_file,
        checkpoint_interval=0.5,
    )

    assert report["status"] == "PASSED"
    assert report["integrity"]["audit_chains_valid"] is True
    assert report["integrity"]["isolation_verified"] is True
    assert len(report["integrity"]["tenant_event_counts"]) == 2
    assert report["integrity"]["telemetry_mode"] == "STRICT_ENFORCED"
