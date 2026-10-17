"""Deterministic adversarial regression and recovery scenarios; isolated SQLite only."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest
from sqlalchemy import delete, event, func, select

from aegis.config import Settings
from aegis.db import AuditHead, AuditLog, BehaviorJob, EventRecord, Organization
from aegis.pipeline import ingest
from aegis.schemas import EventInput
from aegis.security import audit, verify_audit
from aegis.ueba import config, process_jobs
from aegis.worker import process_once


@pytest.mark.parametrize("damage", ["delete_all", "sequence", "organization_head"])
def test_audit_head_damage_fails_closed(system, damage):
    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    with sessions.begin() as db:
        audit(db, settings, org, "cerberus", "before_tampering")
    with sessions.begin() as db:
        if damage == "delete_all":
            db.execute(delete(AuditLog).where(AuditLog.organization_id == org))
        elif damage == "sequence":
            db.get(AuditHead, org).sequence_number += 1
        else:
            db.get(Organization, org).audit_head = "f" * 64
    with sessions() as db:
        assert verify_audit(db, settings, org) is False
        assert verify_audit(db, settings, system["other"]) is True


def test_audit_transaction_interruption_and_restart(system):
    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    with pytest.raises(RuntimeError, match="interruption"), sessions.begin() as db:
        audit(db, settings, org, "cerberus", "rolled_back")
        raise RuntimeError("interruption")
    with sessions.begin() as db:
        assert db.scalar(select(func.count()).select_from(AuditLog)) == 0
        audit(db, settings, org, "cerberus", "recovered")
    with sessions() as db:
        assert verify_audit(db, settings, org)
        assert db.get(AuditHead, org).sequence_number == 1


@pytest.mark.parametrize("interrupt", [False, True])
def test_ueba_failure_rolls_back_partial_writes_and_recovers(system, monkeypatch, interrupt):
    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    with sessions.begin() as db:
        db.add(
            BehaviorJob(
                id="cerberus-job",
                organization_id=org,
                window_end=datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0),
                config=config(settings),
            )
        )

    def fail(db, *args):
        audit(db, settings, org, "cerberus", "must_rollback")
        if interrupt:
            raise KeyboardInterrupt()
        raise ConnectionError("synthetic-secret-must-not-leak")

    with monkeypatch.context() as patch:
        patch.setattr("aegis.ueba.analyze", fail)
        if interrupt:
            with pytest.raises(KeyboardInterrupt):
                process_jobs(settings, sessions)
        else:
            for attempt in range(1, settings.worker_max_attempts + 1):
                assert process_jobs(settings, sessions) == 1
                with sessions.begin() as db:
                    job = db.get(BehaviorJob, "cerberus-job")
                    assert job.attempts == attempt
                    assert job.result == {"error": "ConnectionError"}
                    assert job.state == ("FAILED" if attempt == settings.worker_max_attempts else "RETRY")
                    job.available_at = 0
            assert process_jobs(settings, sessions) == 0
    with sessions.begin() as db:
        assert db.scalar(select(func.count()).select_from(AuditLog)) == 0
        job = db.get(BehaviorJob, "cerberus-job")
        if interrupt:
            assert job.state == "PENDING" and job.attempts == 0
        else:
            job.state, job.attempts = "PENDING", 0
    assert process_jobs(settings, sessions) == 1
    assert process_jobs(settings, sessions) == 0
    with sessions() as db:
        assert db.get(BehaviorJob, "cerberus-job").state == "COMPLETED"


def test_ueba_effective_limit_and_validation(system, monkeypatch):
    monkeypatch.delenv("UEBA_EVENT_LIMIT", raising=False)
    assert Settings(_env_file=None).ueba_event_limit == 10000
    assert system["client"].get("/api/v1/ueba/detectors").json()["config"]["event_limit"] == 10000
    for value in (99, 50001):
        with pytest.raises(ValueError):
            Settings(ueba_event_limit=value, _env_file=None)
    monkeypatch.setenv("UEBA_EVENT_LIMIT", "50000")
    assert config(Settings(_env_file=None))["event_limit"] == 50000


def test_synchronized_audit_writers_preserve_all_entries(system):
    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    barrier = Barrier(4)

    def write(index):
        barrier.wait(timeout=10)
        with sessions.begin() as db:
            audit(db, settings, org, "cerberus", f"concurrent-{index}")

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(write, range(4)))
    with sessions() as db:
        assert verify_audit(db, settings, org)
        assert db.get(AuditHead, org).sequence_number == 4
        assert set(db.scalars(select(AuditLog.action))) == {f"concurrent-{i}" for i in range(4)}


@pytest.mark.parametrize("conflicting", [False, True])
def test_simultaneous_source_sequence_reuse(system, conflicting):
    """Both requests see no existing event before competing for the unique ID."""
    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    engine = system["app"].state.engine
    barrier = Barrier(2)

    def synchronize(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("SELECT events_metadata.id,") and " IN (" in statement:
            barrier.wait(timeout=10)

    def submit(index):
        incoming = EventInput(
            source="cerberus",
            source_sequence="same-sequence",
            raw_event={"message": str(index) if conflicting else "same"},
        )
        try:
            with sessions.begin() as db:
                return ingest(db, settings, org, [incoming], "cerberus")
        except ValueError as exc:
            assert str(exc) == "Source sequence was reused with different evidence"
            return "rejected"

    event.listen(engine, "after_cursor_execute", synchronize)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, range(2)))
    finally:
        event.remove(engine, "after_cursor_execute", synchronize)
    assert sum(isinstance(r, dict) and len(r["accepted"]) == 1 for r in results) == 1
    if conflicting:
        assert results.count("rejected") == 1
    else:
        assert sum(len(r["duplicates"]) for r in results) == 1
    with sessions() as db:
        assert (
            db.scalar(select(func.count()).select_from(EventRecord).where(EventRecord.organization_id == org))
            == 1
        )
        assert verify_audit(db, settings, org)


def test_worker_failure_logs_do_not_disclose_exception_payload(system, monkeypatch, caplog):
    sessions, settings, org = system["app"].state.sessions, system["settings"], system["org"]
    with sessions.begin() as db:
        ingest(db, settings, org, [EventInput(source="cerberus", raw_event="synthetic")], "test")

    def fail(*args, **kwargs):
        raise ConnectionError("cerberus-sensitive-exception-payload")

    monkeypatch.setattr("aegis.worker.detect_batch", fail)
    process_once(settings, sessions, system["app"].state.storage)
    assert "cerberus-sensitive-exception-payload" not in caplog.text
    assert any(r.error_type == "ConnectionError" for r in caplog.records if hasattr(r, "error_type"))


def test_api_dependency_failure_is_visible_and_redacted(system, monkeypatch, caplog):
    def unavailable(*args, **kwargs):
        raise ConnectionError("cerberus-sensitive-exception-payload")

    monkeypatch.setattr("aegis.api.ingest", unavailable)
    response = system["client"].post(
        "/api/v1/events/ingest", json={"events": [{"source": "cerberus", "raw_event": "synthetic"}]}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert "cerberus-sensitive-exception-payload" not in response.text + caplog.text
    with system["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(EventRecord)) == 0
