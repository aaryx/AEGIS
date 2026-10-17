from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from aegis.db import Alert, EventRecord, SearchJob, WindowState
from aegis.detection import SQLState, evaluate
from aegis.rules import builtin_rules
from aegis.schemas import EventInput, parse_query
from aegis.simulation import simulate
from aegis.worker import process_once
from tests.test_pipeline import attack_chain


def test_detection_commits_during_search_outage(system):
    class Offline:
        def index(self, *_):
            raise ConnectionError("offline")

    events = simulate("attack-chain")
    client = system["client"]
    client.post(
        "/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]}
    ).raise_for_status()
    assert process_once(system["settings"], system["app"].state.sessions, Offline()) == 16
    assert client.get("/api/v1/incidents").json()["items"]
    with system["app"].state.sessions() as db:
        assert all(row.state == "PROCESSED" for row in db.scalars(select(EventRecord)))
        assert all(row.state == "RETRY" for row in db.scalars(select(SearchJob)))


def test_rollback_cannot_leak_correlation_state_or_alerts(system, monkeypatch):
    import aegis.worker as worker

    real_detect = worker.detect_batch
    events = simulate("brute-force")
    system["client"].post(
        "/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]}
    ).raise_for_status()

    def fail_after_detection(*args, **kwargs):
        real_detect(*args, **kwargs)
        raise RuntimeError("crash before commit")

    monkeypatch.setattr(worker, "detect_batch", fail_after_detection)
    assert process_once(system["settings"], system["app"].state.sessions, system["app"].state.storage) == 0
    with system["app"].state.sessions.begin() as db:
        assert list(db.scalars(select(Alert))) == []
        assert list(db.scalars(select(WindowState).where(WindowState.key.not_like("aegis:rate:%")))) == []
        assert list(db.scalars(select(SearchJob))) == []
        for row in db.scalars(select(EventRecord)):
            row.available_at = 0
    monkeypatch.setattr(worker, "detect_batch", real_detect)
    assert process_once(system["settings"], system["app"].state.sessions, system["app"].state.storage) == 12
    assert system["client"].get("/api/v1/alerts").json()["items"]


def test_poison_event_does_not_consume_valid_sibling_retries(system, monkeypatch):
    import aegis.worker as worker

    real_detect = worker.detect_batch
    events = [
        EventInput(
            source="poison-test", source_sequence=str(i), raw_event={"message": "bad" if i == 1 else "good"}
        )
        for i in range(3)
    ]
    result = (
        system["client"]
        .post("/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]})
        .json()
    )
    poison = result["accepted"][1]

    def detect(*args, **kwargs):
        if any(record.id == poison for record in args[2]):
            raise ValueError("poison event")
        real_detect(*args, **kwargs)

    monkeypatch.setattr(worker, "detect_batch", detect)
    assert process_once(system["settings"], system["app"].state.sessions, system["app"].state.storage) == 2
    with system["app"].state.sessions() as db:
        for row in db.scalars(select(EventRecord)):
            assert (row.state, row.attempts) == (("RETRY", 1) if row.id == poison else ("PROCESSED", 0))


def test_sequence_detects_second_chain_in_same_window(system):
    rule = next(rule for rule in builtin_rules() if rule.id == "AEGIS-AUTH-003")
    stamp = datetime.now(UTC)
    with system["app"].state.sessions() as db:
        state = SQLState(db)
        matches = []
        for index, outcome in enumerate(["failure"] * 3 + ["success"] + ["failure"] * 3 + ["success"]):
            event = {
                "event_id": str(index),
                "timestamp": (stamp + timedelta(seconds=index)).isoformat(),
                "source_ip": "192.0.2.1",
                "event_category": "authentication",
                "outcome": outcome,
            }
            result = evaluate(rule, event, state, "second-chain")
            if result:
                matches.append(result)
        assert len(matches) == 2
        assert matches[1]["event_ids"] == ["4", "5", "6", "7"]


def test_late_event_does_not_erase_newer_state_and_overflow_is_explicit(system):
    stamp = datetime.now(UTC)
    with system["app"].state.sessions() as db:
        state = SQLState(db, lateness=20, limit=2)

        def event(index):
            return {"event_id": str(index), "timestamp": (stamp + timedelta(seconds=index)).isoformat()}

        state.append("late", event(10), 60)
        assert [item["event_id"] for item in state.append("late", event(1), 60)] == ["1"]
        assert [item["event_id"] for item in state.append("late", event(10), 60)] == ["1", "10"]
        with pytest.raises(ValueError, match="capacity"):
            state.append("late", event(11), 60)


@pytest.mark.parametrize(
    "permissions,path",
    [
        (["events.read"], "investigations/{alert}"),
        (["alerts.read"], "dashboard"),
        (["entities.read"], "entities/{entity}"),
    ],
)
def test_scoped_keys_cannot_escalate_through_composite_responses(system, permissions, path):
    attack_chain(system)
    client = system["client"]
    alert = client.get("/api/v1/alerts").json()["items"][0]["id"]
    entity = client.get("/api/v1/entities").json()["items"][0]["id"]
    key = client.post(
        "/api/v1/auth/api-keys", json={"name": "restricted", "permissions": permissions}
    ).json()["key"]
    client.headers["Authorization"] = "Bearer " + key
    assert client.get("/api/v1/" + path.format(alert=alert, entity=entity)).status_code == 403


def test_health_queue_is_tenant_scoped(system):
    attack_chain(system)
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert client.get("/api/v1/system/health").json()["queue"] == {}


def test_duplicate_ingest_accepted_at_backpressure_limit(system):
    events = simulate("benign")
    client = system["client"]
    body = {"events": [event.model_dump(mode="json") for event in events]}
    client.post("/api/v1/events/ingest", json=body).raise_for_status()
    system["settings"].queue_capacity = 1
    result = client.post("/api/v1/events/ingest", json=body)
    assert result.status_code == 202
    assert len(result.json()["duplicates"]) == 3


def test_time_query_cannot_overflow_or_accept_space_unit():
    for query in ("timestamp > now()-999999999999999999999h", "timestamp > now()-5 "):
        with pytest.raises(ValueError):
            parse_query(query)


def test_event_record_evidence_hash_integrity(system):
    """Verify that ingested event records strictly bind evidence_hash to digest(raw_event)."""
    from aegis.parsers import digest

    events = simulate("benign")
    client = system["client"]
    client.post(
        "/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]}
    ).raise_for_status()

    with system["app"].state.sessions() as db:
        records = list(db.scalars(select(EventRecord)))
        assert len(records) > 0
        for rec in records:
            raw = rec.payload.get("raw_event") if isinstance(rec.payload, dict) else None
            assert raw is not None, "EventRecord payload must contain raw_event"
            assert digest(raw) == rec.evidence_hash, "Evidence hash must match digest(raw_event)"


def test_event_record_evidence_tampering_and_recovery_verification(system):
    """Verify that tampering with raw_event, evidence_hash, or omitting raw_event
    is strictly detected by the recovery drill verification invariant.
    """
    from aegis.parsers import digest

    events = simulate("benign")
    client = system["client"]
    client.post(
        "/api/v1/events/ingest", json={"events": [event.model_dump(mode="json") for event in events]}
    ).raise_for_status()

    def verify_record(rec):
        raw = rec.payload.get("raw_event") if isinstance(rec.payload, dict) else None
        if raw is None or digest(raw) != rec.evidence_hash:
            raise RuntimeError("Evidence hash mismatch")

    with system["app"].state.sessions() as db:
        record = db.scalars(select(EventRecord)).first()
        assert record is not None
        # Untampered record passes verification
        verify_record(record)

    # 1. Tampered payload content
    with system["app"].state.sessions.begin() as db:
        rec = db.scalars(select(EventRecord)).first()
        rec.payload = {**rec.payload, "raw_event": "tampered_raw_message"}

    with system["app"].state.sessions() as db:
        rec = db.scalars(select(EventRecord)).first()
        with pytest.raises(RuntimeError, match="Evidence hash mismatch"):
            verify_record(rec)

    # 2. Tampered evidence_hash
    with system["app"].state.sessions.begin() as db:
        rec = db.scalars(select(EventRecord)).first()
        rec.evidence_hash = "0" * 64

    with system["app"].state.sessions() as db:
        rec = db.scalars(select(EventRecord)).first()
        with pytest.raises(RuntimeError, match="Evidence hash mismatch"):
            verify_record(rec)

    # 3. Missing raw_event
    with system["app"].state.sessions.begin() as db:
        rec = db.scalars(select(EventRecord)).first()
        rec.payload = {"message": "missing_raw_event_key"}

    with system["app"].state.sessions() as db:
        rec = db.scalars(select(EventRecord)).first()
        with pytest.raises(RuntimeError, match="Evidence hash mismatch"):
            verify_record(rec)
