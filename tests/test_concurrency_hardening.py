"""Concurrency and stress tests for rate limiting, audit hash chain, and detection window state (P0 & P1).
"""

import concurrent.futures
import time
from unittest.mock import MagicMock

from aegis.detection import SQLState
from aegis.security import audit, rate_limit, verify_audit


def test_concurrent_rate_limiting_fallback_no_duplicate_key_exceptions(system):
    """Concurrent first-time requests for the same bucket must not raise duplicate key IntegrityError."""
    app = system["app"]
    # Ensure Redis is None so it tests the database fallback
    assert app.state.redis is None

    # Dummy request with app state
    dummy_request = MagicMock()
    dummy_request.app = app

    bucket_key = f"concurrent-bucket-{time.time()}"
    num_threads = 10
    exceptions = []

    def make_rate_limited_call():
        try:
            rate_limit(dummy_request, bucket_key, maximum=50, seconds=60)
            return True
        except Exception as exc:
            exceptions.append(exc)
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(make_rate_limited_call) for _ in range(num_threads)]
        results = [f.result() for f in futures]

    assert len(exceptions) == 0, f"Exceptions occurred during concurrent rate limit: {exceptions}"
    assert all(results)


def test_concurrent_audit_writes_chain_integrity(system):
    """Concurrent audit log entries must preserve hash-chain sequence and verify cleanly."""
    settings = system["app"].state.settings
    org_id = system["org"]
    num_writes = 15

    def write_audit_entry(idx):
        with system["app"].state.sessions.begin() as db:
            audit(
                db,
                settings,
                org_id,
                actor=f"user-{idx}",
                action=f"action-{idx}",
                resource_id=f"res-{idx}",
                details={"idx": idx},
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(write_audit_entry, i) for i in range(num_writes)]
        for f in futures:
            f.result()

    with system["app"].state.sessions() as db:
        valid = verify_audit(db, settings, org_id)
        assert valid is True, "Audit chain verification failed after concurrent writes"


def test_concurrent_detection_window_state_append(system):
    """Concurrent appends to SQLState window state must not lose updates."""
    from datetime import UTC, datetime

    from aegis.db import WindowState

    sessions = system["app"].state.sessions
    rule_key = f"rule:concurrent-test:{time.time()}"
    num_events = 20

    def append_event(idx):
        with sessions.begin() as db:
            state = SQLState(db)
            state.append(
                rule_key,
                {"event_id": f"event-{idx}", "timestamp": datetime.now(UTC).isoformat()},
                window=600,
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(append_event, i) for i in range(num_events)]
        for f in futures:
            f.result()

    # Query window state from database
    with sessions() as db:
        row = db.get(WindowState, rule_key)
        assert row is not None
        assert len(row.data) == num_events, f"Expected {num_events} items in window state, got {len(row.data)}"
        event_ids = {item["event_id"] for item in row.data}
        for i in range(num_events):
            assert f"event-{i}" in event_ids
