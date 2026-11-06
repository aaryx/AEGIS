"""Phase 5 Ingestion, Resource Exhaustion and Resilience Test Suite.

Validates DoS defenses, payload validation limits, admission control,
idempotency, clock skew enforcement, and measured throughput:
1. Oversized event payloads (>256KB) rejected before DB write (422)
2. Excessive string length (>64KB) rejected by StrictModel (422)
3. Deeply nested JSON (>20 levels) rejected before DB write (422)
4. Naive timestamp (missing timezone) rejected before DB write (422)
5. Future clock skew limit (>5 minutes) rejected with 422; valid past timestamps accepted
6. Batch size limit enforcement: batches > 2000 events rejected (422)
7. Admission control queue saturation: returns 503 with Retry-After when queue is full
8. Repeated duplicate event ingestion: idempotent deduplication, zero redundant DB rows
9. Bounded load micro-benchmark: measures throughput (events/sec) and latency (ms)
"""

import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from aegis.db import EventRecord


def test_ingestion_rejects_oversized_payload(system):
    """Payloads exceeding 262,144 bytes (256KB) are rejected by bounded_json validator with 422."""
    client = system["client"]
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    # Generate oversized payload (~300KB)
    large_string = "A" * (300 * 1024)
    payload = {
        "events": [
            {
                "source": "collector-big",
                "source_type": "json",
                "timestamp": datetime.now(UTC).isoformat(),
                "raw_event": {"data": large_string},
            }
        ]
    }
    resp = client.post("/api/v1/events/ingest", json=payload)
    assert resp.status_code == 422
    assert "body.events.0.raw_event" in resp.json()["error"]["message"]


def test_ingestion_rejects_excessive_string_length(system):
    """Strings exceeding 65,536 characters are rejected by StrictModel config with 422."""
    client = system["client"]
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    oversized_source = "S" * 70000
    payload = {
        "events": [
            {
                "source": oversized_source,
                "source_type": "json",
                "timestamp": datetime.now(UTC).isoformat(),
                "raw_event": {"event": "test"},
            }
        ]
    }
    resp = client.post("/api/v1/events/ingest", json=payload)
    assert resp.status_code == 422
    assert "body.events.0.source" in resp.json()["error"]["message"]


def test_ingestion_rejects_deeply_nested_json(system):
    """JSON structures nested deeper than 20 levels are rejected before database insertion with 422."""
    client = system["client"]
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    # Build 25 levels of nested JSON
    nested_event = {"bottom": "target"}
    for i in range(25):
        nested_event = {f"level_{i}": nested_event}

    payload = {
        "events": [
            {
                "source": "collector-nested",
                "source_type": "json",
                "timestamp": datetime.now(UTC).isoformat(),
                "raw_event": nested_event,
            }
        ]
    }
    resp = client.post("/api/v1/events/ingest", json=payload)
    assert resp.status_code == 422
    assert "body.events.0.raw_event" in resp.json()["error"]["message"]


def test_ingestion_rejects_naive_timestamp(system):
    """Timestamps lacking explicit UTC/timezone offset are rejected with 422."""
    client = system["client"]
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    payload = {
        "events": [
            {
                "source": "collector-naive",
                "source_type": "json",
                "timestamp": "2026-10-20T10:00:00",  # Missing timezone offset
                "raw_event": {"event": "naive-ts"},
            }
        ]
    }
    resp = client.post("/api/v1/events/ingest", json=payload)
    assert resp.status_code == 422
    assert "body.events.0.timestamp" in resp.json()["error"]["message"]


def test_ingestion_clock_skew_and_historical_timestamp_handling(system):
    """Past timestamps are accepted; timestamps exceeding allowed future clock skew (>5min) are rejected."""
    client = system["client"]
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    now_utc = datetime.now(UTC)

    # 1. Historical timestamp (1 year ago) is accepted
    past_payload = {
        "events": [
            {
                "source": "collector-past",
                "source_type": "json",
                "timestamp": (now_utc - timedelta(days=365)).isoformat(),
                "raw_event": {"historical": True},
            }
        ]
    }
    resp_past = client.post("/api/v1/events/ingest", json=past_payload)
    assert resp_past.status_code == 202
    assert len(resp_past.json()["accepted"]) == 1

    # 2. Future timestamp exceeding 5 minutes skew is rejected with 422
    future_payload = {
        "events": [
            {
                "source": "collector-future",
                "source_type": "json",
                "timestamp": (now_utc + timedelta(hours=2)).isoformat(),
                "raw_event": {"future": True},
            }
        ]
    }
    resp_future = client.post("/api/v1/events/ingest", json=future_payload)
    assert resp_future.status_code == 422
    assert "Input failed validation" in resp_future.json()["error"]["message"]


def test_ingestion_rejects_batch_exceeding_2000_events(system):
    """Batches exceeding 2,000 events are rejected before processing with 422."""
    client = system["client"]
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    # IngestBatch model restricts list length to max 2000
    events = [
        {
            "source": f"collector-{i}",
            "source_type": "json",
            "timestamp": datetime.now(UTC).isoformat(),
            "raw_event": {"index": i},
        }
        for i in range(2001)
    ]
    resp = client.post("/api/v1/events/ingest", json={"events": events})
    assert resp.status_code == 422
    assert "body.events" in resp.json()["error"]["message"]


def test_admission_control_queue_saturation(system):
    """When tenant pending queue exceeds capacity, ingestion fails closed with 503 Retry-After."""
    client = system["client"]
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    # Temporarily set queue_capacity to 5 for test
    orig_capacity = settings.queue_capacity
    settings.queue_capacity = 5

    try:
        # Pre-fill queue with 5 pending events in DB
        with sessions.begin() as db:
            for i in range(5):
                ev = EventRecord(
                    id=f"EV-SAT-{i}",
                    organization_id=org_id,
                    source="saturation-test",
                    timestamp=datetime.now(UTC),
                    payload={"sat": i},
                    evidence_hash=f"hash-{i}",
                    state="PENDING",
                )
                db.add(ev)

        # Attempt to ingest more events when queue is already at capacity
        client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"
        payload = {
            "events": [
                {
                    "source": "collector-overflow",
                    "source_type": "json",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "raw_event": {"overflow": True},
                }
            ]
        }
        resp = client.post("/api/v1/events/ingest", json=payload)
        assert resp.status_code == 503
        assert "Tenant ingestion/search backlog is full" in resp.json()["error"]["message"]
        assert resp.headers.get("retry-after") == "10"
    finally:
        settings.queue_capacity = orig_capacity


def test_repeated_duplicate_event_ingestion_idempotency(system):
    """Submitting duplicate events does not generate redundant database rows or corrupt state."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"
    ts = datetime.now(UTC).isoformat()
    event_item = {
        "source": "syslog-firewall",
        "source_type": "json",
        "timestamp": ts,
        "raw_event": {"event_id": 100, "action": "blocked", "ip": "198.51.100.22"},
    }

    # First ingestion
    resp1 = client.post("/api/v1/events/ingest", json={"events": [event_item]})
    assert resp1.status_code == 202
    assert len(resp1.json()["accepted"]) == 1
    event_id = resp1.json()["accepted"][0]

    # Duplicate ingestion with identical content: returned as duplicate, zero redundant inserts
    resp2 = client.post("/api/v1/events/ingest", json={"events": [event_item]})
    assert resp2.status_code == 202
    assert resp2.json()["accepted"] == []
    assert resp2.json()["duplicates"] == [event_id]

    # Verify database state: exactly 1 record exists in DB for this event_id
    with sessions() as db:
        count = db.scalar(select(func.count()).where(EventRecord.id == event_id, EventRecord.organization_id == org_id))
        assert count == 1


def test_ingestion_throughput_and_latency_microbenchmark(system):
    """Measures ingestion throughput (events/sec) and latency (ms) under synthetic load."""
    client = system["client"]
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    # Generate synthetic batch of 100 events
    batch_size = 100
    events = [
        {
            "source": f"benchmark-agent-{i % 10}",
            "source_type": "json",
            "timestamp": datetime.now(UTC).isoformat(),
            "raw_event": {
                "process_id": 1000 + i,
                "process_name": "svchost.exe",
                "command_line": f"svchost.exe -k netsvcs -p -s BcastDVRUserService_{i}",
                "user": "NT AUTHORITY\\SYSTEM",
            },
        }
        for i in range(batch_size)
    ]

    start_time = time.monotonic()
    resp = client.post("/api/v1/events/ingest", json={"events": events})
    duration = time.monotonic() - start_time

    assert resp.status_code == 202
    accepted_count = len(resp.json()["accepted"])
    assert accepted_count == batch_size

    # Calculate and verify throughput metrics
    throughput_eps = accepted_count / duration
    latency_per_event_ms = (duration / accepted_count) * 1000

    assert duration < 5.0, f"Ingestion took {duration:.2f}s, exceeding 5.0s limit"
    assert throughput_eps > 20.0, f"Throughput {throughput_eps:.1f} events/s below baseline"
    assert latency_per_event_ms > 0.0
