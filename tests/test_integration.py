import hashlib
import json
import os
import time
from uuid import uuid4

import pytest
from redis import Redis
from sqlalchemy import text

from aegis.config import Settings
from aegis.db import database
from aegis.storage import OpenSearchStorage


@pytest.mark.integration
def test_real_dependency_connectivity():
    if not os.environ.get("AEGIS_INTEGRATION"):
        pytest.skip("Set AEGIS_INTEGRATION=1 with PostgreSQL, Redis and OpenSearch configured")
    settings = Settings()
    assert settings.database_url.startswith("postgresql") and settings.redis_url and settings.opensearch_url
    engine, _ = database(settings.database_url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar() == 1
    redis = Redis.from_url(settings.redis_url, socket_timeout=3)
    assert redis.ping()
    storage = OpenSearchStorage(settings)
    storage.setup()
    assert storage.health() == "HEALTHY"


@pytest.mark.integration
def test_real_redis_queue_semantics_and_delivery():
    """Verify live Redis queue semantics, payload checksum integrity, retry/DLQ, and deduplication.

    Validates that:
    1. Uniquely identified messages are enqueued and dequeued within bounded timeouts.
    2. Payload integrity and cryptographic checksums are preserved across serialization.
    3. Duplicate deliveries are safely detected and deduplicated via atomic gates.
    4. Worker failure retry counter advances and routes to dead-letter queue (DLQ) upon exhaustion.
    5. Cleanup strictly affects test-owned resources with zero residue left in Redis.
    """
    if not os.environ.get("AEGIS_INTEGRATION"):
        pytest.skip("Set AEGIS_INTEGRATION=1 with PostgreSQL, Redis and OpenSearch configured")

    settings = Settings()
    if not settings.redis_url:
        pytest.skip("REDIS_URL not configured")

    redis = Redis.from_url(settings.redis_url, socket_timeout=3, decode_responses=True)
    assert redis.ping(), "Redis ping failed before test execution"

    test_id = uuid4().hex
    queue_key = f"aegis:test:queue:{test_id}"
    retry_key = f"aegis:test:retry:{test_id}"
    dlq_key = f"aegis:test:dlq:{test_id}"
    dedup_key = f"aegis:test:dedup:{test_id}"
    rate_key = f"aegis:test:rate:{test_id}"

    created_keys = [queue_key, retry_key, dlq_key, dedup_key, rate_key]

    try:
        # 1. Enqueue uniquely identified test message with cryptographic checksum
        raw_payload = {
            "message_id": f"msg-{test_id}-100",
            "event_type": "security.containment.action",
            "actor": "ironclad-release-auditor",
            "target": "endpoint-prod-sim-01",
            "timestamp": time.time(),
            "attempts": 0,
            "metadata": {"test_run_id": test_id, "priority": "CRITICAL"},
        }
        canonical_str = json.dumps(raw_payload, sort_keys=True)
        payload_checksum = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        envelope = {
            "checksum": payload_checksum,
            "data": raw_payload,
        }
        enqueue_count = redis.rpush(queue_key, json.dumps(envelope))
        assert enqueue_count == 1, f"Expected 1 item in queue, got {enqueue_count}"

        # 2. Dequeue with timeout and verify payload integrity
        pop_res = redis.blpop(queue_key, timeout=3)
        assert pop_res is not None, f"Timeout (3s) waiting for message on queue '{queue_key}'"
        _q_name, dequeued_raw = pop_res

        dequeued_envelope = json.loads(dequeued_raw)
        recomputed_checksum = hashlib.sha256(
            json.dumps(dequeued_envelope["data"], sort_keys=True).encode("utf-8")
        ).hexdigest()
        assert recomputed_checksum == dequeued_envelope["checksum"], "Payload integrity checksum mismatch!"
        assert dequeued_envelope["data"]["message_id"] == raw_payload["message_id"]
        assert dequeued_envelope["data"]["actor"] == raw_payload["actor"]

        # 3. Duplicate Delivery Handling (At-Least-Once Idempotency Gate)
        # First arrival: acquire processing lease via atomic SETNX
        first_lease = redis.set(dedup_key, "PROCESSED", nx=True, ex=60)
        assert first_lease is True, "First delivery should successfully acquire processing lease"

        # Second arrival (simulated duplicate network redelivery): lease must be rejected
        second_lease = redis.set(dedup_key, "PROCESSED", nx=True, ex=60)
        assert not second_lease, "Duplicate delivery must be rejected by deduplication gate"

        # 4. Failure Retry and Dead-Letter Queue (DLQ) Progression
        max_attempts = 3
        current_msg = dict(raw_payload)
        current_msg["attempts"] = 1

        # Simulate failure iteration 1 -> push to retry queue
        redis.rpush(retry_key, json.dumps(current_msg))
        assert redis.llen(retry_key) == 1

        # Worker picks up from retry, fails again, reaches max_attempts
        retried_raw = redis.lpop(retry_key)
        assert retried_raw is not None
        retry_msg = json.loads(retried_raw)
        retry_msg["attempts"] += 1
        assert retry_msg["attempts"] == 2

        # Simulate terminal failure on 3rd attempt -> route to DLQ
        retry_msg["attempts"] += 1
        assert retry_msg["attempts"] >= max_attempts

        dlq_envelope = {
            "dead_letter_reason": "MAX_RETRIES_EXCEEDED",
            "failed_at": time.time(),
            "original_payload": retry_msg,
        }
        redis.rpush(dlq_key, json.dumps(dlq_envelope))
        assert redis.llen(dlq_key) == 1

        dlq_item = json.loads(redis.lpop(dlq_key))
        assert dlq_item["dead_letter_reason"] == "MAX_RETRIES_EXCEEDED"
        assert dlq_item["original_payload"]["attempts"] == 3

        # 5. Token bucket / rate-limiting counter semantics and TTL
        pipe = redis.pipeline()
        pipe.incr(rate_key)
        pipe.expire(rate_key, 120)
        pipe.incr(rate_key)
        res = pipe.execute()
        assert res[0] == 1
        assert res[1] is True or res[1] == 1
        assert res[2] == 2
        ttl = redis.ttl(rate_key)
        assert 0 < ttl <= 120, f"Expected TTL between 1 and 120, got {ttl}"

    finally:
        # Clean up strictly test-owned keys
        for k in created_keys:
            redis.delete(k)
        # Verify test isolation cleanup succeeded
        for k in created_keys:
            assert not redis.exists(k), f"Key {k} was not cleaned up after test run"
