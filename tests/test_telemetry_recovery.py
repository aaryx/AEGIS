"""Comprehensive qualification tests for telemetry delivery, failure recovery, and isolation.

Validates:
A. Collector restart (pre-delivery and post-persistence crash windows).
B. Log rotation (rename-and-replace, truncation, incomplete lines).
C. API outages (transient 503/network failures, durable spooling, backlog recovery).
D. Poison records and oversized line isolation (batch splitting, quarantining).
E. Capacity limits and tenant/collector identity isolation.
F. Trust Boundary 1: Adversarial cross-tenant delivery prevention before transmission.
G. Trust Boundary 2: Record-level acknowledgment verification by identity (multiplicity, disjoint, exact deterministic UUIDv5 mapping).
H. Crash atomicity & migration: Inode priority, path-keyed spool upgrade, and unbound spool protection.
"""

import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.collector import FileCollector
from aegis.config import Settings
from aegis.db import Base, Organization, User, database
from aegis.parsers import compute_event_id
from aegis.pipeline import seed_rules
from aegis.schemas import EventInput
from aegis.security import PASSWORDS, issue_session


def test_collector_restart_pre_delivery(tmp_path: Path):
    """Restarting collector before flush preserves spool rows and checkpoint."""
    log = tmp_path / "service.log"
    spool = tmp_path / "spool.db"
    log.write_text("event 1\nevent 2\nevent 3\n")

    c1 = FileCollector(spool, "collector-restart-1", tenant_id="test-org")
    assert c1.collect(log) == 3
    assert c1.status() == {"PENDING": 3}
    c1.close()

    # Re-open after restart
    c2 = FileCollector(spool, "collector-restart-1", tenant_id="test-org")
    assert c2.collect(log) == 0  # Checkpoint retained, no duplicate spooling
    assert c2.status() == {"PENDING": 3}

    # Flush delivers all 3
    flushed = []

    def handler(request: httpx.Request):
        data = json.loads(request.content)
        flushed.extend(data["events"])
        return httpx.Response(
            202,
            json={
                "accepted": [
                    compute_event_id("test-org", EventInput.model_validate(e)) for e in data["events"]
                ],
                "duplicates": [],
                "organization_id": "test-org",
            },
        )

    with httpx.Client(base_url="http://localhost/api/v1/", transport=httpx.MockTransport(handler)) as client:
        assert c2.flush(client, "valid-token") == 3
        assert len(flushed) == 3
        assert c2.status() == {}

    c2.close()


def test_collector_crash_post_persistence_pre_ack_deduplication(tmp_path: Path):
    """Crash after API persistence but before local spool deletion recovers via deduplication."""
    log = tmp_path / "service.log"
    spool = tmp_path / "spool.db"
    log.write_text("event A\nevent B\n")

    c1 = FileCollector(spool, "collector-dedup", tenant_id="test-org")
    assert c1.collect(log) == 2

    persisted_ids = set()
    attempt = 0

    def simulated_api(request: httpx.Request):
        nonlocal attempt
        attempt += 1
        data = json.loads(request.content)
        accepted, duplicates = [], []
        for ev in data["events"]:
            eid = compute_event_id("test-org", EventInput.model_validate(ev))
            if eid in persisted_ids:
                duplicates.append(eid)
            else:
                persisted_ids.add(eid)
                accepted.append(eid)

        if attempt == 1:
            # Simulate network/process crash right after server persisted and returned 202,
            # but before client could process the response body or execute DELETE
            raise httpx.ReadTimeout("Connection dropped after server commit")

        return httpx.Response(
            202,
            json={"accepted": accepted, "duplicates": duplicates, "organization_id": "test-org"},
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(simulated_api)
    ) as client:
        # First flush attempt crashes due to ReadTimeout
        assert c1.flush(client, "test-token") == 0
        # Spool still has records as PENDING
        assert c1.status() == {"PENDING": 2}
        c1.close()

        # Restart collector after crash
        c2 = FileCollector(spool, "collector-dedup", tenant_id="test-org")
        c2.db.execute("UPDATE spool SET available_at=0")
        c2.db.commit()

        # Second flush attempt: API recognizes them as duplicates and client deletes from spool
        assert c2.flush(client, "test-token") == 2
        assert c2.status() == {}
        # Server only persisted them once
        assert len(persisted_ids) == 2

    c2.close()


def test_log_rotation_rename_and_replace_both_orders(tmp_path: Path):
    """Rename-and-replace log rotation preserves unread records and avoids duplicate spooling."""
    for order in ["active_first", "rotated_first"]:
        sub = tmp_path / order
        sub.mkdir()
        spool = sub / "spool.db"
        active = sub / "active.log"
        active.write_text("line 1\nline 2\n")

        collector = FileCollector(spool, "rotation-test", tenant_id="test-org")
        assert collector.collect(active) == 2

        # Append unread line before rotation
        with active.open("a") as f:
            f.write("line 3\n")

        # Rotate: rename active -> active.log.1 and create new active
        rotated = sub / "active.log.1"
        active.rename(rotated)
        active.write_text("new active 1\nnew active 2\n")

        if order == "active_first":
            c_act = collector.collect(active)
            c_rot = collector.collect(rotated)
        else:
            c_rot = collector.collect(rotated)
            c_act = collector.collect(active)

        assert c_act == 2
        assert c_rot == 1  # Only the unread line 3 was spooled, lines 1 and 2 not duplicated!

        # Total events in spool must be exactly 5
        rows = collector.db.execute("SELECT payload FROM spool ORDER BY id").fetchall()
        payloads = [json.loads(r[0])["raw_event"] for r in rows]
        assert "line 1" in payloads
        assert "line 2" in payloads
        assert "line 3" in payloads
        assert "new active 1" in payloads
        assert "new active 2" in payloads
        assert len(payloads) == 5
        collector.close()


def test_log_truncation_resets_checkpoint(tmp_path: Path):
    """In-place truncation resets generation and offset, collecting fresh records from byte 0."""
    log = tmp_path / "truncated.log"
    spool = tmp_path / "spool.db"
    log.write_text("first run line 1\nfirst run line 2\n")

    collector = FileCollector(spool, "truncation-col", tenant_id="test-org")
    assert collector.collect(log) == 2

    # Truncate and write shorter content
    log.write_text("truncated line 1\n")
    assert collector.collect(log) == 1

    payloads = [json.loads(r[0]) for r in collector.db.execute("SELECT payload FROM spool ORDER BY id")]
    assert len(payloads) == 3
    assert payloads[2]["raw_event"] == "truncated line 1"
    # Sequences must use different generations
    gen1 = payloads[0]["source_sequence"].split(":")[0]
    gen2 = payloads[2]["source_sequence"].split(":")[0]
    assert gen1 != gen2
    collector.close()


def test_incomplete_trailing_line_retained_until_newline(tmp_path: Path):
    """Incomplete lines without trailing newline are not spooled until completed."""
    log = tmp_path / "partial.log"
    spool = tmp_path / "spool.db"
    log.write_bytes(b"complete line 1\nincomplete par")

    collector = FileCollector(spool, "partial-col", tenant_id="test-org")
    assert collector.collect(log) == 1
    assert collector.status() == {"PENDING": 1}

    # Second collect without new data reads 0
    assert collector.collect(log) == 0

    # Complete the line
    with log.open("ab") as f:
        f.write(b"tial finished\n")

    assert collector.collect(log) == 1
    rows = collector.db.execute("SELECT payload FROM spool ORDER BY id").fetchall()
    payloads = [json.loads(r[0])["raw_event"] for r in rows]
    assert payloads == ["complete line 1", "incomplete partial finished"]
    collector.close()


def test_api_outage_backpressure_and_backlog_recovery(tmp_path: Path):
    """Transient API 503 outage applies exponential backoff, preserves spool, and recovers."""
    log = tmp_path / "outage.log"
    spool = tmp_path / "spool.db"
    log.write_text("rec 1\nrec 2\n")

    collector = FileCollector(spool, "outage-col", tenant_id="test-org")
    collector.collect(log)
    assert collector.status() == {"PENDING": 2}

    api_online = False
    delivered = []

    def mock_server(request: httpx.Request):
        if not api_online:
            return httpx.Response(503, content="Service Unavailable")
        data = json.loads(request.content)
        delivered.extend(data["events"])
        return httpx.Response(
            202,
            json={
                "accepted": [
                    compute_event_id("test-org", EventInput.model_validate(ev)) for ev in data["events"]
                ],
                "duplicates": [],
                "organization_id": "test-org",
            },
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(mock_server)
    ) as client:
        # Outage: flush fails
        assert collector.flush(client, "test-token") == 0
        assert collector.status() == {"PENDING": 2}

        # Items have future available_at
        future = collector.db.execute("SELECT min(available_at) FROM spool").fetchone()[0]
        assert future > 0

        # Attempting flush before backoff yields 0 without network call
        assert collector.flush(client, "test-token") == 0

        # Restore API and reset available_at
        api_online = True
        collector.db.execute("UPDATE spool SET available_at=0")
        collector.db.commit()

        # Flushes backlog
        assert collector.flush(client, "test-token") == 2
        assert len(delivered) == 2
        assert collector.status() == {}

    collector.close()


def test_poison_record_isolation_via_batch_splitting(tmp_path: Path):
    """Batch containing a poison record splits down to limit=1 to isolate and quarantine it."""
    log = tmp_path / "poison.log"
    spool = tmp_path / "spool.db"
    log.write_text("valid-1\npoison-bad-schema\nvalid-2\n")

    collector = FileCollector(spool, "poison-col", tenant_id="test-org")
    collector.collect(log)
    assert collector.status() == {"PENDING": 3}

    delivered = []

    def mock_server(request: httpx.Request):
        data = json.loads(request.content)
        # If poison event is present in the batch, reject entire batch with 422
        if any("poison" in ev["raw_event"] for ev in data["events"]):
            return httpx.Response(
                422,
                json={"error": {"code": "VALIDATION_ERROR", "message": "Malformed event payload"}},
            )
        delivered.extend(data["events"])
        return httpx.Response(
            202,
            json={
                "accepted": [
                    compute_event_id("test-org", EventInput.model_validate(ev)) for ev in data["events"]
                ],
                "duplicates": [],
                "organization_id": "test-org",
            },
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(mock_server)
    ) as client:
        # Flush of batch with 3 records encounters 422, splits to limit=1, delivers 2 and quarantines 1
        flushed_count = collector.flush(client, "test-token", limit=10)
        assert flushed_count == 2
        assert len(delivered) == 2
        assert collector.status() == {"QUARANTINED": 1}

        # Check quarantined record
        q_row = collector.db.execute(
            "SELECT payload, error, state FROM spool WHERE state='QUARANTINED'"
        ).fetchone()
        assert q_row[1] == "HTTP_422"
        assert "poison" in json.loads(q_row[0])["raw_event"]

    collector.close()


def test_oversized_log_line_does_not_block_subsequent_events(tmp_path: Path):
    """Oversized line is quarantined in spool without deadlocking subsequent valid lines."""
    log = tmp_path / "oversized.log"
    spool = tmp_path / "spool.db"

    # Set max_event_bytes to 50 for testing
    collector = FileCollector(spool, "oversized-col", max_event_bytes=50, tenant_id="test-org")

    # Line 1: 20 bytes (valid)
    # Line 2: 120 bytes (oversized)
    # Line 3: 20 bytes (valid)
    log.write_text("valid line one 12345\n" + ("A" * 120) + "\nvalid line three 123\n")

    # Collect must not raise ValueError and must process all lines
    collected = collector.collect(log)
    assert collected == 3
    assert collector.status() == {"PENDING": 2, "QUARANTINED": 1}

    # Verify quarantined record has diagnosis
    q = collector.db.execute("SELECT payload, error FROM spool WHERE state='QUARANTINED'").fetchone()
    assert q[1] == "OVERSIZED_INPUT"
    raw = json.loads(q[0])["raw_event"]
    assert raw["error"] == "OVERSIZED_INPUT"
    assert raw["bytes"] > 50

    collector.close()


def test_collector_capacity_and_backpressure_properties(tmp_path: Path):
    """Spool capacity exhaustion raises OverflowError and exposes depth and is_full."""
    log = tmp_path / "cap.log"
    spool = tmp_path / "spool.db"
    log.write_text("item 1\nitem 2\nitem 3\n")

    collector = FileCollector(spool, "cap-col", capacity=2, tenant_id="test-org")
    assert collector.depth == 0
    assert not collector.is_full

    assert collector.collect(log) == 2
    assert collector.depth == 2
    assert collector.is_full

    with pytest.raises(OverflowError, match="Collector spool full"):
        collector.collect(log)

    collector.close()


def test_tenant_and_identity_isolation_rejection(tmp_path: Path):
    """Spool rejects re-binding to a different collector name or delivery under a different tenant."""
    spool = tmp_path / "spool.db"

    # 1. Collector identity binding
    c1 = FileCollector(spool, "alpha-collector", tenant_id="org-alpha")
    c1.close()

    with pytest.raises(ValueError, match="Spool is bound to collector identity 'alpha-collector'"):
        FileCollector(spool, "bravo-collector")

    with pytest.raises(ValueError, match="Spool is bound to tenant 'org-alpha'"):
        FileCollector(spool, "alpha-collector", tenant_id="org-beta")

    # 2. Cross-tenant delivery rejection in flush
    log = tmp_path / "sec.log"
    log.write_text("log message\n")
    c_valid = FileCollector(spool, "alpha-collector")
    c_valid.collect(log)

    # Server responding with tenant org-beta when spool is bound to org-alpha
    def rogue_server(request: httpx.Request):
        return httpx.Response(
            202,
            json={"accepted": ["seq-1"], "duplicates": [], "organization_id": "org-beta"},
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(rogue_server)
    ) as client:
        with pytest.raises(
            ValueError, match="Spool is bound to tenant 'org-alpha', rejected delivery under 'org-beta'"
        ):
            c_valid.flush(client, "some-token")

    c_valid.close()


# ==============================================================================
# TRUST BOUNDARY 1: Adversarial Cross-Tenant Delivery Prevention
# ==============================================================================


def test_adversarial_cross_tenant_delivery_blocked_before_persistence(tmp_path: Path):
    """Spool bound to Tenant A flushed with Tenant B credentials is rejected with 403 before persistence."""
    db_file = tmp_path / "two_tenant_adv.db"
    settings = Settings(
        database_url=f"sqlite:///{db_file}",
        jwt_secret="adversarial-test-jwt-secret-min-32-chars",
        audit_hmac_key="adversarial-test-audit-hmac-key",
        queue_capacity=1000,
        max_batch_events=100,
    )
    engine, session_factory = database(settings.database_url)
    Base.metadata.create_all(engine)

    with session_factory() as sess:
        with sess.begin():
            org_a = Organization(name="Tenant Alpha")
            org_b = Organization(name="Tenant Beta")
            sess.add_all([org_a, org_b])
            sess.flush()
            org_a_id, org_b_id = org_a.id, org_b.id

            user_a = User(
                organization_id=org_a_id,
                username="col-admin-a",
                password_hash=PASSWORDS.hash("PassA12345!"),
                role="SECURITY_ADMIN",
            )
            user_b = User(
                organization_id=org_b_id,
                username="col-admin-b",
                password_hash=PASSWORDS.hash("PassB12345!"),
                role="SECURITY_ADMIN",
            )
            sess.add_all([user_a, user_b])
            sess.flush()

            token_a, _ = issue_session(sess, user_a, settings)
            token_b, _ = issue_session(sess, user_b, settings)
            seed_rules(sess, org_a_id)
            seed_rules(sess, org_b_id)

    app = create_app(settings)
    client = TestClient(app, base_url="http://testserver/api/v1/")

    # 1. Collector spools records for Tenant A
    log_file = tmp_path / "tenant_a.log"
    log_file.write_text("Tenant A proprietary auth event 1\nTenant A proprietary auth event 2\n")
    spool_a = tmp_path / "spool_a.db"
    col_a = FileCollector(spool_a, "collector-tenant-a", tenant_id=org_a_id)
    assert col_a.collect(log_file) == 2
    assert col_a.status() == {"PENDING": 2}

    # 2. Adversarial attempt: Flush Tenant A's spool using valid Tenant B credentials
    # The server must reject with 403 Forbidden because X-AEGIS-Tenant-ID != Tenant B's credentials
    delivered = col_a.flush(client, token=token_b)
    assert delivered == 0

    # 3. Assert zero leakage/persistence into Tenant B (or Tenant A)
    with session_factory() as sess:
        from aegis.db import EventRecord

        events_in_b = sess.query(EventRecord).filter(EventRecord.organization_id == org_b_id).count()
        events_in_a = sess.query(EventRecord).filter(EventRecord.organization_id == org_a_id).count()
        assert events_in_b == 0, "Security violation: Tenant A records persisted in Tenant B!"
        assert events_in_a == 0, "Records must not persist under wrong authorization"

    # 4. Assert records remain safely accounted for in Tenant A's local spool
    assert col_a.status() == {"PENDING": 2}

    # Reset available_at to permit immediate retry with legitimate credentials
    col_a.db.execute("UPDATE spool SET available_at=0")
    col_a.db.commit()

    # 5. Legitimate delivery with Tenant A credentials succeeds
    delivered_valid = col_a.flush(client, token=token_a)
    assert delivered_valid == 2
    assert col_a.status() == {}

    # Verify database state after legitimate delivery
    with session_factory() as sess:
        events_in_b = sess.query(EventRecord).filter(EventRecord.organization_id == org_b_id).count()
        events_in_a = sess.query(EventRecord).filter(EventRecord.organization_id == org_a_id).count()
        assert events_in_b == 0
        assert events_in_a == 2

    col_a.close()


# ==============================================================================
# TRUST BOUNDARY 2: Record-Level Acknowledgment Verification by Identity
# ==============================================================================


def test_acknowledgment_unrelated_event_ids_rejected(tmp_path: Path):
    """Responses containing correct counts but unrelated event IDs are rejected without deleting spool records."""
    log = tmp_path / "test.log"
    log.write_text("auth log 1\nauth log 2\n")
    spool = tmp_path / "spool.db"

    col = FileCollector(spool, "col-ack-test", tenant_id="tenant-alpha")
    col.collect(log)
    assert col.status() == {"PENDING": 2}

    # Server returns matching count (2) but completely unrelated/fake UUIDs
    def bogus_server(request: httpx.Request):
        return httpx.Response(
            202,
            json={
                "accepted": [str(uuid4()), str(uuid4())],
                "duplicates": [],
                "organization_id": "tenant-alpha",
            },
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(bogus_server)
    ) as client:
        with pytest.raises(ValueError, match="Unexpected or unrelated acknowledgment IDs in response"):
            col.flush(client, "test-token")

    # Both records remain safely spooled
    assert col.status() == {"PENDING": 2}
    col.close()


def test_acknowledgment_repeated_ids_rejected(tmp_path: Path):
    """Responses with duplicate acknowledgment IDs in accepted list are rejected."""
    log = tmp_path / "test.log"
    log.write_text("event 1\nevent 2\n")
    spool = tmp_path / "spool.db"

    col = FileCollector(spool, "col-rep-test", tenant_id="tenant-alpha")
    col.collect(log)

    def repeated_server(request: httpx.Request):
        data = json.loads(request.content)
        real_id = compute_event_id("tenant-alpha", EventInput.model_validate(data["events"][0]))
        return httpx.Response(
            202,
            json={
                "accepted": [real_id, real_id],  # Repeated ID!
                "duplicates": [],
                "organization_id": "tenant-alpha",
            },
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(repeated_server)
    ) as client:
        with pytest.raises(ValueError, match="Repeated acknowledgment ID in accepted list"):
            col.flush(client, "test-token")

    assert col.status() == {"PENDING": 2}
    col.close()


def test_acknowledgment_overlapping_accepted_and_duplicates_rejected(tmp_path: Path):
    """Responses where an ID appears in both accepted and duplicates are rejected."""
    log = tmp_path / "test.log"
    log.write_text("event 1\n")
    spool = tmp_path / "spool.db"

    col = FileCollector(spool, "col-overlap-test", tenant_id="tenant-alpha")
    col.collect(log)

    def overlap_server(request: httpx.Request):
        data = json.loads(request.content)
        real_id = compute_event_id("tenant-alpha", EventInput.model_validate(data["events"][0]))
        return httpx.Response(
            202,
            json={
                "accepted": [real_id],
                "duplicates": [real_id],  # Overlap!
                "organization_id": "tenant-alpha",
            },
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(overlap_server)
    ) as client:
        with pytest.raises(ValueError, match="appears in both accepted and duplicates"):
            col.flush(client, "test-token")

    assert col.status() == {"PENDING": 1}
    col.close()


def test_acknowledgment_malformed_response_bodies_rejected(tmp_path: Path):
    """Malformed response bodies (not JSON, not dict, invalid list elements) do not discard records."""
    log = tmp_path / "test.log"
    log.write_text("event 1\n")
    spool = tmp_path / "spool.db"

    col = FileCollector(spool, "col-malformed-test", tenant_id="tenant-alpha")
    col.collect(log)

    for malformed in [
        httpx.Response(202, text="not json at all"),
        httpx.Response(202, json=["a", "b"]),  # Not a dict
        httpx.Response(202, json={"accepted": 123, "duplicates": []}),  # Not a list
        httpx.Response(202, json={"accepted": [123], "duplicates": []}),  # Elements not strings
    ]:
        col.db.execute("UPDATE spool SET available_at=0")
        col.db.commit()
        with httpx.Client(
            base_url="http://localhost/api/v1/", transport=httpx.MockTransport(lambda req, m=malformed: m)
        ) as client:
            with pytest.raises(ValueError, match="Malformed response body"):
                col.flush(client, "test-token")

    assert col.status() == {"PENDING": 1}
    col.close()


def test_acknowledgment_partial_incomplete_only_deletes_confirmed(tmp_path: Path):
    """Successful status (202) with incomplete acknowledgments only removes confirmed records; unacknowledged remain."""
    log = tmp_path / "test.log"
    log.write_text("event 1\nevent 2\nevent 3\n")
    spool = tmp_path / "spool.db"

    col = FileCollector(spool, "col-partial-test", tenant_id="tenant-alpha")
    col.collect(log)
    assert col.status() == {"PENDING": 3}

    # API confirms only 2 of the 3 events
    def partial_server(request: httpx.Request):
        data = json.loads(request.content)
        id_1 = compute_event_id("tenant-alpha", EventInput.model_validate(data["events"][0]))
        id_2 = compute_event_id("tenant-alpha", EventInput.model_validate(data["events"][1]))
        return httpx.Response(
            202,
            json={
                "accepted": [id_1],
                "duplicates": [id_2],
                # Third event is omitted
                "organization_id": "tenant-alpha",
            },
        )

    with httpx.Client(
        base_url="http://localhost/api/v1/", transport=httpx.MockTransport(partial_server)
    ) as client:
        deleted = col.flush(client, "test-token")
        assert deleted == 2

    # Exactly 1 unacknowledged record remains in the spool
    assert col.depth == 1
    remaining_row = col.db.execute("SELECT payload, error, state FROM spool").fetchone()
    assert remaining_row[2] == "PENDING"
    assert remaining_row[1] == "IncompleteAcknowledgment"
    assert "event 3" in json.loads(remaining_row[0])["raw_event"]
    col.close()


# ==============================================================================
# CRASH ATOMICITY, UPGRADE & SPOOL PROTECTION
# ==============================================================================


def test_legacy_unbound_spool_cannot_silently_acquire_tenant(tmp_path: Path):
    """An unbound legacy spool cannot silently acquire an unrelated tenant identity from API response."""
    spool = tmp_path / "legacy_unbound.db"
    con = sqlite3.connect(spool)
    con.executescript("""
        CREATE TABLE checkpoints (identity TEXT PRIMARY KEY, path TEXT NOT NULL, generation TEXT NOT NULL, offset INTEGER NOT NULL, prefix_hash TEXT NOT NULL, prefix_length INTEGER NOT NULL);
        CREATE TABLE spool (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING', error TEXT, attempts INTEGER NOT NULL DEFAULT 0, available_at REAL NOT NULL DEFAULT 0);
        INSERT INTO spool(payload) VALUES ('{"source":"file:test","collector":"test","source_type":"generic","source_sequence":"gen:0","timestamp":null,"raw_event":"unbound line"}');
    """)
    con.commit()
    con.close()

    col = FileCollector(spool, "unbound-collector")
    assert col.bound_tenant_id is None

    # Attempt to flush against an endpoint returning organization_id
    def server(request: httpx.Request):
        return httpx.Response(
            202,
            json={"accepted": ["0"], "duplicates": [], "organization_id": "hostile-tenant"},
        )

    with httpx.Client(base_url="http://localhost/api/v1/", transport=httpx.MockTransport(server)) as client:
        with pytest.raises(ValueError, match="Legacy unbound spool cannot silently acquire tenant identity"):
            col.flush(client, "test-token")

    # Verify meta table does not contain hostile-tenant
    row = col.db.execute("SELECT value FROM meta WHERE key='tenant_id'").fetchone()
    assert row is None, "Legacy spool silently acquired tenant identity!"
    assert col.depth == 1
    col.close()


def test_legacy_path_keyed_spool_migration_preserves_records_and_progress(tmp_path: Path):
    """Path-keyed legacy checkpoints table migrates to identity-keyed schema without dropping records or progress."""
    spool = tmp_path / "legacy_v1.db"
    con = sqlite3.connect(spool)
    con.executescript("""
        CREATE TABLE checkpoints (
          path TEXT PRIMARY KEY, identity TEXT NOT NULL, generation TEXT NOT NULL,
          offset INTEGER NOT NULL, prefix_hash TEXT NOT NULL, prefix_length INTEGER NOT NULL);
        CREATE TABLE spool (
          id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'PENDING', error TEXT, attempts INTEGER NOT NULL DEFAULT 0,
          available_at REAL NOT NULL DEFAULT 0);
        INSERT INTO checkpoints VALUES('/var/log/auth.log', 'dev1:ino999', 'gen-1234', 450, 'hashabc', 64);
        INSERT INTO spool(payload) VALUES ('{"source":"file:abc","collector":"leg","source_type":"generic","source_sequence":"g:0","timestamp":null,"raw_event":"legacy pending"}');
    """)
    con.commit()
    con.close()

    col = FileCollector(spool, "migrated-collector", tenant_id="tenant-target")
    # Verify schema migration
    table_info = col.db.execute("PRAGMA table_info(checkpoints)").fetchall()
    pk_cols = [c[1] for c in table_info if c[5] == 1]
    assert pk_cols == ["identity"], "checkpoints table did not migrate primary key to identity"

    # Verify checkpoint row preserved
    cp = col.db.execute("SELECT identity, offset, generation FROM checkpoints").fetchone()
    assert cp == ("dev1:ino999", 450, "gen-1234")

    # Verify spool pending record preserved
    assert col.depth == 1
    assert col.bound_tenant_id == "tenant-target"
    col.close()
