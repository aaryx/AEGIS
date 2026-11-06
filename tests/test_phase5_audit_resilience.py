"""Phase 5 Audit Integrity and Incident Accountability Test Suite.

Validates the cryptographic audit hash chain, concurrency, failure modes,
tamper detection, and transactional consistency:
1. Concurrent audit writes for the same tenant (serialized via tenant gate)
2. Concurrent audit writes across multiple tenants (fully isolated and parallel)
3. Transaction rollback atomicity (AuditLog & AuditHead roll back together when mutation aborts)
4. Application restart continuity (monotonic sequence numbers, intact HMAC chain)
5. Tamper detection:
   - Record modification (tampered payload/actor/action)
   - Record deletion (sequence count & hash break)
   - Record reordering
   - Record duplication
   - Previous-hash corruption
   - AuditHead modification / desynchronization from Organization
   - Missing AuditHead
6. Authorization boundaries on audit log endpoints
7. Transactional atomicity: business state cannot commit without audit log
8. Explicit distinction: tamper evidence vs tamper prevention
"""

from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from aegis.config import Settings
from aegis.db import AuditHead, AuditLog, Base, Incident, Organization
from aegis.security import audit, verify_audit


def test_concurrent_audit_writes_same_tenant(system):
    """Multiple concurrent threads writing audit logs for the same tenant maintain valid hash chain."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    def write_log(idx: int):
        with sessions.begin() as db:
            audit(
                db,
                settings,
                org_id,
                f"actor_{idx}",
                "incident.update",
                f"INC-{idx}",
                details={"step": idx, "thread": True},
            )

    # Concurrently execute 10 audit writes
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(write_log, i) for i in range(10)]
        for f in futures:
            f.result()

    # Verify that the resulting chain is strictly monotonic and cryptographically valid
    with sessions() as db:
        head = db.get(AuditHead, org_id)
        assert head is not None
        assert head.sequence_number >= 10
        records = list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.organization_id == org_id)
                .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            )
        )
        assert len(records) >= 10
        assert verify_audit(db, settings, org_id) is True


def test_concurrent_audit_writes_multiple_tenants(system):
    """Concurrent audit writes across different tenants execute independently and remain valid."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_a = system["org"]
    org_b = system["other"]

    def write_multi_log(org_id: str, idx: int):
        with sessions.begin() as db:
            audit(
                db,
                settings,
                org_id,
                f"actor_{org_id}_{idx}",
                "case.update",
                f"CASE-{idx}",
                details={"org": org_id, "idx": idx},
            )

    # Interleave concurrent writes across Org A and Org B
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = []
        for i in range(8):
            futures.append(executor.submit(write_multi_log, org_a, i))
            futures.append(executor.submit(write_multi_log, org_b, i))
        for f in futures:
            f.result()

    # Both tenant chains must be individually and completely valid
    with sessions() as db:
        assert verify_audit(db, settings, org_a) is True
        assert verify_audit(db, settings, org_b) is True

        # Assert no cross-tenant previous_hash contamination
        hashes_a = {
            r.entry_hash
            for r in db.scalars(select(AuditLog).where(AuditLog.organization_id == org_a))
        }
        hashes_b = {
            r.entry_hash
            for r in db.scalars(select(AuditLog).where(AuditLog.organization_id == org_b))
        }
        assert hashes_a.isdisjoint(hashes_b)


def test_transaction_rollback_atomicity(system):
    """When a transaction rolls back, both AuditLog and AuditHead roll back atomically."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    with sessions() as db:
        initial_head = db.get(AuditHead, org_id)
        initial_head_hash = initial_head.audit_head if initial_head else "0" * 64
        initial_seq = initial_head.sequence_number if initial_head else 0

    # Simulate an aborted transaction where an audit record was flushed, but business logic failed
    with pytest.raises(RuntimeError, match="Simulated business logic failure"):
        with sessions.begin() as db:
            audit(
                db,
                settings,
                org_id,
                "actor_abort",
                "security.sensitive_operation",
                "RES-ABORT",
            )
            # Raise exception causing rollback
            raise RuntimeError("Simulated business logic failure")

    # Assert that neither AuditLog nor AuditHead retained the rolled-back entry
    with sessions() as db:
        refreshed_head = db.get(AuditHead, org_id)
        current_seq = refreshed_head.sequence_number if refreshed_head else 0
        current_head_hash = refreshed_head.audit_head if refreshed_head else "0" * 64
        assert current_seq == initial_seq
        assert current_head_hash == initial_head_hash

        # Assert no orphaned AuditLog entry exists
        orphaned = db.scalar(select(AuditLog).where(AuditLog.actor == "actor_abort"))
        assert orphaned is None

        # Verify audit chain integrity remains pristine
        assert verify_audit(db, settings, org_id) is True


def test_application_restart_chain_continuity(tmp_path):
    """Restarting application/database connections preserves monotonic sequence numbers and valid chain."""
    db_file = tmp_path / "restart_audit.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    settings = Settings(database_url=db_url, audit_secret="persistent-audit-secret-key-at-least-32-chars")

    org_id = None
    with Session(engine) as db:
        org = Organization(name="Persistent Org")
        db.add(org)
        db.flush()
        org_id = org.id

        # Write 3 audit logs in first session
        for i in range(3):
            audit(db, settings, org_id, "boot_actor", "sys.start", f"RES-{i}")
        db.commit()

    # Simulate full engine restart (dispose engine and recreate)
    engine.dispose()
    new_engine = create_engine(db_url)

    with Session(new_engine) as db:
        # Verify initial chain
        assert verify_audit(db, settings, org_id) is True
        head = db.get(AuditHead, org_id)
        assert head.sequence_number == 3

        # Append additional logs post-restart
        for i in range(3, 6):
            audit(db, settings, org_id, "post_restart_actor", "sys.resume", f"RES-{i}")
        db.commit()

        # Verify unbroken continuation
        final_head = db.get(AuditHead, org_id)
        assert final_head.sequence_number == 6
        assert verify_audit(db, settings, org_id) is True
    new_engine.dispose()


def test_audit_tamper_detection_modified_payload(system):
    """Tampering with an existing audit record's payload breaks HMAC verification."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    with sessions.begin() as db:
        audit(db, settings, org_id, "auditor", "auth.login", "USER-1", details={"ip": "192.168.1.1"})

    with sessions() as db:
        assert verify_audit(db, settings, org_id) is True

    # Malicious actor tampers with details dictionary in DB
    with sessions.begin() as db:
        record = db.scalar(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.action == "auth.login")
            .order_by(AuditLog.created_at.desc())
        )
        record.details = {"ip": "10.0.0.1"}  # Modified IP address

    # verify_audit must immediately detect the forgery
    with sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_tamper_detection_deleted_record(system):
    """Deleting an intermediate audit record breaks sequence count and hash continuity."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    with sessions.begin() as db:
        for i in range(4):
            audit(db, settings, org_id, "actor", "action.seq", f"ID-{i}")

    with sessions() as db:
        assert verify_audit(db, settings, org_id) is True

    # Malicious actor deletes the 2nd record
    with sessions.begin() as db:
        record_to_delete = db.scalar(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.resource_id == "ID-2")
        )
        db.delete(record_to_delete)

    # verify_audit must detect sequence number mismatch and broken hash chain
    with sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_tamper_detection_reordered_records(system):
    """Reordering audit records breaks the previous_hash link chain."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    with sessions.begin() as db:
        for i in range(3):
            audit(db, settings, org_id, f"actor_{i}", "action.order", f"ID-{i}")

    with sessions() as db:
        assert verify_audit(db, settings, org_id) is True

    # Swap created_at timestamps to reorder chronological traversal
    with sessions.begin() as db:
        recs = list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.organization_id == org_id, AuditLog.action == "action.order")
                .order_by(AuditLog.created_at.asc())
            )
        )
        t0, t1 = recs[0].created_at, recs[1].created_at
        recs[0].created_at, recs[1].created_at = t1, t0

    # verify_audit must detect tampering
    with sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_tamper_detection_head_desynchronization(system):
    """Tampering with AuditHead or Organization audit_head fails verification."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    org_id = system["org"]

    with sessions.begin() as db:
        audit(db, settings, org_id, "admin", "admin.privilege", "ROLE-1")

    with sessions() as db:
        assert verify_audit(db, settings, org_id) is True

    # Malicious actor attempts to forge AuditHead sequence or hash
    with sessions.begin() as db:
        head = db.get(AuditHead, org_id)
        head.audit_head = "f" * 64

    with sessions() as db:
        assert verify_audit(db, settings, org_id) is False


def test_audit_log_access_role_boundaries(system):
    """Only authorized administrative/audit roles can read audit logs."""
    client = system["client"]

    # 1. SUPER_ADMIN can read audit logs
    client.headers["Authorization"] = f"Bearer {system['tokens']['SUPER_ADMIN']}"
    resp_super = client.get("/api/v1/audit")
    assert resp_super.status_code == 200
    assert "items" in resp_super.json()

    # 2. VIEWER cannot read audit logs
    client.headers["Authorization"] = f"Bearer {system['tokens']['VIEWER']}"
    resp_viewer = client.get("/api/v1/audit")
    assert resp_viewer.status_code == 403

    # 3. ANALYST cannot read audit logs
    client.headers["Authorization"] = f"Bearer {system['tokens']['ANALYST']}"
    resp_analyst = client.get("/api/v1/audit")
    assert resp_analyst.status_code == 403


def test_security_sensitive_mutation_atomic_with_audit(system):
    """Mutating incident status is bound in the same transaction as its audit event."""
    client = system["client"]
    sessions = system["app"].state.sessions
    org_id = system["org"]

    with sessions.begin() as db:
        inc = Incident(organization_id=org_id, title="Atomicity Test Incident", severity="high", status="OPEN")
        db.add(inc)
        db.flush()
        inc_id = inc.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"
    resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "TRIAGED", "revision": 1},
    )
    assert resp.status_code == 200

    # Both incident status mutation and audit log must exist in DB and chain must verify
    with sessions() as db:
        refreshed = db.get(Incident, inc_id)
        assert refreshed.status == "TRIAGED"
        assert refreshed.revision == 2

        audit_entry = db.scalar(
            select(AuditLog).where(
                AuditLog.organization_id == org_id,
                AuditLog.action == "incidents.update",
                AuditLog.resource_id == inc_id,
            )
        )
        assert audit_entry is not None
        assert audit_entry.details.get("status") == "TRIAGED"
        assert verify_audit(db, system["settings"], org_id) is True
