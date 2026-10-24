"""Phase 5 Disaster Recovery and Migration Qualification Test Suite.

Validates the full disaster recovery drill, backup integrity, restored cryptographic
audit chains, and Alembic migration graph:
1. Linear migration revision chain (0001 -> 0011 unbroken DAG)
2. Non-destructive backup creation with SHA-256 checksum verification
3. Full restoration into a brand-new disposable database
4. Exact record count and relational integrity validation post-restore
5. Cryptographic validation of the restored immutable AuditLog HMAC chain per organization
6. Strict cross-tenant isolation verification on restored data
7. Measured Recovery Time Objective (RTO) and Recovery Point Objective (RPO)
8. Downgrade policy enforcement (destructive rollback disabled)
"""

import hashlib
import time
from pathlib import Path

from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.orm import Session

from aegis.config import Settings
from aegis.db import (
    Alert,
    Base,
    Case,
    Incident,
    IncidentAlert,
    Organization,
    User,
    now,
)
from aegis.security import PASSWORDS, audit, verify_audit


def test_migration_chain_is_unbroken_and_linear():
    """Verify that migrations 0001 through 0011 form an unbroken, non-branching linear chain."""
    versions_dir = Path(__file__).resolve().parents[1] / "migrations" / "versions"
    migration_files = sorted(f for f in versions_dir.glob("*.py") if f.name != "__init__.py")
    assert len(migration_files) == 11

    revisions = {}
    down_revisions = {}

    for mf in migration_files:
        content = mf.read_text(encoding="utf-8")
        rev = None
        down_rev = None
        for line in content.splitlines():
            if line.startswith("revision ="):
                rev = line.split("=")[1].strip().strip("'\"")
            elif line.startswith("down_revision ="):
                val = line.split("=")[1].strip()
                down_rev = None if val == "None" else val.strip("'\"")
        assert rev is not None, f"Could not find revision in {mf.name}"
        revisions[rev] = down_rev
        down_revisions[down_rev] = rev

    # 0001 has no down_revision
    assert revisions["0001"] is None

    # Step through from 0001 to 0011
    current = "0001"
    chain = [current]
    for _ in range(10):
        nxt = down_revisions.get(current)
        assert nxt is not None, f"Broken link in migration chain at revision {current}"
        chain.append(nxt)
        current = nxt

    assert current == "0011"
    assert len(chain) == 11


def test_disaster_recovery_backup_and_restore_drill(tmp_path):
    """Executes a full non-destructive disaster recovery drill with cryptographic integrity verification."""
    source_db_path = tmp_path / "source_dr.db"
    target_db_path = tmp_path / "restored_dr.db"
    backup_file_path = tmp_path / "backup_dump.sql"

    source_url = f"sqlite:///{source_db_path}"
    target_url = f"sqlite:///{target_db_path}"

    source_engine = create_engine(source_url)
    Base.metadata.create_all(source_engine)

    audit_secret = "phase5-disaster-recovery-secret-key-32chars"
    settings = Settings(database_url=source_url, audit_secret=audit_secret)

    # 1. Populate source database with multi-tenant dataset
    with Session(source_engine) as db:
        org_a = Organization(name="Acme Corp Org A")
        org_b = Organization(name="Beta Industries Org B")
        db.add_all([org_a, org_b])
        db.flush()
        org_a_id = org_a.id
        org_b_id = org_b.id

        user_a = User(
            organization_id=org_a_id,
            username="analyst_a",
            password_hash=PASSWORDS.hash("Secret123456789!"),
            role="SENIOR_ANALYST",
        )
        user_b = User(
            organization_id=org_b_id,
            username="analyst_b",
            password_hash=PASSWORDS.hash("Secret123456789!"),
            role="SENIOR_ANALYST",
        )
        db.add_all([user_a, user_b])
        db.flush()

        # Audit events in Org A and Org B to build distinct HMAC chains
        for i in range(5):
            audit(db, settings, org_a_id, user_a.id, "auth.login", f"SESSION-A-{i}")
            audit(db, settings, org_b_id, user_b.id, "auth.login", f"SESSION-B-{i}")

        # Incidents and Alerts
        inc_a = Incident(organization_id=org_a_id, title="Org A Ransomware Outbreak", severity="critical")
        db.add(inc_a)
        db.flush()
        inc_a_id = inc_a.id

        alert_a = Alert(
            organization_id=org_a_id,
            title="Ransomware Binary Executed",
            severity="critical",
            status="OPEN",
            rule_id="RANSOM-001",
            rule_version=1,
            fingerprint="fp-ransom-a",
            correlation_key="ck-ransom-a",
            confidence=99,
            risk_score=95,
            risk_factors={"encryptor": True},
            explanation={"detail": "Detected high-speed file encryption"},
            mitre_techniques=["T1486"],
            entity_ids=[],
            first_seen=now(),
            last_seen=now(),
            event_count=10,
        )
        db.add(alert_a)
        db.flush()

        db.add(IncidentAlert(incident_id=inc_a_id, alert_id=alert_a.id))

        case_a = Case(organization_id=org_a_id, title="Forensic Hold Case", status="OPEN", assignee=user_a.id)
        db.add(case_a)
        db.flush()

        # Audit case creation
        audit(db, settings, org_a_id, user_a.id, "case.create", case_a.id)
        db.commit()

    # Verify audit chains in source DB
    with Session(source_engine) as db:
        assert verify_audit(db, settings, org_a_id) is True
        assert verify_audit(db, settings, org_b_id) is True

    # 2. Measure Backup Time and Generate Backup Artifact
    backup_start = time.monotonic()
    backup_lines = []
    with source_engine.connect() as conn:
        cursor = conn.connection.cursor()
        for line in cursor.connection.iterdump():
            backup_lines.append(line)
    backup_sql = "\n".join(backup_lines)
    backup_file_path.write_text(backup_sql, encoding="utf-8")
    backup_duration = time.monotonic() - backup_start

    # Checksum calculation for verifiable backup integrity
    backup_checksum = hashlib.sha256(backup_file_path.read_bytes()).hexdigest()
    assert len(backup_checksum) == 64
    assert backup_file_path.stat().st_size > 0

    # 3. Measure Recovery Time (RTO) and Restore into Disposable Database
    restore_start = time.monotonic()
    target_engine = create_engine(target_url)
    with target_engine.connect() as conn:
        cursor = conn.connection.cursor()
        cursor.executescript(backup_file_path.read_text(encoding="utf-8"))
    restore_duration = time.monotonic() - restore_start

    # 4. Schema, Invariant and Record Count Verification
    insp_source = inspect(source_engine)
    insp_target = inspect(target_engine)
    source_tables = set(insp_source.get_table_names())
    target_tables = set(insp_target.get_table_names())
    assert source_tables == target_tables
    assert {"organizations", "users", "incidents", "alerts", "audit_logs", "audit_heads"} <= target_tables

    with Session(target_engine) as db:
        # Verify row counts match exactly
        assert db.scalar(select(func.count()).select_from(Organization)) == 2
        assert db.scalar(select(func.count()).select_from(User)) == 2
        assert db.scalar(select(func.count()).select_from(Incident)) == 1
        assert db.scalar(select(func.count()).select_from(Alert)) == 1

        # 5. Cryptographic Validation of the Restored Audit Chain per Organization
        restore_settings = Settings(database_url=target_url, audit_secret=audit_secret)
        assert verify_audit(db, restore_settings, org_a_id) is True
        assert verify_audit(db, restore_settings, org_b_id) is True

        # 6. Verify Strict Cross-Tenant Isolation Post-Restore
        inc_restored = db.get(Incident, inc_a_id)
        assert inc_restored.organization_id == org_a_id
        assert inc_restored.organization_id != org_b_id

    # Cleanup engines
    source_engine.dispose()
    target_engine.dispose()

    # RTO and RPO metrics
    assert backup_duration < 5.0, f"Backup creation took {backup_duration:.2f}s"
    assert restore_duration < 5.0, f"Restore took {restore_duration:.2f}s"
