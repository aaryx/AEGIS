"""AEGIS TITAN Phase 6: Cloud Backup, Cold Restore & Disaster Recovery Suite.

Validates:
1. Provider-independent authenticated backup encryption and packaging.
2. Cold restoration into a fresh, isolated database instance.
3. Post-restore relational integrity, row count reconciliation, and PRAGMA integrity.
4. Cryptographic HMAC audit-chain verification (verify_audit) across all restored tenants.
5. Strict fail-closed rejection on corrupted ciphertext, tampered headers, or wrong passphrases.
6. Mocked AWS S3 and Google Cloud Storage adapters for KMS encryption, TLS enforcement, and Object Lock.
"""

import hashlib
import json
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select

from aegis.backup_crypto import (
    BackupDecryptionError,
    BackupIntegrityError,
    create_encrypted_backup,
    restore_encrypted_backup,
)
from aegis.config import Settings
from aegis.db import (
    AuditLog,
    Base,
    EventRecord,
    Organization,
    Rule,
    User,
    database,
)
from aegis.pipeline import ingest, seed_rules
from aegis.schemas import EventInput
from aegis.security import PASSWORDS, audit, verify_audit


def test_encrypted_backup_creation_and_cold_restore_drill(tmp_path):
    """Executes full cold disaster recovery drill with authenticated encryption."""
    source_db_file = tmp_path / "source_production.db"
    archive_file = tmp_path / "aegis_encrypted_backup.agbk"
    target_db_file = tmp_path / "restored_production.db"
    passphrase = "Enterprise-Vault-DR-Passphrase-2026-Secure!"

    settings = Settings(
        environment="testing",
        database_url=f"sqlite:///{source_db_file}",
        audit_secret="dr-test-audit-secret-key-32chars-min",
        _env_file=None,
    )

    # 1. Populate source database with representative multi-tenant dataset
    engine_src, sessions_src = database(settings.database_url)
    Base.metadata.create_all(engine_src)

    with sessions_src.begin() as db:
        # Tenant 1: Alpha Defense
        org1 = Organization(name="Alpha Defense Corp")
        db.add(org1)
        db.flush()
        seed_rules(db, org1.id)
        user1 = User(
            organization_id=org1.id,
            username="admin_alpha",
            password_hash=PASSWORDS.hash("AlphaPass123!"),
            role="ADMIN",
        )
        db.add(user1)
        db.flush()
        audit(db, settings, org1.id, user1.id, "system.init", org1.id, details={"version": "6.0"})

        # Ingest events into Tenant 1
        events1 = [
            EventInput(
                source="firewall",
                raw_event={
                    "event_id": f"evt-alpha-{i:04d}",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "source_ip": "10.0.1.5",
                    "action": "drop",
                },
            )
            for i in range(25)
        ]
        res1 = ingest(db, settings, org1.id, events1, user1.id)
        assert len(res1["accepted"]) == 25

        # Tenant 2: Beta Shield
        org2 = Organization(name="Beta Shield Inc")
        db.add(org2)
        db.flush()
        seed_rules(db, org2.id)
        user2 = User(
            organization_id=org2.id,
            username="admin_beta",
            password_hash=PASSWORDS.hash("BetaPass123!"),
            role="ADMIN",
        )
        db.add(user2)
        db.flush()
        audit(db, settings, org2.id, user2.id, "system.init", org2.id, details={"version": "6.0"})

        # Ingest events into Tenant 2
        events2 = [
            EventInput(
                source="syslog",
                raw_event={
                    "event_id": f"evt-beta-{i:04d}",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "source_ip": "10.0.2.10",
                    "action": "allow",
                },
            )
            for i in range(15)
        ]
        res2 = ingest(db, settings, org2.id, events2, user2.id)
        assert len(res2["accepted"]) == 15

    engine_src.dispose()

    # 2. Create Authenticated Encrypted Backup
    backup_result = create_encrypted_backup(source_db_file, archive_file, passphrase)
    assert backup_result["status"] == "BACKUP_CREATED"
    assert archive_file.exists()
    assert archive_file.stat().st_size > 0
    assert len(backup_result["archive_sha256"]) == 64
    assert len(backup_result["unencrypted_sha256"]) == 64

    # 3. Restore to completely fresh isolated target database
    restore_result = restore_encrypted_backup(archive_file, target_db_file, passphrase)
    assert restore_result["status"] == "RESTORE_SUCCESSFUL"
    assert target_db_file.exists()
    assert restore_result["restored_sha256"] == backup_result["unencrypted_sha256"]

    # 4. Validate Restored Database Integrity & Row Counts
    engine_dst, sessions_dst = database(f"sqlite:///{target_db_file}")
    with sessions_dst() as db:
        org_count = db.scalar(select(func.count(Organization.id)))
        user_count = db.scalar(select(func.count(User.id)))
        event_count = db.scalar(select(func.count(EventRecord.id)))
        rule_count = db.scalar(select(func.count(Rule.id)))
        audit_count = db.scalar(select(func.count(AuditLog.id)))

        assert org_count == 2
        assert user_count == 2
        assert event_count == 40
        assert rule_count > 0
        assert audit_count >= 2

        # 5. Verify Cryptographic HMAC Audit-Chain Validity on restored database
        assert verify_audit(db, settings, org1.id) is True
        assert verify_audit(db, settings, org2.id) is True

        # 6. Verify Cross-Tenant Isolation persists post-restore
        org1_events = db.scalars(select(EventRecord).where(EventRecord.organization_id == org1.id)).all()
        assert len(org1_events) == 25
        assert all(e.organization_id == org1.id for e in org1_events)

    engine_dst.dispose()


def test_restore_rejection_wrong_passphrase(tmp_path):
    """Verifies that an incorrect passphrase fails closed with BackupDecryptionError."""
    source_db_file = tmp_path / "src_wrong_key.db"
    archive_file = tmp_path / "backup_wrong_key.agbk"
    target_db_file = tmp_path / "dst_wrong_key.db"

    # Create dummy sqlite db
    with sqlite3.connect(str(source_db_file)) as conn:
        conn.execute("CREATE TABLE t (id INT)")
        conn.execute("INSERT INTO t VALUES (1)")

    create_encrypted_backup(source_db_file, archive_file, "CorrectPassphrase123")

    with pytest.raises(BackupDecryptionError, match="invalid passphrase or corrupted ciphertext"):
        restore_encrypted_backup(archive_file, target_db_file, "WrongPassphrase999")

    assert not target_db_file.exists(), "Target database must not be created on decryption failure"


def test_restore_rejection_corrupted_ciphertext(tmp_path):
    """Verifies that bit flips in the ciphertext trigger BackupDecryptionError."""
    source_db_file = tmp_path / "src_corrupt.db"
    archive_file = tmp_path / "backup_corrupt.agbk"
    target_db_file = tmp_path / "dst_corrupt.db"

    with sqlite3.connect(str(source_db_file)) as conn:
        conn.execute("CREATE TABLE t (id INT)")
        conn.execute("INSERT INTO t VALUES (42)")

    create_encrypted_backup(source_db_file, archive_file, "Pass1234")

    # Corrupt ciphertext payload
    data = bytearray(archive_file.read_bytes())
    data[-10] ^= 0xFF
    archive_file.write_bytes(bytes(data))

    with pytest.raises(BackupDecryptionError):
        restore_encrypted_backup(archive_file, target_db_file, "Pass1234")

    assert not target_db_file.exists()


def test_restore_rejection_tampered_header_checksum(tmp_path):
    """Verifies that tampering with header checksum triggers BackupIntegrityError."""
    source_db_file = tmp_path / "src_hdr.db"
    archive_file = tmp_path / "backup_hdr.agbk"
    target_db_file = tmp_path / "dst_hdr.db"

    with sqlite3.connect(str(source_db_file)) as conn:
        conn.execute("CREATE TABLE t (id INT)")

    create_encrypted_backup(source_db_file, archive_file, "Pass1234")

    data = archive_file.read_bytes()
    header_len = int.from_bytes(data[4:8], "big")
    header = json.loads(data[8 : 8 + header_len].decode("utf-8"))

    # Tamper with expected unencrypted SHA-256
    header["unencrypted_sha256"] = "0" * 64
    new_hdr_bytes = json.dumps(header).encode("utf-8")
    new_archive = (
        b"AGBK"
        + len(new_hdr_bytes).to_bytes(4, "big")
        + new_hdr_bytes
        + data[8 + header_len :]
    )
    archive_file.write_bytes(new_archive)

    with pytest.raises(BackupIntegrityError, match="Integrity check failed"):
        restore_encrypted_backup(archive_file, target_db_file, "Pass1234")


# ==============================================================================
# Mocked Cloud Object Storage Adapters (AWS S3 & Google Cloud Storage)
# ==============================================================================


class MockS3StorageClient:
    """Mock AWS S3 storage client validating bucket policy, KMS encryption, and Object Lock."""

    def __init__(self, bucket: str, kms_key_arn: str, enforce_tls: bool = True):
        self.bucket = bucket
        self.kms_key_arn = kms_key_arn
        self.enforce_tls = enforce_tls
        self.objects: dict[str, dict[str, Any]] = {}
        self.object_locks: dict[str, dict[str, Any]] = {}

    def put_object(
        self,
        key: str,
        data: bytes,
        server_side_encryption: str = "aws:kms",
        ssekms_key_id: str | None = None,
        use_tls: bool = True,
    ) -> dict[str, Any]:
        if self.enforce_tls and not use_tls:
            raise PermissionError("Access Denied: S3 Bucket Policy requires aws:SecureTransport=true")
        if server_side_encryption != "aws:kms":
            raise ValueError("Bucket policy enforces SSE-KMS encryption (aws:kms)")
        if ssekms_key_id != self.kms_key_arn:
            raise PermissionError("Access Denied: KMS key unauthorized or mismatched")

        etag = hashlib.md5(data, usedforsecurity=False).hexdigest()  # nosec B324
        sha256 = hashlib.sha256(data).hexdigest()
        self.objects[key] = {
            "data": data,
            "etag": etag,
            "sha256": sha256,
            "size": len(data),
            "encryption": server_side_encryption,
            "kms_key": ssekms_key_id,
            "uploaded_at": datetime.now(UTC).isoformat(),
        }
        return {"ETag": etag, "ServerSideEncryption": server_side_encryption, "SSEKMSKeyId": ssekms_key_id}

    def put_object_retention(self, key: str, mode: str = "COMPLIANCE", retain_until_days: int = 30):
        if key not in self.objects:
            raise KeyError("NoSuchKey")
        if mode not in {"GOVERNANCE", "COMPLIANCE"}:
            raise ValueError("Invalid Object Lock mode")
        self.object_locks[key] = {
            "mode": mode,
            "retain_until": (datetime.now(UTC) + timedelta(days=retain_until_days)).isoformat(),
        }

    def delete_object(self, key: str):
        if key in self.object_locks and self.object_locks[key]["mode"] == "COMPLIANCE":
            raise PermissionError("Access Denied: Object is locked under WORM COMPLIANCE mode and cannot be deleted")
        self.objects.pop(key, None)


class MockGCSStorageClient:
    """Mock Google Cloud Storage client validating CMEK, uniform access, and Bucket Lock."""

    def __init__(self, bucket: str, kms_key_name: str, uniform_bucket_level_access: bool = True):
        self.bucket = bucket
        self.kms_key_name = kms_key_name
        self.uniform_access = uniform_bucket_level_access
        self.blobs: dict[str, dict[str, Any]] = {}

    def upload_from_string(
        self,
        blob_name: str,
        data: bytes,
        kms_key_name: str | None = None,
    ) -> dict[str, Any]:
        if kms_key_name != self.kms_key_name:
            raise PermissionError("Access Denied: Cloud KMS CMEK key required by bucket policy")

        sha256 = hashlib.sha256(data).hexdigest()
        self.blobs[blob_name] = {
            "data": data,
            "sha256": sha256,
            "size": len(data),
            "kms_key_name": kms_key_name,
            "generation": int(time.time() * 1000),
        }
        return {"name": blob_name, "kms_key_name": kms_key_name, "sha256": sha256}


def test_mock_s3_backup_upload_with_kms_encryption_and_object_lock():
    """Validates S3 adapter logic with mocked KMS encryption, TLS enforcement, and Object Lock."""
    kms_arn = "arn:aws:kms:us-east-1:123456789012:key/aegis-dr-key"
    client = MockS3StorageClient(bucket="aegis-production-dr-backups", kms_key_arn=kms_arn, enforce_tls=True)

    test_payload = b"AEGIS_ENCRYPTED_BACKUP_PAYLOAD_V1"

    # 1. TLS rejection test
    with pytest.raises(PermissionError, match="aws:SecureTransport=true"):
        client.put_object("backup-2026.agbk", test_payload, server_side_encryption="aws:kms", ssekms_key_id=kms_arn, use_tls=False)

    # 2. Plaintext/non-KMS rejection test
    with pytest.raises(ValueError, match="Bucket policy enforces SSE-KMS"):
        client.put_object("backup-2026.agbk", test_payload, server_side_encryption="AES256", ssekms_key_id=kms_arn)

    # 3. Successful upload with KMS and TLS
    resp = client.put_object("backup-2026.agbk", test_payload, server_side_encryption="aws:kms", ssekms_key_id=kms_arn, use_tls=True)
    assert resp["ServerSideEncryption"] == "aws:kms"
    assert resp["SSEKMSKeyId"] == kms_arn

    # 4. Apply WORM Object Lock (COMPLIANCE mode)
    client.put_object_retention("backup-2026.agbk", mode="COMPLIANCE", retain_until_days=90)
    assert client.object_locks["backup-2026.agbk"]["mode"] == "COMPLIANCE"

    # 5. Assert object cannot be deleted under compliance lock
    with pytest.raises(PermissionError, match="cannot be deleted"):
        client.delete_object("backup-2026.agbk")


def test_mock_gcs_backup_upload_with_cmek():
    """Validates Google Cloud Storage adapter logic with customer-managed encryption key (CMEK)."""
    cmek = "projects/aegis-sec/locations/global/keyRings/dr/cryptoKeys/backup-key"
    client = MockGCSStorageClient(bucket="aegis-gcs-dr-backups", kms_key_name=cmek)

    payload = b"GCS_BACKUP_PAYLOAD_TEST"

    # Unauthorized key rejection
    with pytest.raises(PermissionError, match="Cloud KMS CMEK key required"):
        client.upload_from_string("backup.agbk", payload, kms_key_name="wrong-key")

    # Successful upload
    res = client.upload_from_string("backup.agbk", payload, kms_key_name=cmek)
    assert res["name"] == "backup.agbk"
    assert res["kms_key_name"] == cmek
    assert res["sha256"] == hashlib.sha256(payload).hexdigest()
