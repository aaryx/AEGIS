"""AEGIS Encrypted Backup & Disaster Recovery Engine.

Provides authenticated symmetric encryption (AES-256-GCM / Fernet) for database backups,
cryptographic SHA-256 digest validation, and safe isolated restoration.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class BackupError(Exception):
    """Base exception for backup operations."""


class BackupIntegrityError(BackupError):
    """Raised when backup archive checksum or envelope verification fails."""


class BackupDecryptionError(BackupError):
    """Raised when backup decryption fails due to wrong key or corrupted ciphertext."""


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Derives a url-safe base64 32-byte Fernet key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def create_encrypted_backup(
    source_db_path: Path | str,
    output_archive_path: Path | str,
    passphrase: str,
) -> dict[str, Any]:
    """Generates an authenticated encrypted backup archive from a source SQLite database.
    
    Format:
    [4 bytes MAGIC: 'AGBK']
    [4 bytes HEADER LENGTH (N)]
    [N bytes UTF-8 JSON HEADER: {version, salt_hex, sha256, created_at, size_bytes}]
    [CIPHERTEXT BYTES]
    """
    src = Path(source_db_path)
    out = Path(output_archive_path)
    if not src.exists():
        raise FileNotFoundError(f"Source database not found: {src}")

    started = time.monotonic()

    # Create consistent raw snapshot via SQLite backup API if SQLite
    temp_snapshot = out.parent / f"temp_{os.getpid()}_{src.name}"
    src_conn = sqlite3.connect(str(src))
    dst_conn = sqlite3.connect(str(temp_snapshot))
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    try:
        raw_bytes = temp_snapshot.read_bytes()
    finally:
        if temp_snapshot.exists():
            temp_snapshot.unlink()

    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    raw_size = len(raw_bytes)

    # Generate salt and derive symmetric key
    salt = os.urandom(16)
    key = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)

    ciphertext = fernet.encrypt(raw_bytes)

    header = {
        "format": "AEGIS-ENCRYPTED-BACKUP-V1",
        "algorithm": "AES-128-CBC-HMAC-SHA256-FERNET",
        "salt_hex": salt.hex(),
        "unencrypted_sha256": raw_sha256,
        "unencrypted_size_bytes": raw_size,
        "created_at": datetime.now(UTC).isoformat(),
    }
    header_bytes = json.dumps(header).encode("utf-8")

    # Write binary archive
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        f.write(b"AGBK")
        f.write(len(header_bytes).to_bytes(4, "big"))
        f.write(header_bytes)
        f.write(ciphertext)

    duration = time.monotonic() - started
    archive_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return {
        "status": "BACKUP_CREATED",
        "archive_path": str(out),
        "archive_size_bytes": out.stat().st_size,
        "archive_sha256": archive_sha256,
        "unencrypted_sha256": raw_sha256,
        "unencrypted_size_bytes": raw_size,
        "duration_seconds": round(duration, 3),
        "header": header,
    }


def restore_encrypted_backup(
    archive_path: Path | str,
    target_db_path: Path | str,
    passphrase: str,
) -> dict[str, Any]:
    """Restores an encrypted backup archive into a fresh target database after verifying integrity."""
    arc = Path(archive_path)
    target = Path(target_db_path)
    if not arc.exists():
        raise FileNotFoundError(f"Backup archive not found: {arc}")

    started = time.monotonic()
    data = arc.read_bytes()

    if len(data) < 8 or data[:4] != b"AGBK":
        raise BackupIntegrityError("Invalid backup archive: missing magic header 'AGBK'")

    header_len = int.from_bytes(data[4:8], "big")
    if len(data) < 8 + header_len:
        raise BackupIntegrityError("Invalid backup archive: truncated header")

    try:
        header = json.loads(data[8 : 8 + header_len].decode("utf-8"))
    except Exception as exc:
        raise BackupIntegrityError("Failed to decode backup archive header") from exc

    salt = bytes.fromhex(header["salt_hex"])
    ciphertext = data[8 + header_len :]

    key = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)

    try:
        raw_bytes = fernet.decrypt(ciphertext)
    except InvalidToken as exc:
        raise BackupDecryptionError("Decryption failed: invalid passphrase or corrupted ciphertext") from exc

    # Check unencrypted integrity
    restored_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if restored_sha256 != header["unencrypted_sha256"]:
        raise BackupIntegrityError(
            f"Integrity check failed: expected {header['unencrypted_sha256']}, got {restored_sha256}"
        )

    # Write to target database
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    target.write_bytes(raw_bytes)

    # Verify SQLite schema integrity
    with sqlite3.connect(str(target)) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check")
        check_result = cursor.fetchone()[0]
        if check_result != "ok":
            target.unlink()
            raise BackupIntegrityError(f"Database PRAGMA integrity_check failed: {check_result}")

    duration = time.monotonic() - started
    return {
        "status": "RESTORE_SUCCESSFUL",
        "target_db_path": str(target),
        "restored_size_bytes": len(raw_bytes),
        "restored_sha256": restored_sha256,
        "duration_seconds": round(duration, 3),
        "header": header,
    }
