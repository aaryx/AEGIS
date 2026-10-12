"""AEGIS Cryptographic Engine.

Provides Ed25519 asymmetric signing and verification for endpoint command/receipt integrity,
controller trust-root derivation, key lifecycle persistence, and RFC 6238 TOTP MFA.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import stat
import struct
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis.parsers import canonical


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generates an Ed25519 private key and returns (private_key, public_key_hex)."""
    private_key = Ed25519PrivateKey.generate()
    public_hex = private_key.public_key().public_bytes_raw().hex()
    return private_key, public_hex


def ed25519_sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Signs bytes using Ed25519 and returns the signature as a hex string."""
    sig_bytes = private_key.sign(data)
    return sig_bytes.hex()


def ed25519_sign_canonical(private_key: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    """Canonicalizes the payload dictionary and signs it using Ed25519."""
    data = canonical(payload).encode("utf-8")
    return ed25519_sign(private_key, data)


def ed25519_verify(public_key_hex: str, signature_hex: str, data: bytes) -> bool:
    """Verifies an Ed25519 signature against data using public_key_hex."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        if len(pub_bytes) != 32:
            return False
        sig_bytes = bytes.fromhex(signature_hex)
        if len(sig_bytes) != 64:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, data)
        return True
    except (ValueError, InvalidSignature, TypeError):
        return False


def ed25519_verify_canonical(
    public_key_hex: str, signature_hex: str, payload: dict[str, Any]
) -> bool:
    """Canonicalizes the payload dictionary and verifies its Ed25519 signature."""
    data = canonical(payload).encode("utf-8")
    return ed25519_verify(public_key_hex, signature_hex, data)


def save_private_key(private_key: Ed25519PrivateKey, filepath: str) -> None:
    """Persists private key raw bytes (hex) to a secure local file with 0o600 permissions."""
    raw_hex = private_key.private_bytes_raw().hex()
    parent_dir = os.path.dirname(os.path.abspath(filepath))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    # Write file atomically with restrictive permissions
    temp_path = f"{filepath}.tmp.{secrets.token_hex(4)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    fd = os.open(temp_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(raw_hex.strip())

    if hasattr(os, "chmod"):
        try:
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    os.replace(temp_path, filepath)


def load_private_key(filepath: str) -> Ed25519PrivateKey:
    """Loads an Ed25519 private key from a local file containing hex raw bytes."""
    with open(filepath, encoding="utf-8") as f:
        content = f.read().strip()
    raw_bytes = bytes.fromhex(content)
    if len(raw_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 private key length: {len(raw_bytes)} (expected 32 bytes)")
    return Ed25519PrivateKey.from_private_bytes(raw_bytes)


def get_controller_signing_key(settings: Any) -> Ed25519PrivateKey:
    """Returns the controller's Ed25519 signing key.

    If an explicit controller_signing_key is configured in settings, it is loaded.
    Otherwise, a deterministic 32-byte seed is derived from audit_secret using HKDF-SHA256,
    ensuring stability across controller restarts without requiring separate manual configuration.
    """
    configured_key = getattr(settings, "controller_signing_key", None)
    if configured_key:
        key_str = configured_key.get_secret_value() if hasattr(configured_key, "get_secret_value") else str(configured_key)
        key_str = key_str.strip()
        if key_str:
            raw_bytes = bytes.fromhex(key_str)
            if len(raw_bytes) == 32:
                return Ed25519PrivateKey.from_private_bytes(raw_bytes)

    # Derive deterministic seed from audit_secret via HKDF-Expand with domain separation
    secret_val = settings.audit_secret.get_secret_value().encode("utf-8")
    prk = hmac.new(b"AEGIS_CONTROLLER_KEY_DERIVATION_SALT_V1", secret_val, hashlib.sha256).digest()
    info = b"AEGIS_CONTROLLER_ED25519_SIGNING_KEY_V1"
    seed = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def hkdf_derive_key(
    ikm: bytes, info: bytes, salt: bytes = b"AEGIS_HKDF_SALT_V1", length: int = 32
) -> bytes:
    """HKDF-SHA256 key derivation per RFC 5869."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm[:length]


def get_controller_public_key_hex(settings: Any) -> str:
    """Returns the controller's Ed25519 public key as a 64-character hex string."""
    priv = get_controller_signing_key(settings)
    return priv.public_key().public_bytes_raw().hex()


# --- RFC 6238 TOTP Multi-Factor Authentication ---


def generate_totp_secret() -> str:
    """Generates a random 20-byte base32 secret for TOTP (160-bit key per RFC 6238)."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def generate_totp(
    secret: str, timestamp: float | None = None, digits: int = 6, interval: int = 30
) -> str:
    """Generates the RFC 6238 TOTP code for the specified secret and timestamp."""
    if timestamp is None:
        timestamp = time.time()
    time_step = int(timestamp) // interval
    msg = struct.pack(">Q", time_step)
    # Pad base32 secret if necessary
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret.upper() + padding)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def verify_totp(
    secret: str, code: str, timestamp: float | None = None, allowed_drift: int = 1
) -> bool:
    """Verifies a TOTP code against the secret, allowing for ±allowed_drift time steps (default 30s)."""
    if not code or len(code) != 6 or not code.isdigit():
        return False
    if timestamp is None:
        timestamp = time.time()
    # Check current, previous, and next intervals to accommodate network latency/clock drift
    for step_offset in range(-allowed_drift, allowed_drift + 1):
        test_ts = timestamp + (step_offset * 30)
        expected = generate_totp(secret, timestamp=test_ts)
        if hmac.compare_digest(expected, code):
            return True
    return False


def get_totp_uri(secret: str, username: str, issuer: str = "AEGIS") -> str:
    """Constructs standard otpauth URI compatible with authenticator applications."""
    from urllib.parse import quote

    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )
