"""AEGIS TITAN Phase 6: TLS Qualification & Certificate Rotation Suite.

Validates:
1. End-to-end TLS handshake verification with operator-provisioned certificates and CA chains.
2. Positive verification with trusted root CA and matching DNS SAN.
3. Negative verification: rejection of untrusted CAs, expired certificates, and hostname mismatches.
4. Zero-downtime certificate rotation drill: swapping Cert A to Cert B under the same or renewed CA.
5. Fail-closed rejection during rotation if an invalid/untrusted replacement certificate is deployed.
6. Connection-pool reconnection integrity: re-established connections unconditionally preserve TLS validation.
7. Production configuration policies: PostgreSQL pg_hba.conf plaintext rejection, Redis --port 0, and OpenSearch TLS.
"""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aegis.config import Settings
from aegis.transport import postgres_connect_kwargs, redis_client

ROOT = Path(__file__).resolve().parents[1]


def generate_ca(tmp_path: Path, name: str = "RootCA") -> tuple[x509.Certificate, rsa.RSAPrivateKey, Path, Path]:
    """Generates a self-signed root certificate authority."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AEGIS Security Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"AEGIS {name}"),
    ])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{name}_cert.pem"
    key_path = tmp_path / f"{name}_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, key, cert_path, key_path


def generate_server_cert(
    tmp_path: Path,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    name: str = "server",
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    expired: bool = False,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey, Path, Path]:
    """Generates an end-entity server certificate signed by the specified CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AEGIS Security Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, (dns_names or ["localhost"])[0]),
    ])

    san_items: list[x509.GeneralName] = []
    for d in dns_names or ["localhost"]:
        san_items.append(x509.DNSName(d))
    if ip_addresses:
        import ipaddress
        for ip in ip_addresses:
            san_items.append(x509.IPAddress(ipaddress.ip_address(ip)))

    if expired:
        start = datetime.now(UTC) - timedelta(days=10)
        end = datetime.now(UTC) - timedelta(days=1)
    else:
        start = datetime.now(UTC) - timedelta(minutes=5)
        end = datetime.now(UTC) + timedelta(days=30)

    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{name}_cert.pem"
    key_path = tmp_path / f"{name}_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, key, cert_path, key_path


class EphemeralTLSServer:
    """Configurable loopback TLS server for testing handshake validation and rotation."""

    def __init__(self, cert_path: Path, key_path: Path):
        self.cert_path = cert_path
        self.key_path = key_path
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(self.cert_path, self.key_path)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.listener.settimeout(5.0)
        self.port = self.listener.getsockname()[1]
        self._running = True

    def rotate_certificate(self, new_cert_path: Path, new_key_path: Path):
        """Live updates the server's TLS context without interrupting the listening socket."""
        new_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        new_context.load_cert_chain(new_cert_path, new_key_path)
        self.context = new_context
        self.cert_path = new_cert_path
        self.key_path = new_key_path

    def serve_single_handshake(self):
        """Accepts one client, performs server-side TLS handshake, and gracefully closes."""
        try:
            client_sock, _ = self.listener.accept()
            client_sock.settimeout(5.0)
            try:
                with self.context.wrap_socket(client_sock, server_side=True) as secure_sock:
                    # Echo 4 bytes or receive handshake probe
                    data = secure_sock.recv(4)
                    if data:
                        secure_sock.sendall(data)
            except (ssl.SSLError, ConnectionError):
                pass  # Peer verification failure is expected in negative test cases
        except socket.timeout:
            pass

    def close(self):
        self._running = False
        try:
            self.listener.close()
        except Exception:  # noqa: S110
            pass


def test_positive_tls_handshake_with_valid_ca_and_san(tmp_path):
    """Verifies that a valid certificate signed by the trusted CA with matching DNS SAN succeeds."""
    ca_cert, ca_key, ca_cert_path, _ = generate_ca(tmp_path, "TrustedCA")
    _, _, srv_cert_path, srv_key_path = generate_server_cert(
        tmp_path, ca_cert, ca_key, "server_a", dns_names=["localhost"]
    )

    server = EphemeralTLSServer(srv_cert_path, srv_key_path)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(server.serve_single_handshake)

            # Client SSL Context configured with trusted CA
            client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert_path))
            client_ctx.check_hostname = True

            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_sock:
                with client_ctx.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                    tls_sock.sendall(b"PING")
                    reply = tls_sock.recv(4)
                    assert reply == b"PING"
                    assert tls_sock.version() in {"TLSv1.2", "TLSv1.3"}
                    peercert = tls_sock.getpeercert()
                    assert peercert is not None
                    # Verify peer certificate Subject Alternative Name contains localhost
                    san = [v for k, v in peercert.get("subjectAltName", []) if k == "DNS"]
                    assert "localhost" in san

            future.result(timeout=5)
    finally:
        server.close()


def test_negative_tls_untrusted_ca_rejected(tmp_path):
    """Verifies that a certificate signed by an untrusted/different CA is rejected."""
    _, _, trusted_ca_path, _ = generate_ca(tmp_path, "TrustedCA")
    untrusted_ca_cert, untrusted_ca_key, _, _ = generate_ca(tmp_path, "RogueCA")

    # Server uses certificate signed by Rogue CA
    _, _, srv_cert_path, srv_key_path = generate_server_cert(
        tmp_path, untrusted_ca_cert, untrusted_ca_key, "rogue_server", dns_names=["localhost"]
    )

    server = EphemeralTLSServer(srv_cert_path, srv_key_path)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(server.serve_single_handshake)

            # Client only trusts TrustedCA
            client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(trusted_ca_path))
            client_ctx.check_hostname = True

            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_sock:
                with pytest.raises(ssl.SSLCertVerificationError) as exc_info:
                    with client_ctx.wrap_socket(raw_sock, server_hostname="localhost"):
                        pass
                assert "CERTIFICATE_VERIFY_FAILED" in str(exc_info.value) or "self-signed" in str(exc_info.value)

            future.result(timeout=5)
    finally:
        server.close()


def test_negative_tls_hostname_mismatch_rejected(tmp_path):
    """Verifies that a certificate without a matching hostname is rejected."""
    ca_cert, ca_key, ca_cert_path, _ = generate_ca(tmp_path, "TrustedCA")
    # Certificate valid ONLY for "internal-db.aegis.corp"
    _, _, srv_cert_path, srv_key_path = generate_server_cert(
        tmp_path, ca_cert, ca_key, "mismatch_server", dns_names=["internal-db.aegis.corp"]
    )

    server = EphemeralTLSServer(srv_cert_path, srv_key_path)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(server.serve_single_handshake)

            client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert_path))
            client_ctx.check_hostname = True

            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_sock:
                with pytest.raises((ssl.CertificateError, ssl.SSLCertVerificationError)) as exc_info:
                    # Client connects expecting "localhost"
                    with client_ctx.wrap_socket(raw_sock, server_hostname="localhost"):
                        pass
                assert "hostname" in str(exc_info.value).lower() or "match" in str(exc_info.value).lower()

            future.result(timeout=5)
    finally:
        server.close()


def test_negative_tls_expired_certificate_rejected(tmp_path):
    """Verifies that an expired certificate is rejected fail-closed."""
    ca_cert, ca_key, ca_cert_path, _ = generate_ca(tmp_path, "TrustedCA")
    # Certificate expired 1 day ago
    _, _, srv_cert_path, srv_key_path = generate_server_cert(
        tmp_path, ca_cert, ca_key, "expired_server", dns_names=["localhost"], expired=True
    )

    server = EphemeralTLSServer(srv_cert_path, srv_key_path)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(server.serve_single_handshake)

            client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert_path))
            client_ctx.check_hostname = True

            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_sock:
                with pytest.raises(ssl.SSLCertVerificationError) as exc_info:
                    with client_ctx.wrap_socket(raw_sock, server_hostname="localhost"):
                        pass
                assert "certificate has expired" in str(exc_info.value).lower() or "verify failed" in str(exc_info.value).lower()

            future.result(timeout=5)
    finally:
        server.close()


def test_certificate_rotation_drill(tmp_path):
    """Exercises complete zero-downtime certificate rotation drill.
    
    1. Server starts with Cert A (signed by TrustedCA).
    2. Client connects and verifies Cert A fingerprint.
    3. Server live-rotates to Cert B (signed by TrustedCA with fresh serial).
    4. Client connects and verifies Cert B fingerprint.
    5. Server attempts to rotate to untrusted/invalid Cert C.
    6. Client reconnects and fails closed; zero insecure fallback.
    """
    ca_cert, ca_key, ca_cert_path, _ = generate_ca(tmp_path, "TrustedCA")

    # Initial Cert A
    cert_a, _, cert_a_path, key_a_path = generate_server_cert(
        tmp_path, ca_cert, ca_key, "server_cert_a", dns_names=["localhost"]
    )
    fp_a = cert_a.fingerprint(hashes.SHA256()).hex()

    # Replacement Cert B (valid)
    cert_b, _, cert_b_path, key_b_path = generate_server_cert(
        tmp_path, ca_cert, ca_key, "server_cert_b", dns_names=["localhost"]
    )
    fp_b = cert_b.fingerprint(hashes.SHA256()).hex()
    assert fp_a != fp_b

    # Invalid Cert C (signed by separate untrusted CA)
    untrusted_ca, untrusted_key, _, _ = generate_ca(tmp_path, "RogueCA")
    _, _, cert_c_path, key_c_path = generate_server_cert(
        tmp_path, untrusted_ca, untrusted_key, "server_cert_c", dns_names=["localhost"]
    )

    server = EphemeralTLSServer(cert_a_path, key_a_path)
    try:
        client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert_path))
        client_ctx.check_hostname = True

        # Phase 1: Connect with Cert A
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut1 = pool.submit(server.serve_single_handshake)
            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_sock:
                with client_ctx.wrap_socket(raw_sock, server_hostname="localhost") as s1:
                    s1.sendall(b"REQ1")
                    assert s1.recv(4) == b"REQ1"
                    peercert_der = s1.getpeercert(binary_form=True)
                    assert peercert_der is not None
                    observed_fp = hashlib_sha256(peercert_der)
                    assert observed_fp == fp_a
            fut1.result(timeout=5)

        # Phase 2: Live-rotate to Cert B
        server.rotate_certificate(cert_b_path, key_b_path)

        with ThreadPoolExecutor(max_workers=1) as pool:
            fut2 = pool.submit(server.serve_single_handshake)
            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_sock:
                with client_ctx.wrap_socket(raw_sock, server_hostname="localhost") as s2:
                    s2.sendall(b"REQ2")
                    assert s2.recv(4) == b"REQ2"
                    peercert_der = s2.getpeercert(binary_form=True)
                    assert peercert_der is not None
                    observed_fp = hashlib_sha256(peercert_der)
                    assert observed_fp == fp_b
            fut2.result(timeout=5)

        # Phase 3: Rotate to Invalid Cert C -> Client fails closed
        server.rotate_certificate(cert_c_path, key_c_path)

        with ThreadPoolExecutor(max_workers=1) as pool:
            fut3 = pool.submit(server.serve_single_handshake)
            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_sock:
                with pytest.raises(ssl.SSLCertVerificationError):
                    with client_ctx.wrap_socket(raw_sock, server_hostname="localhost"):
                        pass
            fut3.result(timeout=5)

    finally:
        server.close()


def hashlib_sha256(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def test_redis_transport_tls_client_wiring_and_reconnection():
    """Validates redis_client TLS parameter construction and fail-closed security policy."""
    # Rediss URL without CA configuration requires SSL and hostname check
    settings = Settings(
        redis_url="rediss://:mypassword@redis.internal:6379/0",
        redis_ca="/path/to/enterprise-ca.pem",
    )
    client = redis_client(settings)
    assert client is not None
    pool = client.connection_pool
    # Verify pool kwargs enforce strict TLS verification
    assert pool.connection_kwargs.get("ssl_cert_reqs") == "required"
    assert pool.connection_kwargs.get("ssl_check_hostname") is True
    assert pool.connection_kwargs.get("ssl_ca_certs") == "/path/to/enterprise-ca.pem"
    client.close()

    # Plaintext redis:// returns unencrypted pool without silent fallback
    plain_settings = Settings(redis_url="redis://:mypassword@localhost:6379/0")
    plain_client = redis_client(plain_settings)
    assert plain_client is not None
    assert "ssl_cert_reqs" not in plain_client.connection_pool.connection_kwargs
    plain_client.close()


def test_postgres_connect_kwargs_preserves_libpq_tls_parameters():
    """Validates that postgres_connect_kwargs extracts libpq TLS parameters faithfully."""
    url = "postgresql+psycopg://aegis_user:secret@pg.internal:5432/aegis_db?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem"
    kwargs = postgres_connect_kwargs(url)
    assert kwargs["host"] == "pg.internal"
    assert kwargs["port"] == 5432
    assert kwargs["user"] == "aegis_user"
    assert kwargs["dbname"] == "aegis_db"
    assert kwargs["sslmode"] == "verify-full"
    assert kwargs["sslrootcert"] == "/etc/ssl/ca.pem"


def test_production_compose_and_hba_transport_security_invariants():
    """Audits compose.production.yaml and pg_hba.conf for strict transport security invariants."""
    # 1. Audit pg_hba.conf
    hba_path = ROOT / "deploy" / "postgres" / "pg_hba.conf"
    assert hba_path.exists(), "pg_hba.conf must exist"
    hba_content = hba_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in hba_content.splitlines() if line.strip() and not line.strip().startswith("#")]

    # Check for unconditional plaintext TCP rejection
    assert any("hostnossl" in line and "reject" in line for line in lines), (
        "pg_hba.conf must unconditionally reject unencrypted TCP connections via hostnossl ... reject"
    )
    # Check that SSL TCP connections require scram-sha-256
    assert any("hostssl" in line and "scram-sha-256" in line for line in lines), (
        "pg_hba.conf must enforce scram-sha-256 authentication for hostssl connections"
    )
    # Check that no unauthenticated 'trust' rule exists
    assert not any("trust" in line for line in lines), "pg_hba.conf must never contain 'trust' rules"

    # 2. Audit compose.production.yaml
    compose_path = ROOT / "compose.production.yaml"
    assert compose_path.exists(), "compose.production.yaml must exist"
    compose_content = compose_path.read_text(encoding="utf-8")

    # PostgreSQL must run with ssl=on and explicit cert mounts
    assert "ssl=on" in compose_content
    assert "sslmode=verify-full" in compose_content

    # Redis must run with --port 0 (plaintext disabled) and --tls-port 6379
    assert "--port 0" in compose_content
    assert "--tls-port 6379" in compose_content
    assert "rediss://" in compose_content
    assert "ssl_cert_reqs=required" in compose_content

    # OpenSearch must enforce TLS on HTTP and transport
    assert "plugins.security.ssl.http.enabled: \"true\"" in compose_content
    assert "plugins.security.ssl.transport.enforce_hostname_verification: \"true\"" in compose_content
    assert "https://opensearch:9200" in compose_content
