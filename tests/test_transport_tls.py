"""Real loopback TLS handshakes through redis-py, not a Redis service qualification."""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aegis.transport import redis_client
from tests.test_titan_phase4 import production


@pytest.mark.parametrize("mode", ["trusted", "untrusted", "hostname", "invalid_ca", "missing_ca"])
def test_redis_tls_handshake_verification(tmp_path, mode):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    ca = str(cert_path)
    if mode == "untrusted":
        ca = None  # System roots must reject the ephemeral self-signed certificate.
    if mode in {"invalid_ca", "missing_ca"}:
        ca = str(tmp_path / "bad-ca.pem")
        if mode == "invalid_ca":
            (tmp_path / "bad-ca.pem").write_text("not a certificate")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)

        def serve():
            with listener.accept()[0] as connection:
                connection.settimeout(5)
                try:
                    with context.wrap_socket(connection, server_side=True) as secured:
                        secured.recv(1)
                except (ssl.SSLError, ConnectionError):
                    pass  # Expected peer abort when certificate verification fails.

        host = "127.0.0.1" if mode == "hostname" else "localhost"
        settings = production(
            redis_url=f"rediss://:placeholder@{host}:{listener.getsockname()[1]}/0", redis_ca=ca
        )
        client = redis_client(settings)
        connection = client.connection_pool.make_connection()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(serve)
            if mode == "trusted":
                secured = connection._connect()
                assert secured.version() in {"TLSv1.2", "TLSv1.3"}
                secured.close()
            else:
                with pytest.raises((ssl.SSLError, FileNotFoundError)):
                    connection._connect()
            future.result(timeout=8)
        client.close()
