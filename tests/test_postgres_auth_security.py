"""PostgreSQL authentication and HBA security configuration qualification."""

from pathlib import Path

import yaml


def read_pg_hba_rules() -> list[dict[str, str]]:
    hba_path = Path(__file__).resolve().parents[1] / "deploy" / "postgres" / "pg_hba.conf"
    rules = []
    for line in hba_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "local":
            rules.append({
                "type": "local",
                "database": parts[1],
                "user": parts[2],
                "method": parts[3],
                "options": parts[4:],
            })
        elif len(parts) >= 5 and parts[0] in {"host", "hostssl", "hostnossl"}:
            rules.append({
                "type": parts[0],
                "database": parts[1],
                "user": parts[2],
                "address": parts[3],
                "method": parts[4],
                "options": parts[5:],
            })
    return rules


def test_pg_hba_prohibits_trust_authentication():
    """No rule in pg_hba.conf may grant unauthenticated 'trust' access."""
    rules = read_pg_hba_rules()
    assert rules, "pg_hba.conf must contain active authentication rules"
    for rule in rules:
        assert rule["method"] != "trust", (
            f"Overly permissive 'trust' authentication forbidden in production: {rule}"
        )


def test_pg_hba_rejects_unencrypted_tcp_connections():
    """All unencrypted TCP connection attempts must be explicitly rejected."""
    rules = read_pg_hba_rules()
    hostnossl_rules = [r for r in rules if r["type"] == "hostnossl"]
    assert hostnossl_rules, "pg_hba.conf must contain explicit hostnossl rejection rules"
    for rule in hostnossl_rules:
        assert rule["method"] == "reject", (
            f"Unencrypted TCP connections must be rejected, got: {rule['method']}"
        )
        assert rule["database"] == "all"
        assert rule["user"] == "all"
        assert rule["address"] == "all"


def test_pg_hba_enforces_scram_on_ssl_connections():
    """Encrypted TCP connections must require strong SCRAM-SHA-256 authentication."""
    rules = read_pg_hba_rules()
    hostssl_rules = [r for r in rules if r["type"] == "hostssl"]
    assert hostssl_rules, "pg_hba.conf must specify hostssl authentication rules"
    for rule in hostssl_rules:
        assert rule["method"] == "scram-sha-256", (
            f"hostssl connections must require scram-sha-256, got: {rule['method']}"
        )


def test_pg_hba_restricts_local_unix_socket():
    """Local Unix socket connections must require peer auth strictly for postgres system user,

    and scram-sha-256 for all other database users.
    """
    rules = read_pg_hba_rules()
    local_rules = [r for r in rules if r["type"] == "local"]
    assert local_rules, "pg_hba.conf must define local Unix-socket rules"
    # Ensure all local methods are secure
    for rule in local_rules:
        assert rule["method"] in {"peer", "scram-sha-256"}, (
            f"Unexpected local authentication method: {rule['method']}"
        )
        if rule["method"] == "peer":
            assert rule["user"] == "postgres", "peer authentication must be restricted to system user"
        if rule["user"] == "all":
            assert rule["method"] == "scram-sha-256", "General local access must require SCRAM"


def test_production_compose_postgres_hba_and_tls_mounting():
    """Verify that compose.production.yaml configures TLS flags and mounts pg_hba.conf read-only."""
    compose_path = Path(__file__).resolve().parents[1] / "compose.production.yaml"
    with open(compose_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    pg_service = data["services"]["postgres"]
    command_str = " ".join(pg_service["command"])
    assert "ssl=on" in command_str
    assert "ssl_cert_file=/etc/aegis-tls/server.pem" in command_str
    assert "ssl_key_file=/etc/aegis-tls/server-key.pem" in command_str
    assert "hba_file=/etc/aegis-tls/pg_hba.conf" in command_str

    volumes = pg_service["volumes"]
    hba_mount = next((v for v in volumes if "pg_hba.conf" in v), None)
    assert hba_mount is not None, "pg_hba.conf must be mounted into postgres container"
    assert hba_mount.endswith(":ro"), "pg_hba.conf must be mounted read-only"


def test_production_compose_service_urls_require_verified_tls():
    """Verify that all production service database URLs enforce TLS verify-full and root CA."""
    compose_path = Path(__file__).resolve().parents[1] / "compose.production.yaml"
    with open(compose_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    # Check top-level app-production template
    env = data["x-app-production"]["environment"]
    db_url = env["DATABASE_URL"]
    assert "sslmode=verify-full" in db_url
    assert "sslrootcert=" in db_url

    # Check specific services
    for svc_name in ["initialize", "retention"]:
        svc_env = data["services"][svc_name]["environment"]
        svc_url = svc_env["DATABASE_URL"]
        assert "sslmode=verify-full" in svc_url, f"{svc_name} DATABASE_URL must require verify-full"
        assert "sslrootcert=" in svc_url, f"{svc_name} DATABASE_URL must specify root CA"
