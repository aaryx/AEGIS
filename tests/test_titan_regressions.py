"""Offline reproductions of TITAN target-boundary failures."""

import secrets
import time
from pathlib import Path

import pytest
import yaml

from aegis.agent import EndpointAgent
from aegis.crypto import ed25519_sign_canonical
from aegis.db import PlaybookExecution
from aegis.db_safety import DatabaseSafetyError, validate_test_database_url
from tests.test_agent_nonce_replay_invariant import helper_create_command


@pytest.mark.parametrize("key", ["PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR", "PGOPTIONS"])
def test_ambient_database_target_override_rejected(monkeypatch, key):
    monkeypatch.setenv(key, "synthetic-override")
    with pytest.raises(DatabaseSafetyError):
        validate_test_database_url("postgresql+psycopg://localhost/aegis_test")


def test_database_tls_options_remain_supported():
    url = "postgresql+psycopg://localhost/aegis_test?sslmode=verify-full&sslrootcert=ca.pem"
    assert validate_test_database_url(url) == url


def test_production_application_services_mount_only_public_ca():
    config = yaml.safe_load(Path("compose.production.yaml").read_text())
    for name in ("api", "worker", "initialize", "retention", "notifications"):
        service = config["services"][name]
        mount, = service["volumes"]
        assert mount["target"] == service["environment"]["OPENSEARCH_CA"]
        assert mount["source"] == "./certs/opensearch/root-ca.pem"
        assert mount["read_only"] is True
        assert mount["bind"]["create_host_path"] is False


@pytest.mark.parametrize("suffix", ["?dbname=aegis", "?host=production.internal", "?service=production"])
def test_database_target_override_rejected(suffix):
    with pytest.raises(DatabaseSafetyError):
        validate_test_database_url("postgresql+psycopg://user:synthetic@localhost/aegis_test" + suffix)


@pytest.mark.parametrize("url", ["sqlite:///customer.db", "postgresql://localhost/contest", "mysql://localhost/aegis_test"])
def test_ambiguous_test_database_rejected(url):
    with pytest.raises(DatabaseSafetyError):
        validate_test_database_url(url)


@pytest.mark.parametrize("poll_first", [False, True])
def test_signed_receipt_cannot_complete_another_hosts_command(system, poll_first):
    client = system["client"]
    intended = EndpointAgent(name="TITAN-INTENDED", simulation_mode=True)
    wrong = EndpointAgent(name="TITAN-WRONG", simulation_mode=True)
    intended.heartbeat(client=client)
    wrong.heartbeat(client=client)
    command_id = helper_create_command(system, intended.name)
    controller_signature = None
    if poll_first:
        command = next(c for c in intended.poll_commands(client=client) if c["id"] == command_id)
        controller_signature = command["controller_signature"]
    receipt = {
        "command_id": command_id,
        "agent_id": wrong.name,
        "organization_id": system["org"],
        "action": "isolate_host",
        "status": "SUCCESS",
        "result": {"isolated": True},
        "timestamp": time.time(),
        "nonce": secrets.token_hex(16),
        "command_signature": controller_signature,
    }
    response = client.post(
        f"/api/v1/agents/{wrong.name}/receipts",
        json={
            "command_id": command_id, "action": "isolate_host", "status": "SUCCESS",
            "receipt": receipt, "signature": ed25519_sign_canonical(wrong.private_key, receipt),
        },
    )
    assert response.status_code == 403
    with system["app"].state.sessions() as db:
        assert db.get(PlaybookExecution, command_id).status == "DISPATCHED"


def test_postgres_integration_diagnostic_skip_sanitizes_credentials(monkeypatch):
    import tests.test_postgres_integration as tpi

    url = "postgresql+psycopg://aegis:super_secret_password_987@127.0.0.1:5432/aegis_test"
    monkeypatch.setattr(tpi, "POSTGRES_TEST_URL", url)

    def failing_create_engine(*args, **kwargs):
        raise ConnectionRefusedError("Connection refused by test mock")

    monkeypatch.setattr(tpi, "create_engine", failing_create_engine)

    with pytest.raises(pytest.skip.Exception) as exc_info:
        # Run generator fixture up to first yield
        next(tpi.pg_engine.__wrapped__())

    skip_reason = str(exc_info.value)
    assert "super_secret_password_987" not in skip_reason
    assert "127.0.0.1:5432/aegis_test" in skip_reason
    assert "ConnectionRefusedError" in skip_reason

