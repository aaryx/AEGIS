"""Regression and safety test suite for database isolation and URL verification.

Proves that:
1. Operational application databases ('aegis', 'aegis.db') are rejected.
2. Production and staging environments ('production', 'staging', 'prod') are rejected.
3. Protected database names ('postgres', 'master', 'main', 'default') are rejected.
4. Managed cloud database hosts are blocked unless explicitly permitted.
5. Isolated test databases (e.g. 'aegis_test') are accepted.
6. Ephemeral test SQLite instances are accepted, while default operational paths are rejected.
"""

import pytest

from aegis.db_safety import (
    DatabaseSafetyError,
    ensure_isolated_test_database,
    validate_test_database_url,
)


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "postgresql+psycopg://aegis:secret@127.0.0.1:5432/aegis",
        "postgresql://aegis:secret@localhost:5432/aegis",
        "postgresql://aegis:secret@127.0.0.1:5432/production",
        "postgresql://aegis:secret@127.0.0.1:5432/prod",
        "postgresql://aegis:secret@127.0.0.1:5432/staging",
        "postgresql://aegis:secret@127.0.0.1:5432/stage",
        "postgresql://aegis:secret@127.0.0.1:5432/postgres",
        "postgresql://aegis:secret@127.0.0.1:5432/master",
        "postgresql://aegis:secret@127.0.0.1:5432/main",
        "postgresql://aegis:secret@127.0.0.1:5432/default",
        "postgresql://aegis:secret@127.0.0.1:5432/aegis_production",
        "postgresql://aegis:secret@127.0.0.1:5432/aegis_staging",
        "postgresql://aegis:secret@127.0.0.1:5432/customer_db",
        "sqlite:///./aegis.db",
        "sqlite:////var/data/aegis.db",
    ],
)
def test_rejects_unsafe_database_urls(unsafe_url):
    """Refuse to execute integration or test suites when targeted at non-test databases."""
    with pytest.raises(DatabaseSafetyError) as exc_info:
        validate_test_database_url(unsafe_url, environment="testing")
    assert "Refusing to execute" in str(exc_info.value) or "not an explicitly isolated test database" in str(exc_info.value)


@pytest.mark.parametrize("disallowed_env", ["production", "prod", "staging", "stage", "PRODUCTION", "Staging"])
def test_rejects_unsafe_environments(disallowed_env):
    """Refuse to execute tests if environment is configured as production or staging."""
    safe_url = "postgresql+psycopg://aegis:secret@127.0.0.1:5432/aegis_test"
    with pytest.raises(DatabaseSafetyError) as exc_info:
        validate_test_database_url(safe_url, environment=disallowed_env)
    assert "strictly prohibited against production or staging" in str(exc_info.value)


@pytest.mark.parametrize(
    "invalid_input",
    [
        "",
        "   ",
        None,
        "postgresql://aegis:secret@127.0.0.1:5432/",
        "postgresql://aegis:secret@127.0.0.1:5432",
    ],
)
def test_rejects_empty_or_missing_database_names(invalid_input):
    """Empty URLs or URLs without a target database must fail immediately."""
    with pytest.raises(DatabaseSafetyError):
        validate_test_database_url(invalid_input, environment="testing")


def test_rejects_managed_cloud_hosts_without_override(monkeypatch):
    """Connecting to cloud RDS/Neon/Azure databases in test mode is prohibited without explicit override."""
    monkeypatch.delenv("AEGIS_ALLOW_REMOTE_TEST_DB", raising=False)
    cloud_url = "postgresql://user:pass@mydb.us-east-1.rds.amazonaws.com:5432/aegis_test"
    with pytest.raises(DatabaseSafetyError) as exc_info:
        validate_test_database_url(cloud_url, environment="testing")
    assert "managed cloud host" in str(exc_info.value)


def test_accepts_managed_cloud_host_with_explicit_override(monkeypatch):
    """Explicit environment flag allows cloud test instances when intentionally configured."""
    monkeypatch.setenv("AEGIS_ALLOW_REMOTE_TEST_DB", "1")
    cloud_url = "postgresql://user:pass@mydb.us-east-1.rds.amazonaws.com:5432/aegis_test"
    result = validate_test_database_url(cloud_url, environment="testing")
    assert result == cloud_url


@pytest.mark.parametrize(
    "safe_url",
    [
        "postgresql+psycopg://aegis:secret@127.0.0.1:5432/aegis_test",
        "postgresql://aegis:secret@localhost:5432/aegis_test_concurrency",
        "postgresql+psycopg://aegis:secret@127.0.0.1:5432/test_aegis_suite",
        "postgresql://aegis:secret@127.0.0.1:5432/aegis_test_mig_1234abcd",
        "sqlite:///:memory:",
        "sqlite:///./test.db",
        "sqlite:////tmp/pytest-of-user/test_run.db",
    ],
)
def test_accepts_valid_isolated_test_databases(safe_url):
    """Dedicated test database URLs meeting naming and isolation invariants are accepted."""
    result = validate_test_database_url(safe_url, environment="testing")
    assert result == safe_url


def test_ensure_isolated_test_database_rejects_unsafe_names():
    """Auto-provisioning helper refuses to create or touch non-test databases."""
    with pytest.raises(DatabaseSafetyError) as exc_info:
        ensure_isolated_test_database("postgresql://...", "aegis")
    assert "Cannot auto-provision non-test database" in str(exc_info.value)
