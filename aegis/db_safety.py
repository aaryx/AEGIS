"""Database safety verification and test isolation enforcement.

Rejects ambiguous connection targets before test setup. Operators must still
verify that an explicitly named test database is disposable.
"""

from __future__ import annotations

import os
import re
from pathlib import PurePosixPath

from sqlalchemy.engine import make_url


class DatabaseSafetyError(RuntimeError):
    """Raised when a test suite attempts to run against an unsafe or non-test database."""


DISALLOWED_DB_NAMES = {
    "aegis",
    "aegis_prod",
    "aegis_production",
    "aegis_staging",
    "aegis_stage",
    "aegis_live",
    "production",
    "prod",
    "staging",
    "stage",
    "live",
    "master",
    "main",
    "postgres",
    "default",
}

DISALLOWED_ENVIRONMENTS = {
    "production",
    "prod",
    "staging",
    "stage",
}


def validate_test_database_url(
    url: str | None,
    environment: str | None = None,
    allow_sqlite_memory: bool = True,
) -> str:
    """Require explicit test names and reject connection-target overrides.

    This guard does not establish database ownership or authorize destructive work.
    """
    if not url or not isinstance(url, str) or not url.strip():
        raise DatabaseSafetyError("Test database URL is empty or unconfigured.")

    norm_env = (environment or os.environ.get("ENVIRONMENT", "testing")).strip().lower()
    if norm_env in DISALLOWED_ENVIRONMENTS:
        raise DatabaseSafetyError(
            f"Refusing to execute integration tests in environment '{norm_env}'. "
            f"Test execution is strictly prohibited against production or staging environments."
        )

    clean_url = url.strip()

    try:
        parsed = make_url(clean_url)
    except Exception:
        raise DatabaseSafetyError("Malformed test database URL.") from None
    backend = parsed.get_backend_name()
    if backend not in {"sqlite", "postgresql"}:
        raise DatabaseSafetyError("Refusing to execute tests with unsupported database backend.")
    # libpq query parameters override authority/path values. Permit only options
    # which cannot select a different database, host, service or search path.
    allowed_options = {"sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout", "application_name"}
    if set(parsed.query) - allowed_options or (backend == "sqlite" and parsed.query):
        raise DatabaseSafetyError("Refusing to execute tests with connection target overrides.")
    if backend == "sqlite":
        if parsed.database == ":memory:":
            if allow_sqlite_memory:
                return clean_url
            raise DatabaseSafetyError("In-memory SQLite not permitted when persistent test DB required.")
        filename = PurePosixPath((parsed.database or "").replace("\\", "/")).name.lower()
        if not re.search(r"(^|[_.-])test([_.-]|$)", filename):
            raise DatabaseSafetyError("Refusing to execute tests against a non-test SQLite filename.")
        return clean_url

    db_name = parsed.database or ""
    if not _test_database_name(db_name):
        raise DatabaseSafetyError("Target database is not an explicitly isolated test database.")
    if any(os.environ.get(key) for key in ("PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR", "PGOPTIONS")):
        raise DatabaseSafetyError("Refusing to execute tests with ambient libpq target overrides.")
    hostname = (parsed.host or "").lower()
    if not hostname or "," in hostname or "/" in hostname:
        raise DatabaseSafetyError("Refusing to execute tests without a single explicit database host.")
    if hostname not in {"localhost", "127.0.0.1", "::1"}:
        if os.environ.get("AEGIS_ALLOW_REMOTE_TEST_DB") != "1":
            raise DatabaseSafetyError(
                "Refusing to execute tests against remote or managed cloud host without explicit override."
            )
    return clean_url


def _test_database_name(name: str) -> bool:
    return bool(
        re.fullmatch(r"[a-zA-Z0-9_]{1,63}", name)
        and "test" in name.lower().split("_")
        and name.lower() not in DISALLOWED_DB_NAMES
    )


def ensure_isolated_test_database(admin_dsn: str, test_db_name: str) -> None:
    """Connect to the administrative maintenance database and create the isolated test DB if absent."""
    import psycopg

    # Re-verify test database name meets strict safety criteria before creating
    if not _test_database_name(test_db_name):
        raise DatabaseSafetyError(f"Cannot auto-provision non-test database name '{test_db_name}'.")

    # Connect to maintenance database in autocommit mode
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (test_db_name,))
            if not cur.fetchone():
                cur.execute(psycopg.sql.SQL("CREATE DATABASE {}").format(psycopg.sql.Identifier(test_db_name)))
