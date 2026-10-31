"""scripts/initialize.py: .env loading (B5) and maintenance-role grants (B4)."""

import os

import pytest
from dotenv import load_dotenv
from sqlalchemy import select

from aegis.config import Settings
from aegis.db import Base, User, database
from aegis.security import check_password
from scripts import initialize

VARIABLES = (
    "BOOTSTRAP_USERNAME",
    "BOOTSTRAP_PASSWORD",
    "POSTGRES_RUNTIME_PASSWORD",
    "POSTGRES_MAINTENANCE_PASSWORD",
    "OPENSEARCH_ADMIN_PASSWORD",
)
PASSWORD = "dotenv-bootstrap-pass-24c"


@pytest.fixture
def run(tmp_path, monkeypatch):
    """Point main() at a tmp SQLite schema; database_url is what main() sees for role provisioning."""
    for name in VARIABLES:  # setenv then delenv records the key, so .env values are removed afterwards
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(initialize.command, "upgrade", lambda *_: None)
    engine, sessions = database(f"sqlite:///{tmp_path / 'init.db'}")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(initialize, "database", lambda _url: (engine, sessions))

    def main(database_url="sqlite:///unused.db"):
        settings = Settings(
            environment="testing",
            database_url=database_url,
            audit_secret="test-audit-integrity-key-at-least-32-characters",
            _env_file=None,
        )
        monkeypatch.setattr(initialize, "get_settings", lambda: settings)
        initialize.main()
        with sessions() as db:
            return db.scalars(select(User)).all()

    return main


def test_initialize_reads_dotenv_and_env_wins(run, tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(f"BOOTSTRAP_USERNAME=fromdotenv\nBOOTSTRAP_PASSWORD={PASSWORD}\n")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "fromenv")

    (user,) = run()

    assert user.username == "fromenv"
    assert check_password(user.password_hash, PASSWORD)


def test_maintenance_role_can_write_audit_chain(run, monkeypatch):
    statements = []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, query, params=None):
            statements.append(str(query))
            return self

        def fetchone(self):
            return (1,)  # roles already exist, so CREATE ROLE is skipped

    monkeypatch.setattr(initialize.psycopg, "connect", lambda **_: FakeConnection())
    monkeypatch.setenv("POSTGRES_MAINTENANCE_PASSWORD", "synthetic-maintenance-password")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", PASSWORD)

    run("postgresql+psycopg://aegis:synthetic@localhost:5432/aegis")

    revoke = statements.index("REVOKE UPDATE, DELETE ON audit_logs FROM aegis_maintenance")
    for grant in (
        "GRANT INSERT ON audit_logs TO aegis_maintenance",
        "GRANT INSERT, UPDATE ON audit_heads TO aegis_maintenance",
        "GRANT UPDATE (audit_head) ON organizations TO aegis_maintenance",
    ):
        assert grant in statements and statements.index(grant) < revoke, grant
    assert not [
        s
        for s in statements
        if s.startswith("GRANT") and "audit_logs" in s and ("UPDATE" in s or "DELETE" in s)
    ]


@pytest.mark.parametrize("name", VARIABLES)
@pytest.mark.parametrize("in_env, in_dotenv", [(True, False), (True, True), (False, False)])
def test_environment_wins_over_dotenv(run, tmp_path, monkeypatch, name, in_env, in_dotenv):
    """Preservation: the line main() runs first must never override a set variable."""
    (tmp_path / ".env").write_text(f"{name}=fromdotenv\n" if in_dotenv else "")
    if in_env:
        monkeypatch.setenv(name, "fromenv")

    load_dotenv(".env")

    assert os.environ.get(name) == ("fromenv" if in_env else None)
