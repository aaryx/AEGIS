from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from aegis.config import get_settings


def test_clean_install_and_repeated_migration(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        command.upgrade(Config("alembic.ini"), "head")
        command.upgrade(Config("alembic.ini"), "head")
        engine = create_engine(url)
        assert {
            "search_jobs",
            "integrations",
            "notification_deliveries",
            "agents",
            "agent_enrollment_tokens",
            "audit_heads",
        } <= set(inspect(engine).get_table_names())
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0005"
        engine.dispose()
    finally:
        get_settings.cache_clear()
