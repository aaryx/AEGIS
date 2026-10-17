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
            "audit_checkpoints",
            "replay_jobs",
            "replay_matches",
        } <= set(inspect(engine).get_table_names())
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0010"
        assert {"intel_observables", "intel_observable_events", "intel_enrichments", "intel_history"} <= set(
            inspect(engine).get_table_names()
        )
        assert {"soar_playbooks", "soar_versions", "soar_runs"} <= set(inspect(engine).get_table_names())
        assert {"storylines", "storyline_members"} <= set(inspect(engine).get_table_names())
        engine.dispose()
    finally:
        get_settings.cache_clear()


def test_stepwise_schema_migration_chain(tmp_path, monkeypatch):
    """Verify that migrations upgrade cleanly one revision at a time from 0001 to 0007."""
    url = f"sqlite:///{tmp_path / 'stepwise.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config("alembic.ini")

    try:
        engine = create_engine(url)

        # 1. 0001
        command.upgrade(cfg, "0001")
        insp = inspect(engine)
        assert "organizations" in insp.get_table_names()
        assert "replay_jobs" not in insp.get_table_names()

        # 2. 0002 to 0006
        for rev in ["0002", "0003", "0004", "0005", "0006"]:
            command.upgrade(cfg, rev)
            with engine.connect() as conn:
                assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == rev

        # 3. 0007 (Detection Engineering & Attack Replay Lab)
        command.upgrade(cfg, "0007")
        insp_0007 = inspect(engine)
        tables_0007 = set(insp_0007.get_table_names())
        assert "replay_jobs" in tables_0007
        assert "replay_matches" in tables_0007

        # Verify added columns on detection_rules
        rule_cols = {col["name"] for col in insp_0007.get_columns("detection_rules")}
        assert {"status", "lifecycle_stage", "activated_at", "activated_by", "last_replay_id"} <= rule_cols

        # Verify added columns on rule_versions
        ver_cols = {col["name"] for col in insp_0007.get_columns("rule_versions")}
        assert {"lifecycle_stage", "approved_by", "approved_at"} <= ver_cols

        # Verify indexes on replay_jobs and replay_matches
        indexes_jobs = {idx["name"] for idx in insp_0007.get_indexes("replay_jobs")}
        assert "ix_replay_jobs_org_rule" in indexes_jobs

        indexes_matches = {idx["name"] for idx in insp_0007.get_indexes("replay_matches")}
        assert "ix_replay_matches_job_event" in indexes_matches

        with engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0007"

        # 4. 0008 to 0010 (Storylines, SOAR, Threat Intelligence)
        for rev in ["0008", "0009", "0010"]:
            command.upgrade(cfg, rev)
            with engine.connect() as conn:
                assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == rev

        insp_head = inspect(engine)
        tables_head = set(insp_head.get_table_names())
        assert {"storylines", "soar_playbooks", "soar_versions", "soar_runs", "intel_observables", "intel_enrichments"} <= tables_head

        engine.dispose()
    finally:
        get_settings.cache_clear()


def test_downgrade_policy_rejection(tmp_path, monkeypatch):
    """Verify that project policy strictly disables destructive downgrades across all revisions."""
    import pytest

    url = f"sqlite:///{tmp_path / 'downgrade.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config("alembic.ini")

    try:
        command.upgrade(cfg, "head")
        with pytest.raises(RuntimeError, match="Destructive downgrade is disabled"):
            command.downgrade(cfg, "-1")
    finally:
        get_settings.cache_clear()


def test_intelligence_upgrade_from_existing_events_schema(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'intel-upgrade.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        cfg = Config("alembic.ini")
        command.upgrade(cfg, "0009")
        engine = create_engine(url)
        # Reproduce the real pre-feature event schema (0001 uses current ORM metadata).
        with engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_events_metadata_intel_indexed"))
            connection.execute(text("ALTER TABLE events_metadata DROP COLUMN intel_indexed"))
        command.upgrade(cfg, "0010")
        assert "intel_indexed" in {c["name"] for c in inspect(engine).get_columns("events_metadata")}
        assert "intel_history" in inspect(engine).get_table_names()
        engine.dispose()
    finally:
        get_settings.cache_clear()
