"""Initial tenant-scoped operational schema.

This initial migration creates the full schema from the release metadata.
Subsequent changes must use explicit Alembic schema operations.
"""

from alembic import op

from aegis.db import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Freeze the initial table set: later migrations exclusively own new tables.
    later_tables = {
        "intel_observables", "intel_observable_events", "intel_enrichments", "intel_history",
        "soar_playbooks",
        "soar_versions",
        "soar_runs",
        "search_jobs",
        "integrations",
        "notification_deliveries",
        "agents",
        "agent_enrollment_tokens",
        "audit_heads",
        "audit_checkpoints",
        "storylines",
        "storyline_members",
        "replay_jobs",
        "replay_matches",
    }
    initial = set(Base.metadata.tables) - later_tables
    Base.metadata.create_all(
        op.get_bind(), tables=[table for table in Base.metadata.sorted_tables if table.name in initial]
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
        CREATE FUNCTION aegis_audit_immutable() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'Audit records are append-only'; END;
        $$ LANGUAGE plpgsql
        """)
        op.execute(
            "CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION aegis_audit_immutable()"
        )


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
