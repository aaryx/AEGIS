"""Observed intelligence and durable lookups; curated IOC semantics are unchanged."""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def owned():
    return [
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column(
            "organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False, index=True
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
    ]


def upgrade():
    # 0001 bootstraps existing tables from release metadata; support both paths.
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = set(insp.get_table_names())

    if "intel_indexed" not in {c["name"] for c in insp.get_columns("events_metadata")}:
        op.add_column(
            "events_metadata",
            sa.Column("intel_indexed", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        op.create_index("ix_events_metadata_intel_indexed", "events_metadata", ["intel_indexed"])
    if "intel_observables" not in existing_tables:
        op.create_table(
            "intel_observables",
            *owned(),
            sa.Column("type", sa.String(12), nullable=False),
            sa.Column("value", sa.String(2048), nullable=False),
            sa.Column("normalized_key", sa.String(64), nullable=False),
            sa.Column("external_allowed", sa.Boolean(), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("organization_id", "normalized_key"),
            sa.UniqueConstraint("organization_id", "id"),
        )
    if "intel_observable_events" not in existing_tables:
        op.create_table(
            "intel_observable_events",
            *owned(),
            sa.Column("observable_id", sa.String(80), nullable=False),
            sa.Column(
                "event_id",
                sa.String(80),
                sa.ForeignKey("events_metadata.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.ForeignKeyConstraint(
                ["organization_id", "observable_id"],
                ["intel_observables.organization_id", "intel_observables.id"],
            ),
            sa.UniqueConstraint("organization_id", "observable_id", "event_id"),
        )
    if "intel_enrichments" not in existing_tables:
        op.create_table(
            "intel_enrichments",
            *owned(),
            sa.Column("observable_id", sa.String(80), nullable=False),
            sa.Column("provider", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("result", sa.JSON(), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("available_at", sa.Float(), nullable=False),
            sa.Column("lease_token", sa.String(36)),
            sa.Column("lease_until", sa.Float(), nullable=False),
            sa.Column("enriched_at", sa.Float()),
            sa.Column("expires_at", sa.Float(), nullable=False),
            sa.ForeignKeyConstraint(
                ["organization_id", "observable_id"],
                ["intel_observables.organization_id", "intel_observables.id"],
            ),
            sa.UniqueConstraint("organization_id", "observable_id", "provider"),
            sa.UniqueConstraint("organization_id", "id"),
        )
        op.create_index("ix_intel_queue", "intel_enrichments", ["status", "available_at"])
    if "intel_history" not in existing_tables:
        op.create_table(
            "intel_history",
            *owned(),
            sa.Column("enrichment_id", sa.String(80), nullable=False, index=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("result", sa.JSON(), nullable=False),
            sa.ForeignKeyConstraint(
                ["organization_id", "enrichment_id"],
                ["intel_enrichments.organization_id", "intel_enrichments.id"],
            ),
        )

    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS tenant_intel_event ON intel_observable_events")
        op.execute(
            "CREATE TRIGGER tenant_intel_event BEFORE INSERT OR UPDATE ON intel_observable_events "
            "FOR EACH ROW EXECUTE FUNCTION aegis_check_tenant_fk('event_id', 'events_metadata')"
        )
    else:
        for action in ("INSERT", "UPDATE"):
            op.execute(f"DROP TRIGGER IF EXISTS tenant_intel_event_{action.lower()}")
            op.execute(
                f"CREATE TRIGGER tenant_intel_event_{action.lower()} BEFORE {action} ON intel_observable_events "  # noqa: S608 -- fixed DDL literals
                "WHEN NOT EXISTS (SELECT 1 FROM events_metadata WHERE id=NEW.event_id "
                "AND organization_id=NEW.organization_id) BEGIN SELECT RAISE(ABORT, 'Cross-tenant reference rejected'); END"
            )


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
