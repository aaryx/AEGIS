"""Separate search projection and notification delivery from detection commits."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "search_jobs",
        sa.Column("event_id", sa.String(80), sa.ForeignKey("events_metadata.id"), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.Float(), nullable=False),
        sa.Column("last_error", sa.String(100)),
    )
    op.create_index("ix_search_jobs_organization_id", "search_jobs", ["organization_id"])
    op.create_index("ix_search_jobs_ready", "search_jobs", ["state", "available_at"])
    op.create_table(
        "integrations",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("endpoint", sa.String(2048), nullable=False),
        sa.Column("secret_env", sa.String(100)),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("last_error", sa.String(100)),
        sa.Column("last_success", sa.Float()),
        sa.UniqueConstraint("organization_id", "name"),
    )
    op.create_index("ix_integrations_organization_id", "integrations", ["organization_id"])
    op.create_index("ix_integrations_created_at", "integrations", ["created_at"])
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notification_id", sa.String(80), sa.ForeignKey("notifications.id"), nullable=False),
        sa.Column("integration_id", sa.String(80), sa.ForeignKey("integrations.id"), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.Float(), nullable=False),
        sa.Column("last_error", sa.String(100)),
        sa.Column("delivered_at", sa.Float()),
        sa.UniqueConstraint("notification_id", "integration_id"),
    )
    op.create_index(
        "ix_notification_deliveries_organization_id", "notification_deliveries", ["organization_id"]
    )
    op.create_index("ix_notification_deliveries_created_at", "notification_deliveries", ["created_at"])
    op.create_index("ix_delivery_ready", "notification_deliveries", ["state", "available_at"])
    # Reconcile existing processed evidence; deterministic document IDs make reindexing safe.
    op.execute(
        "INSERT INTO search_jobs (event_id, organization_id, state, attempts, available_at) SELECT id, organization_id, 'PENDING', 0, 0 FROM events_metadata WHERE state = 'PROCESSED'"
    )


def downgrade():
    raise RuntimeError("Restore a verified backup rather than discarding durable jobs")
