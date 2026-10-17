"""Durable versioned SOAR workflows."""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
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
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = set(insp.get_table_names())
    if "soar_playbooks" not in existing_tables:
        op.create_table(
            "soar_playbooks",
            *owned(),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.UniqueConstraint("organization_id", "name"),
            sa.UniqueConstraint("organization_id", "id"),
        )
    if "soar_versions" not in existing_tables:
        op.create_table(
            "soar_versions",
            *owned(),
            sa.Column("playbook_id", sa.String(80), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("document", sa.JSON(), nullable=False),
            sa.Column("author", sa.String(80), sa.ForeignKey("users.id"), nullable=False),
            sa.ForeignKeyConstraint(
                ["organization_id", "playbook_id"], ["soar_playbooks.organization_id", "soar_playbooks.id"]
            ),
            sa.UniqueConstraint("organization_id", "playbook_id", "version"),
        )
    if "soar_runs" not in existing_tables:
        op.create_table(
            "soar_runs",
            *owned(),
            sa.Column("playbook_id", sa.String(80), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("requested_by", sa.String(80), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("source_type", sa.String(20), nullable=False),
            sa.Column("source_id", sa.String(80), nullable=False),
            sa.Column("dry_run", sa.Boolean(), nullable=False),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column("idempotency_key", sa.String(64), nullable=False),
            sa.Column("fingerprint", sa.String(64), nullable=False),
            sa.Column("context", sa.JSON(), nullable=False),
            sa.Column("history", sa.JSON(), nullable=False),
            sa.Column("cursor", sa.Integer(), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("available_at", sa.Float(), nullable=False),
            sa.Column("deadline", sa.Float(), nullable=False),
            sa.Column("started_at", sa.Float()),
            sa.Column("completed_at", sa.Float()),
            sa.Column("approved_by", sa.String(80), sa.ForeignKey("users.id")),
            sa.Column("approved_at", sa.Float()),
            sa.ForeignKeyConstraint(
                ["organization_id", "playbook_id", "version"],
                ["soar_versions.organization_id", "soar_versions.playbook_id", "soar_versions.version"],
            ),
            sa.UniqueConstraint("organization_id", "idempotency_key"),
            sa.UniqueConstraint(
                "organization_id", "playbook_id", "version", "source_type", "source_id", "dry_run"
            ),
        )
        op.create_index("ix_soar_queue", "soar_runs", ["status", "available_at"])


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
