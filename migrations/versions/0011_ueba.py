"""Tenant-scoped behavioral profiles, immutable findings, evidence and durable jobs."""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
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
    # 0001 uses release metadata: clean installs can already contain these tables.
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "ueba_profiles" not in existing:
        op.create_table(
            "ueba_profiles",
            *owned(),
            sa.Column("entity_type", sa.String(16), nullable=False),
            sa.Column("entity", sa.String(254), nullable=False),
            sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
            sa.Column("baseline", sa.JSON(), nullable=False),
            sa.Column("risk_score", sa.Integer(), nullable=False),
            sa.UniqueConstraint("organization_id", "entity_type", "entity"),
            sa.UniqueConstraint("organization_id", "id"),
        )
    if "ueba_findings" not in existing:
        op.create_table(
            "ueba_findings",
            *owned(),
            sa.Column("profile_id", sa.String(80), nullable=False, index=True),
            sa.Column("detector", sa.String(60), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("window_end", sa.DateTime(timezone=True), nullable=False, index=True),
            sa.Column("risk_score", sa.Integer(), nullable=False),
            sa.Column("severity", sa.String(16), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("comparison", sa.JSON(), nullable=False),
            sa.Column("explanation", sa.String(2000), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("lifecycle", sa.JSON(), nullable=False),
            sa.ForeignKeyConstraint(
                ["organization_id", "profile_id"], ["ueba_profiles.organization_id", "ueba_profiles.id"]
            ),
            sa.UniqueConstraint("organization_id", "profile_id", "detector", "window_end"),
            sa.UniqueConstraint("organization_id", "id"),
        )
    if "ueba_evidence" not in existing:
        op.create_table(
            "ueba_evidence",
            *owned(),
            sa.Column("finding_id", sa.String(80), nullable=False, index=True),
            sa.Column("event_id", sa.String(80), nullable=False, index=True),
            sa.Column("evidence_hash", sa.String(64), nullable=False),
            sa.ForeignKeyConstraint(
                ["organization_id", "finding_id"],
                ["ueba_findings.organization_id", "ueba_findings.id"],
                ondelete="CASCADE",
            ),
            sa.UniqueConstraint("organization_id", "finding_id", "event_id"),
        )
    if "ueba_jobs" not in existing:
        op.create_table(
            "ueba_jobs",
            *owned(),
            sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
            sa.Column("refresh_only", sa.Boolean(), nullable=False),
            sa.Column("state", sa.String(20), nullable=False, index=True),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("available_at", sa.Float(), nullable=False),
            sa.Column("config", sa.JSON(), nullable=False),
            sa.Column("result", sa.JSON(), nullable=False),
            sa.UniqueConstraint("organization_id", "window_end", "refresh_only"),
        )


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
