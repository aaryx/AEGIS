"""Detection engineering rule lifecycle and historical event replay engine.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = set(insp.get_table_names())

    # 1. Update detection_rules columns
    if "detection_rules" in tables:
        rule_columns = {col["name"] for col in insp.get_columns("detection_rules")}
        if "status" not in rule_columns:
            op.add_column(
                "detection_rules",
                sa.Column("status", sa.String(30), nullable=False, server_default="ACTIVE"),
            )
        if "lifecycle_stage" not in rule_columns:
            op.add_column(
                "detection_rules",
                sa.Column("lifecycle_stage", sa.String(30), nullable=False, server_default="ACTIVE"),
            )
        if "activated_at" not in rule_columns:
            op.add_column(
                "detection_rules",
                sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
            )
        if "activated_by" not in rule_columns:
            op.add_column(
                "detection_rules",
                sa.Column("activated_by", sa.String(80), nullable=True),
            )
        if "last_replay_id" not in rule_columns:
            op.add_column(
                "detection_rules",
                sa.Column("last_replay_id", sa.String(80), nullable=True),
            )

    # 2. Update rule_versions columns
    if "rule_versions" in tables:
        version_columns = {col["name"] for col in insp.get_columns("rule_versions")}
        if "lifecycle_stage" not in version_columns:
            op.add_column(
                "rule_versions",
                sa.Column("lifecycle_stage", sa.String(30), nullable=False, server_default="ACTIVE"),
            )
        if "approved_by" not in version_columns:
            op.add_column(
                "rule_versions",
                sa.Column("approved_by", sa.String(80), nullable=True),
            )
        if "approved_at" not in version_columns:
            op.add_column(
                "rule_versions",
                sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            )

    # 3. Create replay_jobs table
    if "replay_jobs" not in tables:
        op.create_table(
            "replay_jobs",
            sa.Column("id", sa.String(80), primary_key=True),
            sa.Column("organization_id", sa.String(80), nullable=False, index=True),
            sa.Column("rule_id", sa.String(80), nullable=False, index=True),
            sa.Column("candidate_version", sa.Integer(), nullable=True),
            sa.Column("active_version", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(30), nullable=False, server_default="PENDING", index=True),
            sa.Column("target_type", sa.String(30), nullable=False),
            sa.Column("target_params", sa.JSON(), nullable=False),
            sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("events_evaluated", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("candidate_matches_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("active_matches_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("metrics", sa.JSON(), nullable=False),
            sa.Column("errors", sa.JSON(), nullable=False),
            sa.Column("created_by", sa.String(80), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_replay_jobs_org_rule",
            "replay_jobs",
            ["organization_id", "rule_id", "created_at"],
        )

    # 4. Create replay_matches table
    if "replay_matches" not in tables:
        op.create_table(
            "replay_matches",
            sa.Column("id", sa.String(80), primary_key=True),
            sa.Column("organization_id", sa.String(80), nullable=False, index=True),
            sa.Column("job_id", sa.String(80), sa.ForeignKey("replay_jobs.id", ondelete="CASCADE"), nullable=False, index=True),
            sa.Column("event_id", sa.String(80), nullable=False, index=True),
            sa.Column("rule_id", sa.String(80), nullable=False),
            sa.Column("rule_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("matched_candidate", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("matched_active", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("explanation", sa.JSON(), nullable=False),
            sa.Column("event_snapshot", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_replay_matches_job_event",
            "replay_matches",
            ["job_id", "event_id"],
        )


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
