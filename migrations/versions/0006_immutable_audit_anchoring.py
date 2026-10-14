"""External immutable audit checkpoint anchoring metadata.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    checkpoint_columns = {col["name"] for col in insp.get_columns("audit_checkpoints")}

    if "anchor_status" not in checkpoint_columns:
        op.add_column(
            "audit_checkpoints",
            sa.Column("anchor_status", sa.String(30), nullable=False, server_default="LOCAL"),
        )
    if "anchor_uri" not in checkpoint_columns:
        op.add_column("audit_checkpoints", sa.Column("anchor_uri", sa.String(500), nullable=True))
    if "anchor_version_id" not in checkpoint_columns:
        op.add_column(
            "audit_checkpoints", sa.Column("anchor_version_id", sa.String(100), nullable=True)
        )
    if "anchored_at" not in checkpoint_columns:
        op.add_column(
            "audit_checkpoints", sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=True)
        )
    if "anchor_error" not in checkpoint_columns:
        op.add_column("audit_checkpoints", sa.Column("anchor_error", sa.String(500), nullable=True))


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
