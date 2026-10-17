"""Persist explainable storyline membership alongside existing incidents."""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = set(insp.get_table_names())
    for name, columns in (
        (
            "storylines",
            [
                sa.Column(
                    "incident_id", sa.String(80), sa.ForeignKey("incidents.id"), nullable=False, unique=True
                ),
                sa.Column(
                    "anchor_alert_id", sa.String(80), sa.ForeignKey("alerts.id"), nullable=False, unique=True
                ),
                sa.Column("window_seconds", sa.Integer(), nullable=False),
                sa.Column("summary", sa.JSON(), nullable=False),
            ],
        ),
        (
            "storyline_members",
            [
                sa.Column(
                    "storyline_id", sa.String(80), sa.ForeignKey("storylines.id"), nullable=False, index=True
                ),
                sa.Column("alert_id", sa.String(80), sa.ForeignKey("alerts.id"), nullable=False, unique=True),
                sa.Column("reasons", sa.JSON(), nullable=False),
            ],
        ),
    ):
        if name not in existing_tables:
            op.create_table(
                name,
                sa.Column("id", sa.String(80), primary_key=True),
                sa.Column(
                    "organization_id",
                    sa.String(36),
                    sa.ForeignKey("organizations.id"),
                    nullable=False,
                    index=True,
                ),
                sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
                *columns,
            )


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
