"""Endpoint cryptographic identity, enrollment tokens, audit chain decoupling, and MFA hardening.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = set(insp.get_table_names())

    # 1. Create agents table if not exists
    if "agents" not in existing_tables:
        op.create_table(
            "agents",
            sa.Column("id", sa.String(80), primary_key=True),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False, index=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("name", sa.String(200), nullable=False, index=True),
            sa.Column("public_key", sa.String(128), nullable=False),
            sa.Column("status", sa.String(30), nullable=False, server_default="ENROLLED"),
            sa.Column("os", sa.String(50), nullable=False, server_default="unknown"),
            sa.Column("os_release", sa.String(50), nullable=False, server_default=""),
            sa.Column("ip", sa.String(50), nullable=False, server_default="127.0.0.1"),
            sa.Column("version", sa.String(30), nullable=False, server_default="1.0.0"),
            sa.Column("capabilities", sa.JSON(), nullable=False),
            sa.Column("isolation_status", sa.String(30), nullable=False, server_default="NONE"),
            sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=False),
            sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("auth_token_hash", sa.String(64), nullable=True, unique=True, index=True),
            sa.UniqueConstraint("organization_id", "name", name="uq_agent_org_name"),
        )

    # 2. Create agent_enrollment_tokens table if not exists
    if "agent_enrollment_tokens" not in existing_tables:
        op.create_table(
            "agent_enrollment_tokens",
            sa.Column("id", sa.String(80), primary_key=True),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False, index=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True, index=True),
            sa.Column("expires_at", sa.Float(), nullable=False, index=True),
            sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("used_by_agent_id", sa.String(80), nullable=True),
        )

    # 3. Create audit_heads table for lock contention decoupling if not exists
    if "audit_heads" not in existing_tables:
        op.create_table(
            "audit_heads",
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), primary_key=True),
            sa.Column("audit_head", sa.String(64), nullable=False, server_default="0" * 64),
            sa.Column("sequence_number", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    # 4. Create audit_checkpoints table if not exists
    if "audit_checkpoints" not in existing_tables:
        op.create_table(
            "audit_checkpoints",
            sa.Column("id", sa.String(80), primary_key=True),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False, index=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("sequence_number", sa.Integer(), nullable=False, index=True),
            sa.Column("head_entry_hash", sa.String(64), nullable=False),
            sa.Column("checkpoint_hash", sa.String(64), nullable=False),
            sa.Column("signature", sa.String(256), nullable=False),
            sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
        )

    # 5. Add columns to users table for MFA if not already present
    user_columns = {col["name"] for col in insp.get_columns("users")}
    if "mfa_enabled" not in user_columns:
        op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    if "mfa_secret" not in user_columns:
        op.add_column("users", sa.Column("mfa_secret", sa.String(64), nullable=True))

    # 6. Add key_version to audit_logs if not already present
    audit_columns = {col["name"] for col in insp.get_columns("audit_logs")}
    if "key_version" not in audit_columns:
        op.add_column("audit_logs", sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"))


def downgrade():
    raise RuntimeError("Destructive downgrade is disabled. Restore a verified backup instead.")
