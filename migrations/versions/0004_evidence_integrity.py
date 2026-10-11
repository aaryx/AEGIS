"""Protect original evidence and identity from in-place edits at the database boundary."""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("""
        CREATE FUNCTION aegis_original_evidence_immutable() RETURNS trigger AS $$
        BEGIN
          IF NEW.id IS DISTINCT FROM OLD.id
             OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
             OR NEW.timestamp IS DISTINCT FROM OLD.timestamp
             OR NEW.evidence_hash IS DISTINCT FROM OLD.evidence_hash
             OR NEW.source IS DISTINCT FROM OLD.source
             OR (NEW.payload::jsonb->'raw_event') IS DISTINCT FROM (OLD.payload::jsonb->'raw_event') THEN
            RAISE EXCEPTION 'Original evidence is immutable' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER evidence_no_mutation BEFORE UPDATE ON events_metadata
          FOR EACH ROW EXECUTE FUNCTION aegis_original_evidence_immutable();
    """)


def downgrade():
    raise RuntimeError("Evidence integrity controls require an explicit reviewed forward migration")
