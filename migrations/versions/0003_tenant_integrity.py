"""Enforce tenant consistency for evidence links and tenant-owned foreign keys."""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("""
        CREATE FUNCTION aegis_check_tenant_fk() RETURNS trigger AS $$
        DECLARE target_tenant text; reference text;
        BEGIN
          reference := to_jsonb(NEW)->>TG_ARGV[0];
          IF reference IS NULL THEN RETURN NEW; END IF;
          EXECUTE format('SELECT organization_id FROM %I WHERE id=$1', TG_ARGV[1])
            INTO target_tenant USING reference;
          IF target_tenant IS DISTINCT FROM NEW.organization_id THEN
            RAISE EXCEPTION 'Cross-tenant reference rejected' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END; $$ LANGUAGE plpgsql;
        CREATE FUNCTION aegis_check_tenant_link() RETURNS trigger AS $$
        DECLARE left_tenant text; right_tenant text;
        BEGIN
          EXECUTE format('SELECT organization_id FROM %I WHERE id=$1', TG_ARGV[1])
            INTO left_tenant USING to_jsonb(NEW)->>TG_ARGV[0];
          EXECUTE format('SELECT organization_id FROM %I WHERE id=$1', TG_ARGV[3])
            INTO right_tenant USING to_jsonb(NEW)->>TG_ARGV[2];
          IF left_tenant IS NULL OR left_tenant IS DISTINCT FROM right_tenant THEN
            RAISE EXCEPTION 'Cross-tenant evidence link rejected' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END; $$ LANGUAGE plpgsql;
    """)
    references = {
        "sessions": {"user_id": "users"},
        "api_keys": {"user_id": "users"},
        "password_resets": {"user_id": "users"},
        "alerts": {"assignee": "users"},
        "incidents": {"assignee": "users"},
        "cases": {"assignee": "users"},
        "case_notes": {"author": "users"},
        "case_evidence": {"case_id": "cases", "attached_by": "users"},
        "rule_versions": {"rule_id": "detection_rules", "author": "users"},
        "saved_searches": {"author": "users"},
        "reports": {"incident_id": "incidents", "generated_by": "users"},
        "entity_relationships": {
            "source_id": "entities",
            "target_id": "entities",
            "event_id": "events_metadata",
        },
        "playbook_executions": {"requested_by": "users", "approved_by": "users"},
        "search_jobs": {"event_id": "events_metadata"},
        "notification_deliveries": {"notification_id": "notifications", "integration_id": "integrations"},
    }
    for table, fields in references.items():
        for field, target in fields.items():
            op.execute(
                f"CREATE TRIGGER tenant_{table}_{field} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION aegis_check_tenant_fk('{field}', '{target}')"
            )
    for table, left, left_table, right, right_table in [
        ("alert_events", "alert_id", "alerts", "event_id", "events_metadata"),
        ("incident_alerts", "incident_id", "incidents", "alert_id", "alerts"),
        ("ioc_matches", "ioc_id", "iocs", "event_id", "events_metadata"),
    ]:
        op.execute(
            f"CREATE TRIGGER tenant_{table} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION aegis_check_tenant_link('{left}', '{left_table}', '{right}', '{right_table}')"
        )


def downgrade():
    raise RuntimeError("Tenant integrity controls require an explicit reviewed forward migration")
