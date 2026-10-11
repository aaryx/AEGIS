# AEGIS Data Lifecycle & Retention Runbook

## 1. Overview & Policy Definition

The AEGIS data lifecycle subsystem (`aegis/retention.py`) automates time-based data pruning across security telemetry, transient workflow states, and OpenSearch search indexes while strictly preserving evidence under legal custody.

### Retention Defaults

| Data Domain | Default Retention Window | Enforcement Mechanism |
|---|---|---|
| **Event Telemetry** (`events_metadata`) | 90 days (`RETENTION_DAYS`) | Scheduled batch cleanup via `aegis-retention` |
| **Search Outbox Jobs** (`search_jobs`) | Pruned synchronously with event deletion | Cascade deletion in `aegis/retention.py` |
| **Derived Entity Relationships** (`entity_relationships`) | Pruned when parent event is pruned | Bounded batch cascade in `aegis/retention.py` |
| **IOC Matches** (`ioc_matches`) | Pruned when parent event is pruned | Cascade deletion in `aegis/retention.py` |
| **OpenSearch Daily Indices** (`aegis-events-YYYY.MM.DD`) | 90 days (`RETENTION_DAYS`) | Index lifecycle deletion via `prune_opensearch_indices` |
| **Transient Window State** (`window_state`) | Expiry timestamp (`WindowState.expires`) | Pruned on expiry by retention worker |
| **Session Tokens & Password Resets** | Expiry timestamp (`SessionToken.expires`) | Pruned on expiry by retention worker |
| **Tamper-Evident Audit Logs** (`audit_logs`) | Permanent / Long-Term Archive Policy | **IMMUTABLE**: Never deleted by retention worker |

---

## 2. Legal Hold & Evidence Custody

Records subject to legal hold or active incident investigation are **strictly exempt** from automated deletion.

An event is protected from deletion if:
1. It is attached as evidence to an existing case (`CaseEvidence.resource_type == "event"`).
2. It is attached to an open alert (`AlertEvent.alert_id` where `Alert.status` is `NEW` or `INVESTIGATING`).

When the retention worker evaluates candidate events older than `RETENTION_DAYS`, it queries `get_legal_holds()` and excludes all held records from the deletion batch.

---

## 3. Database Least Privilege & Maintenance Identity

The ordinary runtime user `aegis_runtime` has `DELETE` permissions explicitly revoked on `events_metadata` and `audit_logs` to prevent accidental or malicious destruction of telemetry.

A dedicated maintenance role `aegis_maintenance` is used by the retention worker:

```sql
-- Provisioned by scripts/initialize.py
CREATE ROLE aegis_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
ALTER ROLE aegis_maintenance PASSWORD '<POSTGRES_MAINTENANCE_PASSWORD>';
GRANT USAGE ON SCHEMA public TO aegis_maintenance;
GRANT SELECT, DELETE ON ALL TABLES IN SCHEMA public TO aegis_maintenance;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegis_maintenance;

-- Even maintenance identity CANNOT delete or update audit logs!
REVOKE UPDATE, DELETE ON audit_logs FROM aegis_maintenance;
```

---

## 4. Operational Commands & Procedures

### 4.1 Running Dry-Run Inspection

To preview the number of eligible records, records under legal hold, and estimated deletion impact without modifying data:

```bash
# Via CLI
aegis maintenance retention --dry-run

# Via REST API (requires system.manage role)
curl -X POST "http://localhost:8000/api/v1/system/retention?dry_run=true" \
  -H "Authorization: Bearer <SUPER_ADMIN_TOKEN>"
```

### 4.2 Executing Immediate Retention Cleanup

```bash
# Via CLI
aegis maintenance retention

# Via REST API
curl -X POST "http://localhost:8000/api/v1/system/retention?dry_run=false" \
  -H "Authorization: Bearer <SUPER_ADMIN_TOKEN>"
```

### 4.3 Verifying Retention Audit Records

Every non-dry-run retention cycle that prunes data generates an auditable record in `audit_logs` with action `system.retention`:

```bash
# Verify audit chain integrity after retention execution
aegis audit verify
```

Expected output:
```json
{
  "valid": true
}
```
