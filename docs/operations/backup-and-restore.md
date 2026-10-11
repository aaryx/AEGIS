# AEGIS Backup, Restore & Disaster Recovery Runbook

## 1. Objectives & Recovery Targets

| Metric | Target | Notes |
|---|---|---|
| **Recovery Point Objective (RPO)** | < 15 minutes | Bounded by PostgreSQL WAL streaming or snapshot frequency |
| **Recovery Time Objective (RTO)** | < 30 minutes | Clean rebuild from database dump and OpenSearch outbox re-projection |

---

## 2. PostgreSQL Backup & Restore Procedure

### 2.1 Generating a Consistent Database Backup

Execute a custom-format compressed backup:

```bash
# Inside docker compose environment
docker compose exec postgres pg_dump -U aegis -d aegis -Fc -f /tmp/aegis-backup.dump
docker compose cp postgres:/tmp/aegis-backup.dump ./aegis-backup.dump

# Direct PostgreSQL host
pg_dump -h localhost -U aegis -d aegis -Fc -f aegis-backup.dump
```

Store the resulting dump file in encrypted, off-site secondary storage.

### 2.2 Restoring from Backup

> [!WARNING]
> Always restore into an **isolated database instance** first to verify audit-chain continuity and evidence hash matching before switching production traffic.

```bash
# 1. Create target restore database
createdb -h localhost -U aegis aegis_restored

# 2. Restore schema and data
pg_restore -h localhost -U aegis -d aegis_restored --clean --if-exists aegis-backup.dump

# 3. Verify audit chain validity on restored database
DATABASE_URL="postgresql+psycopg://aegis:<PASSWORD>@localhost:5432/aegis_restored" \
python -c "
from aegis.config import get_settings
from aegis.db import database, Organization, select
from aegis.security import verify_audit
settings = get_settings()
_, sessions = database(settings.database_url)
with sessions() as db:
    org_id = db.scalar(select(Organization.id).limit(1))
    valid = verify_audit(db, settings, org_id)
    assert valid, 'Audit chain verification failed on restored database!'
    print('Restored database verified successfully! Audit chain is valid.')
"
```

---

## 3. OpenSearch Snapshot & Outbox Re-projection

OpenSearch serves as an indexed projection of primary telemetry stored durably in PostgreSQL `events_metadata`.

### 3.1 Snapshots via OpenSearch Snapshot Repository

```bash
# 1. Register S3 or shared filesystem snapshot repository
curl -X PUT "http://localhost:9200/_snapshot/aegis_backup" \
  -H "Content-Type: application/json" \
  -u "admin:<OPENSEARCH_ADMIN_PASSWORD>" \
  -d '{
    "type": "fs",
    "settings": {
      "location": "/usr/share/opensearch/snapshots"
    }
  }'

# 2. Create daily snapshot
curl -X PUT "http://localhost:9200/_snapshot/aegis_backup/snapshot_$(date +%Y%m%d)?wait_for_completion=true" \
  -u "admin:<OPENSEARCH_ADMIN_PASSWORD>"
```

### 3.2 Recovery via Outbox Re-projection

If OpenSearch indexes are lost or corrupted, primary event records in `events_metadata` remain intact.
To rebuild OpenSearch indices from the authoritative database:

```bash
# Re-queue indexed events into search_jobs outbox
python -c "
from aegis.config import get_settings
from aegis.db import database, EventRecord, SearchJob, select
settings = get_settings()
_, sessions = database(settings.database_url)
with sessions.begin() as db:
    events = list(db.scalars(select(EventRecord).where(EventRecord.state == 'PROCESSED')))
    for ev in events:
        db.add(SearchJob(organization_id=ev.organization_id, event_id=ev.id, state='PENDING'))
    print(f'Queued {len(events)} events for search re-projection')
"
```
The background worker (`aegis-worker`) will automatically re-index the events into OpenSearch without duplicating detections or alerts.

---

## 4. Automated Recovery Drill

AEGIS includes an automated end-to-end backup and recovery verification drill:

```bash
python scripts/recovery_drill.py
```

The script exercises:
1. Live event ingestion and detection execution.
2. Generating a PostgreSQL archive dump.
3. Restoring into a temporary isolated database.
4. Verifying evidence hashes, rule matches, and cryptographic audit-chain integrity.
