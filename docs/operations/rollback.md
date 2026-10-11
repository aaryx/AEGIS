# AEGIS Production Rollback Procedure

## 1. Principles of Safe Rollback

1. **Reverting application code does not revert database schema migrations**.
2. **Never roll back backward-incompatible migrations without an offline restore drill**.
3. **Audit chain continuity must remain verifiable before and after rollback**.

---

## 2. Step-by-Step Application Rollback

### Step 1: Drain Ingestion & Stop Background Workers
```bash
# Gracefully stop workers to complete in-flight batches
docker compose stop worker retention notifications
```

### Step 2: Roll Back Application Container Images
Deploy the previous stable image tag:
```bash
# Update compose.yaml or image tag reference to previous release
docker compose up -d --no-deps api web
```

### Step 3: Database Migration Rollback (If Applicable)
If the release introduced a schema revision that needs to be reversed:

```bash
# Inspect current migration revision
docker compose exec api alembic current

# Downgrade by 1 revision
docker compose exec api alembic downgrade -1
```

> [!CAUTION]
> If a migration dropped a column or performed destructive transformation, downgrade will not restore destroyed data. Restore from the pre-deployment PostgreSQL backup dump instead.

### Step 4: Restart Workers & Verify Health
```bash
docker compose start worker retention notifications
docker compose ps

# Verify API and Worker health
curl -s http://localhost:8000/api/v1/system/readiness
aegis audit verify
```
