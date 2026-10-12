# AEGIS Troubleshooting & Remediation Guide

## 1. Diagnostic Decision Tree

```
Telemetry Ingestion Issue?
├── HTTP 503 "Tenant ingestion/search backlog is full"
│   └── Cause: Total queue depth exceeds settings.queue_capacity (100k).
│   └── Remedy: Scale worker replicas; check for dead-lettered poison events blocking outbox.
├── HTTP 409 "Source sequence was reused with different evidence"
│   └── Cause: Event ID was re-submitted with differing payload evidence hash.
│   └── Remedy: Verify collector sequence generator. Event IDs must be globally unique per evidence payload.
└── HTTP 429 "Rate limit exceeded"
    └── Cause: Client exceeded per-minute endpoint throttle.
    └── Remedy: Implement client-side exponential backoff; tune rate_limit in api.py if legitimate burst.
```

---

## 2. Common Operational Symptoms & Fixes

### 2.1 Worker iteration failures & poison events
- **Symptom**: `logger.error("event_processing_failed")` appears in `docker compose logs worker`.
- **Diagnostic**:
  ```bash
  # Check dead-lettered events
  curl -X GET "http://localhost:8000/api/v1/system/search-jobs?limit=50" \
    -H "Authorization: Bearer <SUPER_ADMIN_TOKEN>"
  ```
- **Resolution**:
  Dead-lettered events (`state == 'DEAD'`) are isolated so they do not block healthy sibling events. After deploying parser or rule fixes, retry dead-lettered events via:
  ```bash
  curl -X POST "http://localhost:8000/api/v1/system/dead-letter/<EVENT_ID>/retry" \
    -H "Authorization: Bearer <SUPER_ADMIN_TOKEN>"
  ```

### 2.2 Audit chain verification failure
- **Symptom**: `aegis audit verify` returns `{"valid": false}`.
- **Diagnostic**:
  A verification failure indicates that an audit row was deleted, reordered, truncated, or tampered with directly in PostgreSQL without the protected HMAC secret key.
- **Resolution**:
  1. Inspect the last verified `entry_hash` against `AuditLog.previous_hash`.
  2. Identify the tampered row ID or gap in the sequential timeline.
  3. Raise a P1 Security Incident for database perimeter breach investigation.

### 2.3 OpenSearch yellow / red cluster health
- **Symptom**: `/system/readiness` returns 503; OpenSearch logs report unassigned shards.
- **Diagnostic**:
  ```bash
  curl -s --user "admin:<ADMIN_PASSWORD>" "http://localhost:9200/_cluster/health"
  ```
- **Resolution**:
  In single-node development deployments, verify `opensearch_replicas` is set to `0`. If set to `>=1` on a 1-node cluster, replica shards cannot be assigned, resulting in yellow cluster status.
