# AEGIS Monitoring, Metrics & Observability Runbook

## 1. Health Endpoints & Probes

AEGIS exposes standardized Kubernetes and Docker readiness/liveness endpoints:

| Endpoint | Purpose | Success Code | Failure Condition |
|---|---|---|---|
| `GET /api/v1/system/liveness` | Process liveness | `200 OK` | Process deadlock or crash |
| `GET /api/v1/system/readiness` | Ingress readiness probe | `200 OK` | `503 Service Unavailable` if PostgreSQL, OpenSearch, or Redis is unhealthy |
| `GET /api/v1/system/health` | Comprehensive component health check | `200 OK` | Returns JSON status of DB, Search, Redis, AI, and Threat Intelligence |
| `GET /api/v1/system/metrics` | Prometheus metrics scrape | `200 OK` | Requires `system.manage` privilege or scrape bearer token |

---

## 2. Core Prometheus Metrics

All metrics follow standard OpenTelemetry and Prometheus naming conventions without high-cardinality label explosion:

### Ingestion & Queue Metrics
- `aegis_events_ingested_total` (Counter): Total security events durably received.
- `aegis_events_processed_total` (Counter): Total events evaluated through rule detection.
- `aegis_events_failed_total` (Counter): Events routed to dead-letter queue.
- `aegis_queue_depth` (Gauge): Current backlog (`PENDING` + `RETRY` events).

### Performance & Latency Histograms
- `aegis_api_latency_seconds` (Histogram): Request-to-response duration across API routes.
- `aegis_search_latency_seconds` (Histogram): OpenSearch and local query execution duration.

---

## 3. Recommended Prometheus Alerting Rules

```yaml
groups:
  - name: aegis_siem_alerts
    rules:
      - alert: AegisQueueBacklogHigh
        expr: aegis_queue_depth > 10000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "AEGIS ingestion queue backlog is elevated (>10k events)"
          description: "Queue depth has remained above 10,000 for over 5 minutes. Consider scaling worker replicas."

      - alert: AegisDeadLetterRateHigh
        expr: rate(aegis_events_failed_total[5m]) > 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "AEGIS poison events detected in worker queue"
          description: "Workers are failing to process events at a rate >5/sec. Check logs for schema errors."

      - alert: AegisDatabaseReadinessFailed
        expr: probe_success{instance="http://api:8000/api/v1/system/readiness"} == 0
        for: 1m
        labels:
          severity: page
        annotations:
          summary: "AEGIS API reporting unready status"
          description: "Readiness probe failed. Verify PostgreSQL and OpenSearch cluster health."

      - alert: AegisWorkerHeartbeatMissing
        expr: time() - aegis_worker_last_seen_seconds > 120
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Detection worker heartbeat missing"
          description: "Worker has not updated heartbeat in over 2 minutes."
```
