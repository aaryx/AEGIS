# Production hardening work

## What changed

### Atomic detection and independent search

Correlation window updates, alert/evidence links, entity updates, incidents and
search-job creation now commit in one PostgreSQL transaction. Redis remains the
shared rate-limiting dependency; it is no longer a second authoritative detection
state store. This eliminates state surviving a rolled-back detection transaction.

OpenSearch indexing is an idempotent durable outbox with its own retry/dead-letter
state. A search outage does not block detection. The worker isolates failing
events with savepoints so one poison record does not consume sibling retries.
Search backlog contributes to per-tenant backpressure, but duplicate acceptance
still works when the backlog is full. Operators can inspect/retry search jobs:

```
GET /api/v1/system/search-jobs
POST /api/v1/system/search-jobs/{event_id}/retry
```

Sequences now anchor on the current terminal event, allowing subsequent attack
chains in the same window. All timestamps normalize to UTC before index naming.
Future timestamps over five minutes are rejected. Bounded late arrivals preserve
newer state rather than deleting it; events outside the lateness/capacity budget
fail visibly into retry/dead letters. There is no automatic historical backfill.

### Authorization and database integrity

Composite investigations require all the data permissions they expose. Scoped
keys cannot read incident/entity/IOC data through an events-only permission.
Audit activity is hidden from non-audit readers. Queue metrics are tenant-scoped.
User administration/password recovery require human sessions; password reset
invalidates other reset tokens, sessions and API keys. Session refresh consumes
the old session only once. Approval execution rechecks the approver's current
rights and expiration. Invalid action/target pairings fail before approval.

PostgreSQL migrations reject cross-tenant evidence links and tenant-owned foreign
key references. Original event evidence, hashes and identity are immutable even
when processing/enrichment metadata changes. The deployed API/workers use
`aegis_runtime`, a non-superuser without schema ownership or evidence deletion;
migrations/bootstrap retain a separate owner connection. New deployments generate
a distinct POSTGRES_RUNTIME_PASSWORD. Existing .env files temporarily fall back to
POSTGRES_PASSWORD; set a separate runtime password and rerun initialization to rotate.

### Collector

```
aegis collectors run /var/log/auth.log --source-type linux --spool /var/lib/aegis/collector.db --name auth-agent
aegis collectors spool /var/lib/aegis/collector.db
```

The spool parent must exist. SQLite FULL synchronization transactionally stores
source offsets and pending records. Stable generation/offset identities survive
process restarts, file replacement and detected truncation. Partial lines are not
acknowledged. Backpressure does not advance checkpoints. Invalid API records are
quarantined while valid siblings continue. HTTP failures retry persisted payloads.
Remote connections require HTTPS. Restrict spool directory ACLs: it holds evidence.

This is a real newline-delimited file tailer, not a native Windows Event Log API
or cloud subscription agent. A rotation that discards unread bytes before the
collector observes them cannot be recovered; configure source retention accordingly.

### Integration delivery

Settings now exposes configured integrations, feed synchronization and delivery
status. CLI: `aegis integrations list|save|sync|deliveries`.

Supported providers: generic signed webhook, Slack incoming webhook, Teams adaptive
card webhook and JSON IOC feed. Integration code lives in `aegis/integrations.py`.
Configure exact DNS hosts through INTEGRATION_ALLOWED_HOSTS, for example
`["hooks.slack.com","intel.example.org"]`. Configure signing/feed secrets as
environment variables whose names begin AEGIS_INTEGRATION_. Compose forwards
AEGIS_INTEGRATION_SOC_WEBHOOK and AEGIS_INTEGRATION_IOC_FEED; additional names require
explicit deployment forwarding. API responses redact endpoint path/query.

Delivery uses a separate worker and durable records, timeouts, bounded replies,
backoff, explicit failure status and stable idempotency headers. Generic webhook
signatures are HMAC-SHA256 over `<unix-seconds>.<exact-body>`; receivers should
verify signatures, a short timestamp tolerance and deduplicate Idempotency-Key.
Vendor endpoints may not deduplicate, so retries can deliver duplicate messages.
TLS hostname verification is retained while connections pin resolved IPs.
Redirects, metadata/link-local, multicast and unspecified targets are rejected.
An operator allowlist may intentionally permit private integration hosts.

Feeds accept up to 5,000 validated IOCInput objects; the entire document validates
before insertion. Existing analyst IOCs are preserved. Synchronization is explicit,
not scheduled. Tests exercise real local HTTP I/O; live Slack/Teams accounts were
not available for vendor acceptance.

### Operational proof

`scripts/failure_drill.py` stops only the local OpenSearch service, submits a
synthetic event, verifies committed detection state/evidence, restarts search and
waits for projection recovery. It restarts search in a finally block.

`scripts/recovery_drill.py` takes pg_dump, restores into a uniquely named temporary
database, verifies every original evidence hash and audit chain, then drops only
that temporary database. Backups remain in ignored local-data for operator handling.
`scripts/benchmark_pipeline.py --events 1000` measures acceptance and search visibility.

## Measured results

- Backend: 118 passing tests plus one opt-in connectivity test skipped.
- All 34 bundled detections pass independently authored positive/near-miss samples;
  sample generation no longer reads rule thresholds/predicates to derive expected events.
- Frontend: 7 passing tests; deployed Playwright investigation/report flow passed,
  including refresh/deep-link restoration and Settings integration controls.
- Distributed integration: 13 passing checks including tenant-link rejection,
  immutable evidence, non-superuser runtime and transactional-state rollback.
- Real OpenSearch outage/recovery drill: passed.
- Isolated acceptance run: exactly 16 new evidence events, 12 failed-authentication
  search results, associated incident/report and valid audit chain. Each run uses
  a unique host/source identity to prevent old incidents from satisfying acceptance.
- Restore drill: 1,065 event hashes and audit chains verified; backup 1.97 seconds,
  total backup/restore/verification 14.90 seconds, 255,304-byte archive.
- 1,000-event local benchmark: 26.25 seconds through search visibility, 38.10 events/s;
  median batch acceptance latency 83.7 ms. This run overlapped other verification;
  it is not a sustained throughput/SLA claim.
- API image moved from Debian 12 to patched Debian 13 with an isolated application
  environment: high/critical findings reduced from 11 to 2 high, zero critical.
  Remaining scanner findings: CVE-2026-82560 (Perl), CVE-2026-85091 (zlib), no fix
  reported. They remain open findings, not suppressed passes.

## Remaining gates before a defensible industry 9/10

Independent penetration testing; remediation/risk treatment of remaining image
findings; SSO/MFA; real workload sustained load/soak tests; production TLS and HA;
full role/endpoint security coverage; live vendor acceptance; historical replay
and event-time watermarks; automatic evidence-aware retention/legal holds;
native source integrations; real EDR/IAM response providers; and a representative
SOC detection precision/recall evaluation. These cannot be replaced with a
self-assigned rating or the number of passing tests.
