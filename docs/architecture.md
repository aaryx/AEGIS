# Architecture and initial audit

**Current architecture amendment:** see [hardening.md](hardening.md). PostgreSQL
now owns atomic correlation state and search/notification outboxes. Redis serves
shared rate limits. The initial architecture rationale below is retained as history.

The initial repository audit on 2026-09-28 found an empty directory: no source,
dependencies, migrations, tests, infrastructure, or existing security controls.
There was no reusable implementation and no user work to replace.

```
Next.js / Typer -> FastAPI /api/v1 -> domain services -> PostgreSQL
                                      |                 durable inbox
                                      |                      |
                                      +-- investigation <-- worker
                                                             |
                                           parser -> enrichment -> OpenSearch
                                                             |
                                              Redis windows -> detections
                                                             |
                                          evidence -> alerts -> incidents
```

PostgreSQL owns users, tenant boundaries, immutable source evidence, ingestion
status, rules and their history, alerts, incidents, cases, entity relationships,
IOCs, approvals, reports and audit chains. OpenSearch is the time-partitioned
search projection, not the only copy of evidence. Redis holds bounded temporal
detection state and shared rate counters. A durable database inbox is the job
queue; workers claim rows using `FOR UPDATE SKIP LOCKED`. Delivery is at least
once with deterministic event IDs, idempotent indexing and unique alert keys.

The local development adapter uses SQLite for evidence search and window state.
It is for a single worker and bounded data volumes. Production configuration
requires PostgreSQL, Redis and OpenSearch. Local and deployed modes run the
same parser, rules, correlation, risk, authorization and investigation logic.

Tenant-scoped API queries are mandatory, including indirect evidence lookups.
Worker processing is serialized per tenant to maintain ordered correlation;
independent tenants can be processed concurrently. Horizontal scaling of a
single large tenant requires partitioning by correlation entity.

Rules are declarative validated data, never executable Python or unrestricted
regular expressions. AI is advisory and evidence-minimized. Response requests
are persisted, authorization checked and high-impact operations require a
different approving operator. Local containment writes a local policy record;
it never claims to have changed a real host or account.

Verification covers parser boundaries, positive/negative detection examples,
the complete synthetic attack chain, RBAC, tenant isolation, CSRF, idempotency,
audit integrity, response authorization and frontend flows. Infrastructure
tests require actual services and are reported separately from local tests.
