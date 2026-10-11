# AEGIS SIEM/SOAR — Production Hardening & Architecture Remediation Assessment

**Assessment Date**: 2026-10-11  
**Lead Roles**: Principal Security Engineer, Staff Backend Engineer, SIEM Architect, SRE, DevSecOps  
**Repository Baseline Commit**: `ee9152f` (main branch)  
**Verification Environment**: Python 3.14.3, FastAPI 0.135.1, SQLAlchemy 2.0.48, Next.js 16.3.6 Turbopack, Vitest 4.1.11, Playwright 1.58.2  

---

## 1. Executive Summary & Verification Matrix

An exhaustive architectural audit and empirical verification of the AEGIS SIEM/SOAR platform was performed. All 10 major architectural areas were inspected directly against executable source code.

| ID | Subsystem | Verified Finding | Severity | Status | Remediated In |
|---|---|---|---|---|---|
| **F-01** | Ingestion & Worker Concurrency | Tenant-wide `SELECT ... FOR UPDATE` on `Organization` during batch ingest (`aegis/pipeline.py:43`) and worker claiming (`aegis/worker.py:74-86`) serializes all ingestion and worker execution per tenant. | **Critical (P0)** | Confirmed | Stage B |
| **F-02** | Retention & Data Lifecycle | `retention_days` configuration was unenforced; no automated cleanup engine existed; runtime database user has `DELETE` revoked on `events_metadata`, preventing cleanup without dedicated maintenance identity. | **Critical (P0)** | Confirmed | Stage C |
| **F-03** | Authentication & Anti-DoS | Dynamic `PASSWORDS.hash(secrets.token_urlsafe(20))` executed on every invalid username login in `aegis/api.py:458`, creating a severe Argon2id CPU-exhaustion DoS vulnerability. | **Critical (P0)** | Confirmed | Stage B |
| **F-04** | SOAR & Two-Person Approval | SOAR approval lacked strict revalidation of parameters, cryptographic command signing for remote agents, and receipt validation accepted unverified hashes. | **High (P0)** | Confirmed | Stage B |
| **F-05** | Evidence & Audit Integrity | Audit hash chain maintained HMAC-SHA256, but lacked archival export, key rotation versioning, and tamper alert hooks. Original event evidence was hashed but required canonical verification guarantees. | **High (P0)** | Confirmed | Stage B |
| **F-06** | Detection State & Sliding Windows | JSON-serialized `WindowState` loaded and rewritten per event without atomic partial updates or memory bounding; lacked explicit degraded state during Redis/DB saturation. | **Medium (P1)** | Confirmed | Stage D |
| **F-07** | Entity Relationship Combinatorics | Unbounded $N(N-1)/2$ pairwise combinations generated for every event in `aegis/pipeline.py:173`, triggering exponential database growth on multi-entity telemetry. | **High (P1)** | Confirmed | Stage D |
| **F-08** | Native Ingestion Protocols | Ingestion was restricted to HTTP REST and a rudimentary unbuffered UDP CLI loop; lacked RFC 5424/RFC 3164 Syslog server with TCP framing and TLS support. | **Medium (P1)** | Confirmed | Stage D |
| **F-09** | OpenSearch Query Resilience | Hardcoded `number_of_replicas: 0` in index template; unconstrained `*wildcard*` queries on `contains` filters caused term dictionary full-scans. | **Medium (P1)** | Confirmed | Stage D |
| **F-10** | SSRF, CSRF, CSV & EDR Boundary | Webhook SSRF lacked loopback / private IP filtering in non-test profiles; CSV exports lacked formula injection sanitization; endpoint agent lacked asymmetric command signatures. | **High (P1)** | Confirmed | Stage B & E |

---

## 2. Deep-Dive Findings & Reproduction Evidence

### F-01: Tenant Serialization in Ingestion and Detection Workers (P0)
- **Affected Files**: `aegis/pipeline.py` (L43), `aegis/worker.py` (L74-86)
- **Reproduction**:
  - In `aegis/pipeline.py`:
    ```python
    db.scalar(select(Organization).where(Organization.id == organization_id).with_for_update())
    ```
    Every incoming HTTP ingestion batch acquired an exclusive row lock on the tenant's `Organization` record for the entire duration of parsing, normalization, and deduplication.
  - In `aegis/worker.py`:
    ```python
    org = db.scalar(
        select(Organization)
        .where(...)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    ```
    Workers locked the entire tenant row. Consequently, only a single worker could process batches for a given organization at any time, rendering horizontal worker scaling ineffective for single-tenant or high-volume enterprise deployments.
- **Remediation Strategy**:
  1. Remove `with_for_update()` on `Organization` in `aegis/pipeline.py:ingest()`.
  2. Implement direct `EventRecord` row-level claiming with `with_for_update(skip_locked=True)` in `aegis/worker.py:process_once()`.
  3. Ensure multiple workers can process independent event batches concurrently for the same organization while keeping rule state isolated.

---

### F-02: Missing Automated Retention Subsystem & Privilege Separation (P0)
- **Affected Files**: `aegis/config.py` (L36), `scripts/initialize.py` (L46-47), `compose.yaml`
- **Reproduction**:
  - `retention_days: int = Field(90, ge=7)` exists in settings but is never queried for deletion.
  - In `scripts/initialize.py`:
    ```sql
    REVOKE UPDATE, DELETE ON audit_logs FROM aegis_runtime;
    REVOKE DELETE ON events_metadata FROM aegis_runtime;
    ```
    The runtime application user `aegis_runtime` is strictly prohibited from deleting records. Without a distinct maintenance identity, automated retention jobs fail or cannot run.
- **Remediation Strategy**:
  1. Build `aegis/retention.py` providing a resilient, bounded, resumable retention engine.
  2. Support dry-run mode, batch pruning of `events_metadata`, `events`, `search_jobs`, transient `window_state`, and expired sessions.
  3. Enforce legal hold protection (`is_held` on incidents/evidence).
  4. Provide dedicated maintenance credentials and scheduler in `compose.yaml`.

---

### F-03: Argon2id CPU Denial of Service on Invalid Username (P0)
- **Affected Files**: `aegis/api.py` (L458), `aegis/security.py`
- **Reproduction**:
  - In `aegis/api.py`:
    ```python
    valid = (
        check_password(user.password_hash, data.password)
        if user
        else check_password(PASSWORDS.hash(secrets.token_urlsafe(20)), data.password)
    )
    ```
    For invalid usernames, `PASSWORDS.hash()` dynamically computes an Argon2id hash (time_cost=3, memory_cost=65536) followed immediately by `check_password()`.
  - An attacker sending unauthenticated requests with randomized usernames consumes 100% CPU on all uvicorn worker threads.
- **Remediation Strategy**:
  1. Compute a constant `DUMMY_PASSWORD_HASH` at module initialization with identical Argon2id parameters.
  2. In `login()`, verify against `user.password_hash if user else DUMMY_PASSWORD_HASH`.

---

### F-04: Two-Person Approval & Endpoint Agent Trust Boundary (P0)
- **Affected Files**: `aegis/response.py`, `aegis/agent.py`, `aegis/api.py`
- **Reproduction**:
  - In `aegis/api.py:1443`, `agent_receipt` accepted `data.receipt_hash` without cryptographically verifying that the hash matches the canonical hash of the execution result.
  - Commands polled by agents did not enforce expiration timestamps or controller signatures.
- **Remediation Strategy**:
  1. Implement canonical HMAC/SHA-256 receipt validation in `aegis/api.py:agent_receipt`.
  2. Enforce strict parameter immutability between approval and dispatch.
  3. Validate host firewall state directly rather than assuming subprocess exit 0 implies containment.

---

### F-05: Entity Relationship Graph Combinatorics (P1)
- **Affected Files**: `aegis/pipeline.py` (L173-185)
- **Reproduction**:
  - `combinations(entities, 2)` created $N(N-1)/2$ edges for every event, querying the DB for every single edge.
  - A single telemetry event with 20 extracted entities generated 190 edges and 190 database lookups.
- **Remediation Strategy**:
  1. Restrict relationship creation to meaningful semantic bindings: `user -> host`, `process -> host`, `process -> file`, `ip -> host`.
  2. Cap maximum extracted entities per event (`settings.max_entities_per_event = 15`).
  3. Batch insert relationships with set deduplication.

---

### F-06: OpenSearch Search Resilience & Index Lifecycle (P1)
- **Affected Files**: `aegis/storage.py` (L179, L226-228)
- **Reproduction**:
  - `number_of_replicas: 0` is hardcoded in the index template.
  - `contains` queries construct `*value*` wildcards on keyword fields without bounding string length or pattern complexity.
- **Remediation Strategy**:
  1. Make `number_of_replicas` configurable via `settings.opensearch_replicas` (defaulting to 0 in test/dev, 1 in production).
  2. Enforce minimum character length and bound wildcards on `contains` queries.
  3. Validate cluster shard placement and document index lifecycle management (ISM).

---

### F-07: Native Syslog Protocol Ingestion (P1)
- **Affected Files**: `aegis/cli.py`, `aegis/syslog.py` (new)
- **Reproduction**:
  - Only HTTP REST and an unbuffered UDP loop in CLI existed; no TCP framing (RFC 6587 / octet counting / LF) or TLS (RFC 5425) Syslog daemon existed.
- **Remediation Strategy**:
  1. Create `aegis/syslog.py` with RFC 5424 / RFC 3164 parser.
  2. Implement TCP and UDP syslog listener service with batch buffering, rate limiting, and backpressure into `aegis.pipeline.ingest`.

---

### F-08: SSRF, CSRF, CSV Injection & Outbound Security (P1)
- **Affected Files**: `aegis/integrations.py`, `aegis/api.py`
- **Reproduction**:
  - `request_bytes` validated against link-local/multicast but permitted loopback addresses if added to allowlist in non-testing environments.
  - No CSV export endpoint existed with formula injection protection (`=`, `+`, `-`, `@`, `\t`, `\r`).
- **Remediation Strategy**:
  1. Reject loopback and private IPv4/IPv6 addresses in `validate_endpoint` unless explicitly testing.
  2. Add CSV export with strict formula neutralization prefixing (`'`).

---

## 3. Implementation Plan & Staged Milestones

- **Stage A**: Baseline discovery and documentation. (Completed)
- **Stage B**: Critical Correctness & Security (P0) — Ingestion locks, worker claiming, Argon2id DoS, receipt verification, SOAR state machine.
- **Stage C**: Data Lifecycle Subsystem (P0) — `aegis/retention.py`, maintenance identity, CLI/API triggers, legal holds.
- **Stage D**: Scale & Protocol Architecture (P1) — Semantic entity linking, OpenSearch hardening, RFC Syslog listener.
- **Stage E**: Reliability & Observability (P0/P1) — Docker compose hardening, health checks, Prometheus metrics, backup/restore scripts.
- **Stage F**: Complete Verification & Testing — Regression pytest, strict typing, Playwright E2E, benchmarks.
- **Stage G**: Operator Documentation & Runbooks — Runbooks across `docs/operations/`, `docs/security/`, `docs/testing/`.
