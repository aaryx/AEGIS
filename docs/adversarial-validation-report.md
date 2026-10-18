# Project Cerberus: adversarial validation evidence

Assessment date: 2026-10-17. This is a bounded engineering assessment, not a
production-readiness certification. No production database, credentials, or
external attack target was used.

Tested implementation commit: `37db897654b8d17d075e9a13a755df145d77f13c`.
This commit builds on prior Cerberus fixes (`a71939483421570c9c1db00db9ba4a90a3402b3e`),
resolving acceptance drill race conditions and incomplete investigation polling (CER-05).
Source-file SHA-256 digests are preserved in `validation/cerberus/results.json`.

## Ground truth and environment

The starting tree was clean on `main`, commit
`146bbddb4b10e90c92b3359e963baa81be077408`. A read-only `git ls-remote origin
refs/heads/main` confirmed the same remote SHA. Origin is
`https://github.com/aaryx/AEGIS.git`. GitHub reported successful baseline CI:
<https://github.com/aaryx/AEGIS/actions/runs/39027511373>.
That run does **not** validate Cerberus changes.

Local environment: Windows 11 build 26200, Python 3.14.3, existing project virtual
environment and frontend dependencies. Tests use temporary SQLite WAL databases;
the benchmark additionally records its platform in `validation/cerberus/benchmark.json`.
Docker's Linux-engine named pipe is absent, including outside the sandbox.
PostgreSQL, Redis, OpenSearch, container scans, and backup/restore cannot be
validated locally through Compose. Existing `.env`, `aegis.db`, and local user
data were not modified. No migration or destructive drill targeted them.

The containing commit identifies the tested source changes; find it with
`git log -1 --format=%H -- docs/adversarial-validation-report.md`. Final remote
CI must be checked against that exact SHA, not the baseline run above:
`gh run list --branch security/cerberus-validation --json headSha,status,conclusion,url`.
Remote CI status is intentionally not predicted in this committed report.

## Risk-ranked execution plan and inspected boundaries

1. High: audit deletion/head corruption; tenant/object authorization; conflicting
   ingestion acknowledgements; approval and evidence integrity.
2. High/medium: rollback, bounded retries, duplicate delivery, concurrent writes,
   worker interruption, and sensitive exception handling.
3. Medium: parser/payload/configuration bounds, migration realism, dependency
   failure, frontend/CLI error behavior, and resource measurements.

Inspected implementation: `security.py` (sessions, scoped keys, roles, CSRF,
   HMAC chains/checkpoints); `api.py`, `investigation.py` and specialized UEBA,
SOAR/intelligence routers; `pipeline.py`, parsers/schemas, detection/replay and
storylines; `worker.py`, `ueba.py`, `soar.py`, integration/provider transport;
database models, migrations 0001–0011, deployment/initialization/recovery scripts,
CLI, frontend E2E configuration, and `.github/workflows/ci.yml`.

SQL is authoritative for acknowledged ingestion and jobs; OpenSearch is a
retryable projection. PostgreSQL row locks and constraints are the production
concurrency boundary. SQLite tests do not prove PostgreSQL scheduling behavior.
The SOAR containment adapters remain simulated. Scope and human approvals are
revalidated in the workflow engine. No action adapter or permission was expanded.

## Confirmed findings and fixes

| ID | Severity and condition | Reproduction and smallest fix |
|---|---|---|
| CER-01 | High integrity-verification defect: a privileged storage tamper deleting every audit row returned `valid=true` despite a nonempty durable head. | `test_audit_head_damage_fails_closed[delete_all]` failed before the fix. Empty history now must agree with the organization head. Unknown organizations fail verification. |
| CER-02 | Medium: altered audit sequence counts and disagreement between organization/AuditHead pointers passed verification. | The `sequence` and `organization_head` cases failed before the fix. Check sequence count against row count and both head pointers before HMAC traversal. |
| CER-03 | High ingestion correctness: simultaneous source-sequence reuse with different raw evidence could be acknowledged as a duplicate. The first stored record survived, but the second caller received a misleading acknowledgement. | Two database reads are synchronized with a barrier before either insert. The unique-key loser previously skipped hash comparison. Re-read the winner's evidence hash after the conflict and reject differing evidence inside the transaction. Identical evidence still deduplicates. |
| CER-04 | Medium confidentiality: worker exception logging included arbitrary exception messages and traceback text. | A synthetic `ConnectionError` containing a sentinel appeared in captured logs before the fix. Detection/search worker paths now log stable event names, exception class and event count. The API catch-all uses the same policy, retaining request ID and generic HTTP 503. |
| CER-05 | High acceptance reliability: bounded polling in acceptance drill prematurely aborted upon finding an incomplete investigation before all 16 events and IOCs/entities correlated. | `test_acceptance_waits_for_complete_investigation` reproduced the premature exit and incomplete assertion failure (`acceptance-before.xml`). `wait_for_investigation` in `scripts/acceptance.py` now polls until all 16 events, IOCs, and entities are present before proceeding. Verified with `acceptance-after.xml` and full test suite. |
| TITAN-01 | High UEBA assessment defect: duplicate event IDs yielded in behavior evidence caused `UniqueConstraint("organization_id", "finding_id", "event_id")` `IntegrityError` in `aegis/ueba.py`, failing entire tenant assessments. | Deduplicate evidence event IDs via `seen_evidence_ids` before persistence in `aegis/ueba.py`. Verified with regression test `test_evidence_deduplication_prevents_unique_constraint_failure`. |
| TITAN-02 | Medium SOAR runtime safety: string-encoded numeric values in context raised unhandled `TypeError` during `matches()` evaluation for `gte` operator in `aegis/soar.py`. | Coerce numeric fields (`risk_score`, `intel_confidence`) to integers and catch comparison `TypeError` gracefully with fallback to `False`. Verified with `test_matches_condition_safe_numeric_comparison`. |
| TITAN-03 | Low SOAR audit completeness: `resource_id` was empty string on 403 authorization failures in `decision()`, and omitted on trigger rejection audit calls in `aegis/soar_api.py`. | Initialize `resource_id = identifier` at endpoint start in `decision()`, and pass `resource_id=identifier` to `audit()` in `execute()`. Verified with `test_soar_audit_resource_id_on_decision_rejection_and_trigger`. |
| TITAN-04 | Medium storyline correlation resilience: missing or purged anchor alerts / incidents in `aegis/storylines.py` raised unhandled `KeyError` during correlation. | Safe lookups `by_id.get(story.anchor_alert_id)` and `incidents.get(story.incident_id)` with safe continue semantics. Verified with `test_correlate_resilience_missing_anchor_alert_or_incident`. |
| TITAN-05 | High intelligence tenant isolation: `related()` in `aegis/intelligence.py` joined `AlertEvent` and `IncidentAlert` across tenants without filtering `Alert.organization_id == org` and `Incident.organization_id == org`. | Join `Alert` and `Incident` with explicit `organization_id == org` filters. Verified with `test_related_observables_tenant_isolation`. |
| TITAN-06 | High audit integrity closed-failure: deleting the `AuditHead` row allowed `verify_audit()` in `aegis/security.py` to evaluate truncated chains as valid. | Check `if not head: if records or org.audit_head != '0'*64: return False` to enforce fail-closed verification on missing head. Verified with `test_audit_verification_closed_failure_on_missing_or_tampered_head`. |
| TITAN-07 | Medium UEBA event limit enforcement (Section 9): tested below, at, and above the 10,000 default (configurable up to 50,000) bound with nested transaction rollback. | Verified in `test_ueba_event_limit_below_at_and_above` that exceeding the bound raises `ValueError`, rolls back partial state, and transitions worker job cleanly to `FAILED` without getting stuck in retry loops. |
| IRONCLAD-01 | High Data Retention & Legal Holds: Case evidence with plural `resource_type == "events"` and non-closed active alerts (`ACKNOWLEDGED`, `INVESTIGATING`, `ESCALATED`) bypassed retention protection in `aegis/retention.py`. | Checked `resource_type in {"event", "events"}` and protected all active non-closed alerts; added tenant scoping to search job/entity relationship pruning. Verified in `tests/test_ironclad_qualification.py::test_ironclad_01_retention_legal_hold_case_evidence_plural_and_active_alerts`. |
| IRONCLAD-02 | Critical Agent Cryptographic Receipt Authenticity: `/agents/{name}/receipts` accepted unkeyed SHA-256 fallback (`receipt_hash`) recomputed from client payload, bypassing Ed25519 signatures, challenge freshness windows, and controller signature binding. | Removed unkeyed SHA-256 fallback, enforced mandatory Ed25519 signature from enrolled agent, 300s freshness window, controller signature binding, and anti-replay nonces in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_02_agent_receipt_requires_cryptographic_verification`. |
| IRONCLAD-03 | High Agent Token Authentication & Anti-Impersonation: Missing anti-impersonation checks across agent endpoints allowed one agent token to query or submit data for another agent. | Enforced token authentication and strict path/token identity alignment in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_03_enrolled_agent_token_can_access_agent_endpoints_and_rejects_impersonation`. |
| IRONCLAD-04 | Medium Agent Ed25519 Key Rotation: Inconsistent JSON key ordering and missing signature verification allowed unvalidated key rotation payloads. | Standardized canonical payload serialization and enforced Ed25519 signature verification on key rotation in `aegis/agent.py` and `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_04_agent_key_rotation_validates_signature`. |
| IRONCLAD-05 | High Syslog TCP Bounded Buffer Protection: RFC 5425 octet-counting parser accumulated unbounded byte streams when presented with invalid frame headers, risking DoS memory exhaustion. | Enforced bounded buffer defense in `aegis/syslog.py` discarding frames exceeding `max_bytes` (64KB). Verified in `tests/test_ironclad_qualification.py::test_ironclad_05_syslog_tcp_oversized_octet_frame_defense`. |
| IRONCLAD-06 | Medium Ingestion Parser Error Propagation: Unparsed schema validation errors bubbled up as HTTP 500/503 errors instead of explicit client errors (400/422). | Caught schema parsing validation errors in `aegis/parsers.py` and mapped them to `ValueError` (HTTP 400). Verified in `tests/test_ironclad_qualification.py::test_ironclad_06_ingestion_parser_malformed_event_returns_400_not_503`. |
| IRONCLAD-07 | High Agent Process Termination Safety Guardrails: `terminate_process` permitted arbitrary PID termination, risking termination of PID 0, PID 1, or critical Windows subsystem binaries (`csrss.exe`, `lsass.exe`, `services.exe`). | Added boundary checks in `aegis/agent.py` blocking `pid <= 1` and system binaries. Verified in `tests/test_ironclad_qualification.py::test_ironclad_07_agent_terminate_process_blocks_invalid_pid_and_system_binaries`. |
| IRONCLAD-08 | Low Case Status Workflow Transitions: Case status updates allowed arbitrary strings without state machine validation. | Enforced recognized lifecycle transitions (`OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`) with HTTP 422 on invalid status in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_08_case_status_workflow_transitions`. |
| IRONCLAD-09 | High Case & Evidence Multi-Tenant Isolation: Cross-tenant evidence attachment and case access verified and isolated. | Verified explicit tenant scoping on case/evidence attachment in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_09_tenant_isolation_cases_and_evidence_cross_attach`. |
| IRONCLAD-10 | High SOAR Playbook Multi-Tenant Isolation: Playbook templates and execution runs strictly isolated per tenant. | Verified tenant boundaries in `aegis/soar_api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_10_tenant_isolation_soar_playbooks_and_executions`. |
| IRONCLAD-11 | Medium SOAR Separation of Duties: Users barred from approving their own playbook execution requests even if holding manager privileges. | Verified self-approval prevention in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_11_soar_separation_of_duty_prevents_self_approval`. |
| IRONCLAD-12 | Medium Rule Replay Multi-Tenant Isolation: Replay jobs restricted from accessing or referencing foreign tenant rules/events. | Verified tenant scoping in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_12_tenant_isolation_rule_replay_jobs`. |
| IRONCLAD-13 | Medium System Retry Multi-Tenant Isolation: Dead-letter and search job retries restricted to the owning organization. | Verified tenant scoping in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_13_tenant_isolation_dead_letter_and_search_retries`. |
| IRONCLAD-14 | High Resource Export Multi-Tenant Scoping: Bulk export endpoint filtered strictly by authenticated tenant. | Verified tenant scoping in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_14_tenant_isolation_export_endpoint`. |
| IRONCLAD-15 | Medium Incident Idempotency Conflict Handling: Reusing idempotency keys with conflicting payload attributes returns HTTP 409 Conflict. | Verified conflict resolution in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_15_incident_idempotency_key_conflict_rejection`. |
| IRONCLAD-16 | Medium Sigma Import Guardrails: Enforced file size limits (>1MB rejected) and YAML rule schema validation. | Verified in `aegis/api.py`. Verified in `tests/test_ironclad_qualification.py::test_ironclad_16_sigma_rule_import_validation_and_size_limits`. |
| IRONCLAD-17 | Low SQLite Benchmark Ephemeral Schema Reset: Ephemeral benchmark database schema collision on pre-existing SQLite files. | Unlinked default ephemeral database prior to `create_all()` in `scripts/benchmark_concurrency_and_stress.py`. Verified in concurrency benchmarks. |

Integrating the PostgreSQL regression also exposed a release-gate parser that
could not recognize parameterized pytest node names. The gate now requires both
exact case identifiers, with negative tests proving omission of either is fatal.
The existing OpenSearch outage/outbox recovery drill is now a CI step against
the runner's disposable Compose services; no existing gate or scan was removed.

No public schema or migration changes were necessary. Audit verification becomes
stricter; operators encountering inconsistent heads should investigate, not reset
the chain to make verification pass. Existing records/evidence are not rewritten.

Before/after machine-readable evidence lives in `validation/cerberus/`:
`before.xml` records three audit failures and two passing controls;
`race-before.xml` records one conflict failure and one identical-duplicate pass;
`log-before.xml` records the sensitive-log failure;
`acceptance-before.xml` records four premature exit/incomplete investigation failures;
`cerberus-final.xml` records all 12 new local tests passing;
`acceptance-after.xml` records 32 tests passing (4 acceptance recovery, 12 Cerberus, and 16 gate tests).
These historical expected failures are distinct from final regression failures.

## Automated scenario coverage

| Area | Executable evidence and scope |
|---|---|
| Authentication, tenant isolation, RBAC | Existing `test_security`, `test_phase32_security_verification`, `test_master_qa_security_and_functional`, `test_ueba`, `test_soar`, `test_intelligence`, `test_storylines` exercise separate identities, scoped keys, foreign identifiers, roles, sessions, CSRF and object access. Passing existing tests is not an exhaustive endpoint authorization proof. |
| Audit/evidence | Existing audit, anchor, agent-security and hardening suites cover HMAC mutation, middle deletion, truncation, checkpoint signatures, raw-event hashes and simulated receipts. New tests cover total deletion and inconsistent heads, rollback, and four barrier-synchronized audit writers. |
| Ingestion/detection | Existing schema, pipeline, detection, replay, durability and rule suites cover invalid inputs, payload size, nesting, thresholds, duplicate delivery, late events and isolated replay. New paired-request race tests cover identical versus contradictory evidence. |
| UEBA recovery | Injected `ConnectionError` after a flushed audit write proves savepoint rollback, six bounded attempts ending FAILED, redacted error storage, explicit retry and successful completion. Injected `KeyboardInterrupt` proves outer transaction rollback and a fresh worker invocation can complete the still-PENDING job. These simulate interruption, not OS kill or power loss. |
| SOAR | Existing tests cover revoked approval, two-person authorization, restart, bounded retries, timeout rollback, pinned versions, tenant scope and simulated containment. No claim of exactly-once external side effects. |
| Providers/dependencies | Existing mocked intelligence/integration tests cover malformed responses, missing credentials, HTTP errors/timeouts, SSRF protections and rate/size bounds. New API injection verifies HTTP 503, no mutation and no sensitive exception text. Real service outage/connection recovery remains a staging requirement. |
| Concurrency | New barriers coordinate audit writers and the exact ingestion read/insert race without sleeps. The PostgreSQL version is added to the mandatory zero-skip integration gate. Existing suites cover rate limiting, window updates, workflows, findings and transaction rollback. |
| Frontend/CLI | Existing CLI regression tests run in pytest. Real local API/Next.js Playwright analyst flow passes. Two UEBA browser cases require Compose fixtures and remain locally skipped. New `tests/test_acceptance_recovery.py` verifies bounded investigation polling and strict failure on permanently missing evidence in `scripts/acceptance.py`. |

## Event-limit resolution

`Settings.ueba_event_limit` and Compose both default to **10,000**; the allowed
range is **100–50,000**. `ueba.config()` snapshots the setting into each job.
`analyze()` reads at most limit + 1 rows for one tenant from baseline start
through (exclusive) observation end, before feature filtering and deduplication.
With defaults this spans **15 days**, not one day or one entity. Overflow fails
the job without partial profiles/findings. Tests verify default/API exposure,
environment override and bounds; existing tests verify overflow rollback.
The historical production-readiness wording has been corrected accordingly.

## Performance evidence

Command: `python scripts/benchmark_cerberus.py`. It uses only disposable databases,
one discarded 100-event warm-up, three independent repetitions each at 100 and
500 events, batches of 50, 34 seeded rules, one worker, 20 synthetic users/five
hosts and authentication-success events. All submitted events must reach
PROCESSED. SQL statement counting uses an engine hook; elapsed time uses
`perf_counter`, process CPU uses `process_time`, Python allocation peak uses
`tracemalloc`. Raw repetitions are in `validation/cerberus/benchmark.json`.

| Median of three repetitions | 100 events | 500 events |
|---|---:|---:|
| Ingest events/sec | 119.91 | 153.37 |
| Worker events/sec | 39.09 | 53.21 |
| Ingest batch p50 seconds | 0.4170 | 0.2988 |
| Ingest batch p95 seconds | 0.4668 | 0.5455 |
| UEBA assessment seconds | 0.1142 | 0.2828 |
| SQL statements | 1,497 | 6,321 |
| Process CPU seconds | 3.2344 | 11.5000 |
| Peak Python allocated bytes | 2,304,591 | 5,428,580 |

This is an instrumented local smoke baseline, **not production throughput**.
Other test processes were active; timings include instrumentation overhead.
Small sample p95 values are batch order statistics, not reliable tail estimates.
Python allocations are not RSS. Workload lacks attack-heavy correlation and
long mature UEBA history. API latency distributions, database slow-query plans,
production queue depth, sustained saturation, multitenant throughput, and
concurrent PostgreSQL benchmarks are unmeasured. No speculative performance
optimization was made from these numbers.

## Deployment, recovery and residual risks

- Local migration tests exercise fresh installation, repeat upgrade, stepwise
  0001–0011, rejected downgrade and explicit old-schema reconstruction. Migration
  0001 derives columns from current ORM metadata (and includes UEBA tables);
  therefore stepwise tests alone do not establish upgrades from every historical
  release. Replay real release snapshots on disposable PostgreSQL before rollout.
  The old report's zero-downtime claim was not established by these tests.
- PostgreSQL runtime privileges/append-only audit triggers reduce storage-tamper
  exposure but do not protect against database administrators. Consistent removal
  of logs **and** local heads requires independent trusted checkpoints to detect.
  Independently configured WORM storage and restore drills remain necessary.
- Queue-capacity prechecks in ingestion are not a demonstrated strict concurrent
  global quota. At-least-once delivery and idempotent local transitions are the
  supported model; no exactly-once or power-loss durability claim is made.
- UEBA terminal transitions do not emit separate audit entries in `process_jobs`;
  durable job state provides observability, but the old documentation's blanket
  complete-audit-lifecycle claim is too strong. This remains an operational gap.
- Exception redaction changes cover API catch-all and event/search workers.
  Agent, retention and syslog logging still need a separate sensitive-error review.
- Retention Compose healthcheck exits zero without checking worker progress.
  Treat it as process configuration, not proof of maintenance health.
- Live PostgreSQL/Redis interruption, OS-level worker termination, network
  partition, backup/restore, graceful container shutdown and independent WORM
  recovery were not run locally. Existing CI commands and dedicated staging
  drills are required; mocks and Python interruption do not substitute for them.
- Repository-wide formatter check fails on pre-existing formatting drift. No
  security checks, assertions, tests, or branch policies were disabled.

## Reproduction and final verification

| Final local check | Passed | Failed/errors | Skipped |
|---|---:|---:|---:|
| Complete backend (TITAN: `docs/validation/titan/release-backend.xml`) | 381 | 0 | 26 |
| Complete backend (IRONCLAD: `docs/validation/ironclad/release-backend.xml`) | 397 | 0 | 26 |
| IRONCLAD qualification security suite (`tests/test_ironclad_qualification.py`) | 16 | 0 | 0 |
| Cerberus + Acceptance + TITAN regression subset | 23 | 0 | 0 |
| Frontend Vitest | 27 | 0 | 0 |
| Detection rule cases | 34 | 0 | 0 |
| Local browser E2E | 1 | 0 | 2 |

Backend coverage is 82%; this is execution coverage, not detection accuracy.
See the comprehensive [Project IRONCLAD Qualification Report](docs/validation/ironclad/ironclad-qualification-report.md) for full risk registers, benchmarks, failure drills, and release gates.
Lint, mypy (38 source files), frontend typecheck/build, Bandit medium/high scan,
pip-audit and npm audit passed. Pip-audit excludes the editable project itself.
One non-test check fails: repository-wide formatting (42 pre-existing files).
Six locally blocked check groups are enumerated in `results.json`; they are not
invented test-case totals. Remote service/scanner results must be read from CI.
Earlier gate integration runs with four and then two failures are retained as
historical artifacts; the final full run above includes the corrected gate and
both negative parameter-case tests. No failures were suppressed.

Use the installed virtual environment (`.venv/Scripts/python` on Windows):

```text
python -m pytest tests/test_ironclad_qualification.py -v
python -m pytest --cov=aegis --cov-report=term --junitxml=docs/validation/ironclad/release-backend.xml
python -m ruff check aegis tests scripts
python -m mypy aegis
python -m bandit -r aegis scripts -ll -q
python -m pip_audit --skip-editable
python -m aegis.cli rules test --all
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
npm --prefix web audit
python scripts/e2e.py
python scripts/benchmark_cerberus.py
python scripts/benchmark_concurrency_and_stress.py
```

In a **fresh disposable checkout with disposable service volumes**, follow the
existing configure/Compose procedure, then run `python scripts/dev.py integration`,
`python scripts/acceptance.py`, `docker compose exec -T api python
scripts/integration_checks.py`, `python scripts/recovery_drill.py`, and
`python scripts/compose_e2e.py`. Do not aim these commands at a shared database.
The existing CI also runs Trivy, Gitleaks and image CycloneDX SBOM generation.
It now additionally runs `python scripts/failure_drill.py` to stop and restart
OpenSearch and verify durable detection/projection recovery. Run this command
only against disposable services.

Exact local outcome totals are recorded in `validation/cerberus/results.json`;
JUnit artifacts preserve individual outcomes. Counts from overlapping runs must
not be summed as unique coverage. Skipped service tests are not passes. The
initial sandbox attempt had 268 fixture permission errors; the approved rerun
completed successfully. Repository CI on the mission branch is the authoritative
remote check for the containing source commit and must be reported separately.
