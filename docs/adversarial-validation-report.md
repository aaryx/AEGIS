# Project Cerberus: adversarial validation evidence

Assessment date: 2026-10-17. This is a bounded engineering assessment, not a
production-readiness certification. No production database, credentials, or
external attack target was used.

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
`cerberus-final.xml` records all 12 new local tests passing. These historical
expected failures are distinct from final regression failures.

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
| Frontend/CLI | Existing CLI regression tests run in pytest. Real local API/Next.js Playwright analyst flow passes. Two UEBA browser cases require Compose fixtures and remain locally skipped. |

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
| Complete backend (`release-backend.xml`) | 370 | 0 | 26 |
| New Cerberus subset (included above) | 12 | 0 | 0 |
| Frontend Vitest | 27 | 0 | 0 |
| Detection rule cases | 34 | 0 | 0 |
| Local browser E2E | 1 | 0 | 2 |

Backend coverage is 81%; this is execution coverage, not detection accuracy.
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
python -m pytest tests/test_cerberus.py -q
python -m pytest --cov=aegis --cov-report=term --junitxml=backend.xml
python -m ruff check aegis tests scripts
python -m ruff format --check aegis tests scripts
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
