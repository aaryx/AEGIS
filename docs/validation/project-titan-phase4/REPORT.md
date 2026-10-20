# TITAN Phase 4 qualification

Date: 2026-10-20. Production-pilot decision: **BLOCKED** pending live qualification.
Local regression status and deployment qualification are separate decisions.

## Repository baseline

Started on `feature/ironclad-qualification`, HEAD `593952d3607d9c28813c6f317dcca5d8f3ebafd2`, with a clean index and working tree, no untracked files. Origin is `https://github.com/aaryx/AEGIS.git`. History includes `5683bc1`, `3a96b13`, and the earlier security implementation `772d6b6`. Fetch confirmed the remote branch matched the starting HEAD. No history rewriting or unrelated changes.

Read the Phase 3 report, implementation and tests, CI workflow, release gate, bootstrap/migration configuration, production/development Compose configurations and secret-scan configuration. Phase 3's claims of a universal lock hierarchy and Redis CA wiring were not supported by the starting code. This report supersedes those claims for the inspected paths without rewriting the earlier evidence.

## Findings

| Finding | Severity | Independent result | Remediation and evidence |
| --- | --- | --- | --- |
| H-001 queue admission | High hypothesis | Earlier fix present; original admission race not reproduced in controlled local schedules | `pipeline.ingest` already locks the tenant before counting PENDING/RETRY events plus unindexed search jobs and inserting. Added commit/rollback contention, duplicate retry, capacity and tenant-isolation tests; real PostgreSQL counterparts added to the mandatory release gate. |
| H-002 lock ordering | High | Confirmed SQL ordering defect; PostgreSQL deadlock occurrence not locally reproduced | `security.audit` inserted AuditHead before tenant locking, including its unique/FK locks. Regression captured the wrong first write. Tenant lock now precedes head creation and ORM autoflush. Resource-first paths in API, workers, storyline correlation and retention were corrected; multi-tenant batches lock sorted tenant IDs before resource rows. See matrix for scope and limits. |
| H-003 revocation | High hypothesis | Earlier serialization fix present; no bypass reproduced | Revocation and receipt processing already share a tenant gate, refresh agent state and hold row locks through commit. Tests pause real HTTP receipt processing during signature verification and before execution persistence while revocation attempts the gate. Historical accepted evidence survives; submissions after revocation fail. |
| H-004 transport | High | Confirmed residual configuration and wiring defects | Production accepted verify-ca, ambiguous/blank parameters, hostname-disable overrides and username-only Redis authentication. REDIS_CA was unused; bootstrap discarded PostgreSQL TLS query parameters; maintenance URL escaped policy. Corrected validation and shared client construction; preserved bootstrap TLS; configured TLS server listeners and production role-specific URLs. |

The original Phase 4 reproduction command was `.venv/Scripts/python.exe -m pytest tests/test_titan_phase4.py -q --basetemp=.pytest_temp/phase4-before -p no:cacheprovider`: **11 failed, 4 passed** before implementation fixes. Ten failures demonstrated transport policy acceptance; one demonstrated audit SQL order. An earlier sandbox attempt could not create database fixtures and is not counted as concurrency evidence.

### Engineering behavior

Ingestion remains database-backed and transactional; Redis is used for rate limiting, not atomic queue admission. A rejected batch does not commit events, collector counters or an audit entry. Duplicate ingestion preserves the existing at-least-once API contract. Worker detection moves backlog from event state to durable search outbox in one transaction.

Audited operations acquire tenant gates before shared resources; multi-tenant worker/notification/retention batches acquire gates in sorted order. Audit-head creation occurs under the gate. SQLAlchemy autoflush is suppressed while acquiring it. Worker and UEBA discovery is a nonlocking candidate read followed by tenant acquisition and a fresh eligibility check under resource locks. Cross-tenant detection batches are rejected explicitly.

PostgreSQL application engines now bound connection attempts to 5 seconds, lock waits to 5 seconds and statements to 30 seconds, and hide SQL parameters in SQLAlchemy exception rendering. Detection-worker serialization/deadlock/lock-timeout/cancellation/disconnect failures escape the poison-event fallback and roll back the transaction. Existing worker main-loop recovery waits five seconds between failed iterations. No automatic API mutation replay was added; there is no claim of exactly-once external webhook delivery.

### Reproduction and regression files

- `tests/test_titan_phase4.py`: local controlled admission and receipt schedules, first audit write ordering, policy negatives, client wiring, bootstrap propagation, maintenance policy, bounded engine arguments and synthetic DBAPI rollback/recovery.
- `tests/test_transport_tls.py`: ephemeral loopback TLS servers with actual redis-py SSL connections; trusted certificate, untrusted CA, wrong hostname, invalid CA and missing CA.
- `tests/test_phase4_postgres.py`: isolated database URL safety checks and real PostgreSQL admission/first-head schedules, with bounded database waits. Skipped only if the URL is absent; a configured unavailable server fails.
- `scripts/integration_gate.py` and `tests/test_ci_release_gate.py`: retain all previous mandatory tests and require three additional named PostgreSQL cases. Fixture counts increased from 17 to 20; failure assertions retained.

## Executed validation

All commands ran from the repository root using Windows Python 3.14.3 in `.venv`; remote CI uses Python 3.12. Generated logs remain ignored under `test-results/`.

| Command | Observed result |
| --- | --- |
| `.venv/Scripts/python.exe -m pytest tests/test_titan_phase4.py tests/test_titan_phase3_security_hardening.py -q --basetemp=.pytest_temp/phase4-after -p no:cacheprovider` | 26 passed at the initial remediation checkpoint |
| `.venv/Scripts/python.exe -m pytest tests/test_transport_tls.py -q --basetemp=.pytest_temp/phase4-tls -p no:cacheprovider` | 5 passed, actual loopback TLS handshakes |
| `.venv/Scripts/python.exe -m pytest tests -q --basetemp=.pytest_temp/phase4-full -p no:cacheprovider` | Intermediate checkpoint: 530 passed, 27 skipped; subsequent changes require final run below |
| `.venv/Scripts/python.exe -m pytest tests/test_titan_phase4.py tests/test_transport_tls.py tests/test_phase4_postgres.py tests/test_ci_release_gate.py -q --basetemp=.pytest_temp/phase4-focused-verified -p no:cacheprovider` | 48 passed, 3 unavailable PostgreSQL cases skipped; before final engine-timeout assertion |
| `.venv/Scripts/python.exe scripts/dev.py lint` | Ruff and frontend TypeScript passed |
| `.venv/Scripts/python.exe scripts/dev.py typecheck` | Mypy and frontend TypeScript passed; final standalone Mypy also passed across 42 files |
| `.venv/Scripts/python.exe -m aegis.cli rules test --all` | 34/34 rule cases passed |
| `npm.cmd --prefix web test -- --run` | 35 tests, 8 files passed |
| `npm.cmd --prefix web run build` | Next.js production build passed |
| `.venv/Scripts/python.exe scripts/dev.py security` | Scanner output clean, PowerShell aggregate status 1 with stderr warnings; individual commands rerun below |
| `.venv/Scripts/python.exe -m bandit -r aegis scripts -ll -q` | No medium/high findings; existing nosec comment warnings |
| `.venv/Scripts/python.exe -m pip_audit --skip-editable` | No known vulnerabilities; editable project excluded; local invalid-distribution warning |
| `npm.cmd --prefix web audit` | 0 vulnerabilities |
| `gitleaks.exe git . --config .gitleaks.toml --redact --no-banner` | Gitleaks 8.30.1, official archive checksum verified; 35 commits scanned, no leaks |
| `docker compose -f compose.yaml -f compose.production.yaml config --quiet` | Passed syntax/interpolation validation; no services started |
| `.venv/Scripts/python.exe scripts/integration_gate.py` | Failed closed: PostgreSQL unavailable on local port 5432; downstream service tests not executed |
| `docker info --format '{{.ServerVersion}}'` | Docker daemon unavailable, including outside sandbox |

Existing configuration broadly allowlists tests, docs and Compose in Gitleaks. This scan is not evidence of coverage for those paths; intended files also receive manual review. No secret values or generated private keys belong in this commit.

Final local results and remote CI status are recorded below after execution. Starting HEAD's Actions run `39144264743` passed; that is historical evidence, not qualification of this change.

## Release-candidate local results

- `.venv/Scripts/python.exe -m pytest tests -q --basetemp=.pytest_temp/phase4-release -p no:cacheprovider`: **537 passed, 30 skipped, 3 warnings in 228.98 seconds**. The 30 skips include three new unavailable PostgreSQL cases plus the existing 27 infrastructure-dependent cases. They are not live passes.
- `.venv/Scripts/python.exe -m pytest tests/test_titan_phase4.py tests/test_transport_tls.py tests/test_phase4_postgres.py tests/test_ci_release_gate.py -q --basetemp=.pytest_temp/phase4-timeouts -p no:cacheprovider`: **49 passed, 3 skipped in 15.80 seconds**.
- Final `.venv/Scripts/python.exe -m ruff check aegis tests scripts`, `.venv/Scripts/python.exe -m mypy aegis --cache-dir .mypy_cache/phase4`, and Bandit medium/high gate passed.
- `git diff --cached --check` passed. `gitleaks.exe git . --pre-commit --staged --config .gitleaks.toml --redact --no-banner` scanned the intended staged changes with no findings. The exact executable was installed under the temporary `aegis-phase4-gitleaks` directory.
- Local software scope: **PARTIAL**, because live integration qualification is missing. Production pilot: **BLOCKED**.
- Remote CI for this change: pending push at the time of this engineering commit. The final handover records the actual pushed SHA/run result; no earlier run is attributed to this code.

## Remaining qualification

See `RELEASE_BLOCKERS.md` and `TRANSPORT_SECURITY.md`. In particular, a green SQLite suite cannot qualify PostgreSQL lock semantics; loopback TLS cannot qualify deployed Redis, PostgreSQL or OpenSearch. New PostgreSQL tests are wired into the remote integration release gate. No production deployment is authorized by this report.

## Remote integration follow-up

Engineering commit `fa884d4b7783f7452951ff5eab112a73084d88e6` was pushed without force to the existing feature branch. [Actions run 39357157576](https://github.com/aaryx/AEGIS/actions/runs/39357157576) passed backend tests, lint/types, security/dependency checks, frontend tests/build, browser E2E and Docker startup, then **failed** integration: **61 passed, 1 failed, zero skips**. Later release/image/secret gates did not execute in that run.

All three new PostgreSQL admission/first-head cases passed on real CI PostgreSQL. Existing Redis/OpenSearch connectivity and other database cases also passed. The failure was `test_postgres_concurrent_storyline_correlation`: its hand-written incident updater acquired the incident row before the tenant gate, reproducing a PostgreSQL deadlock against the now tenant-first correlator. This confirms that the gate must precede resource locking; taking it later inside audit cannot repair an already inverted order.

The follow-up changes that test's simulated updater to the same tenant-first protocol already implemented by the production status endpoint. All original concurrency, membership and audit assertions remain; an exact four-revision increment assertion strengthens it. A new real-HTTP local regression captures SQL and requires the production status endpoint's tenant gate before its incident lookup, preventing the test-only gate from masking a production mismatch. No skip, retry tolerance or deadlock exception suppression was added. Follow-up remote CI remains pending at commit time and is reported by SHA in the final handover.

Follow-up local command: `.venv/Scripts/python.exe -m pytest tests/test_titan_phase4.py tests/test_storylines.py tests/test_postgres_integration.py -q --basetemp=.pytest_temp/phase4-ci-followup -p no:cacheprovider`: **49 passed, 21 unavailable PostgreSQL cases skipped in 17.96 seconds**. Ruff and diff checks passed. Only tests and evidence changed after the fully tested engineering commit.
