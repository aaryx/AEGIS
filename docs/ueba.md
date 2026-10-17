# UEBA behavioral risk intelligence

AEGIS UEBA compares a completed UTC observation day with the preceding 14 days.
It uses normalized `username` (falling back to `user_id`), `host` (falling back to
`hostname`), `source_ip`, `event_category`, `outcome`, and persisted event timestamps.
Service accounts are identities; no account type, location, device identity or
process semantics are inferred. The engine does not contact external services.

## Operation

Apply `alembic upgrade head` using the existing deployment procedure. Revision 0011
follows 0010; no existing migration was edited. Restart the API and normal
`aegis-worker`. Jobs are explicitly submitted, not automatically scheduled on every
event. An operator scheduler can submit the previous day after an appropriate
ingestion delay. Redis and OpenSearch are not required for UEBA calculation.

```sh
export AEGIS_URL=http://localhost:8000
export AEGIS_TOKEN=<existing-token>
aegis --format json ueba analyze 2026-10-17T00:00:00Z
aegis --format json ueba jobs
aegis --format json ueba profiles --entity alice
aegis --format json ueba profile <profile-id>
aegis --format json ueba findings --detector failure_burst
aegis --format json ueba evidence <finding-id> --offset 0
aegis --format json ueba analyze 2026-10-17T00:00:00Z --refresh-only
aegis --format json ueba detectors
```

The example analyzes October 16 and compares it with October 2–15. Replace the date
with a completed UTC midnight within the past 90 days. The command submits a job;
inspect jobs for completion or failure. Baseline refresh submits a separate job
that computes profiles without creating findings. Repeat submission returns the
same job. Completed jobs do not reprocess late arrivals. Choose an ingestion delay
appropriate to the deployment; late events remain available to subsequent baseline
windows. A failed job can be explicitly retried with the current configuration.

Configuration uses the existing settings/environment mechanism:

| Setting | Default | Bounds |
|---|---:|---|
| `UEBA_BASELINE_DAYS` | 14 | 7–30 |
| `UEBA_MIN_OBSERVATIONS` | 20 | 10–10,000 |
| `UEBA_MIN_ACTIVE_DAYS` | 7 | 3–7 |
| `UEBA_EVENT_LIMIT` | 10,000 | 100–50,000 |

Each job records its effective configuration. A tenant may have at most ten pending
or retrying jobs. One job runs per worker iteration. The database query reads at
most limit + 1 events over the baseline plus observation window. Exceeding the
bound fails the job without writing partial profiles or findings. There is no
sampling fallback. Size the configured bound and deployment resources together;
high-volume tenants may require a future streaming aggregation implementation.

## Calculation and interpretation

Events are ordered by timestamp and ID, deduplicated by evidence hash plus timestamp
and source, and grouped
by tenant and exact identity/host or canonical IP. Case is preserved for identity
and host names to avoid conflating distinct principals. Invalid or missing entity
fields are ignored. Synthetic collectors, synthetic/test/simulation/replay tags,
and synthetic/test/replay metadata are excluded. Untagged test data cannot be
distinguished from real telemetry. Identical raw messages at different times count
separately because AEGIS hashes the raw event, not its normalized timestamp.
Source-dependent payload differences may still represent duplicate real-world activity.

The baseline contains counts, active days, daily median/MAD (including zero days),
known hosts/IPs, and authentication UTC hours. Below either minimum history
threshold, profiles remain cold and produce no findings. Baselines describe
observed activity; they are not a trusted-clean training corpus.

| Detector v1 | Condition | Impact |
|---|---|---:|
| `activity_volume` | At least 10 events, >2× median, robust deviation ≥6 | 45 |
| `failure_burst` | At least 5 authentication failures, >2× median, deviation ≥6 | 65 |
| `new_source_ip` | Known identity uses an IP absent from nonempty baseline | 35 |
| `new_host` | Known identity uses a host absent from nonempty baseline | 35 |
| `unusual_hour` | At least 3 authentications at unseen UTC hours, baseline ≥20 authentications | 30 |
| `failure_then_success` | At least 5 failures followed by success within 15 minutes for one identity | 75 |

Volume and failure-burst apply to users, hosts and IPs. Other detectors apply to
users. No geolocation or process detector is implemented. Timing is UTC, not an
inferred local work schedule. Day boundaries can split a failure/success sequence.

Robust deviation = `(observed - median) / max(1, 1.4826 * MAD)`.
Novelty/timing use deviation weight 3; failure-then-success uses 6 and exposes its
absolute sequence threshold rather than pretending that it is a statistical z-score.
Confidence = `min(1, history_count / (3 * minimum)) * min(1, active_days / baseline_days)`.
Impact is the documented detector weight, distinct from deviation and confidence.
Priority = rounded and clamped `impact * (0.5 + 0.5 * confidence) *
(0.5 + 0.5 * min(1, deviation / 6))`, within 0–100.
Severity: low <40, medium 40–64, high 65–84, critical ≥85. Current detector weights
do not produce critical findings. Entity priority is the maximum detector score
for its latest analyzed day, never a sum of overlapping evidence. Profile priority
is an observation snapshot; suppressing a finding changes active summary counts,
not that historical measurement. These scores are **not compromise probabilities**.

## Analyst workflow and APIs

The UEBA console shows active severity counts, recent findings, highest-risk
profiles, baseline JSON, risk history, evidence hashes, configuration and job status.
Filters cover entity, severity, status, detector and date. Partial panel failures
are visible and retryable. Finding detail supports acknowledgement, resolution,
suppression and reopening with a reason. Suppression applies to that finding only;
it does not hide future days. Repeated detectors on subsequent days have separate
stable findings and a `repeated` flag. Reprocessing the same day does not create
new occurrences. Risk history reports daily maxima where findings exist; absent
days are not reported as zero risk.

All routes are under `/api/v1/ueba` and use existing authentication and CSRF rules:

| Method | Route | Purpose |
|---|---|---|
| GET | `/summary`, `/detectors` | Counts and effective configuration |
| GET | `/profiles?entity=alice&offset=0&limit=50` | Highest-priority profiles |
| GET | `/profiles/{id}` | Baseline and up to 90 days with findings |
| GET | `/findings?status=NEW&severity=high&detector=failure_burst` | Filtered findings |
| GET | `/findings/{id}?offset=0&limit=50` | Explanation and paginated evidence |
| POST | `/analyze` | `{ "window_end": "2026-10-17T00:00:00Z", "refresh_only": false }` |
| GET | `/jobs`, `/jobs/{id}` | Recent 50 jobs / one job |
| POST | `/jobs/{id}/retry` | Retry FAILED job with current configuration |
| POST | `/findings/{id}/status` | `{ "status": "ACKNOWLEDGED", "reason": "Reviewed authentication logs" }` |
| GET | `/context/{event\|alert\|incident\|storyline}/{id}` | Related findings, up to 100 |

Lists accept offset/limit (default 50, maximum 100), except summary/configuration,
jobs and context as noted. Findings also accept `entity`, `since`, `until` and
`status` (`NEW`, `ACKNOWLEDGED`, `RESOLVED`, `SUPPRESSED`).

`ueba.read` is available to existing read roles; `ueba.update` starts at analyst;
`ueba.execute` starts at senior analyst. Evidence-bearing operations additionally
require the existing composite investigation evidence permissions, including for
restricted API keys. IDs from another tenant return 404. Analyst decisions, job
submission and explicit retry/configuration snapshots use existing integrity-protected
audit logging. Lifecycle history is limited to 100 actual status changes per finding.

Investigation and storyline intelligence panels display findings linked by shared
event evidence. Finding detail links back to existing alerts, incidents and
storylines. This is additive context, not a modification to existing correlation
scores. No incidents or alerts are automatically created. `/context` and finding
IDs are the integration interface for downstream consumers. An integration failure
cannot remove a committed finding. SOAR remains an explicit analyst action from
the existing investigation, with existing approvals and simulated containment.

## Persistence, retention and limitations

Four tables: `ueba_profiles` (latest baseline), `ueba_findings` (immutable assessment
plus mutable analyst lifecycle), `ueba_evidence` (event references and original
hashes), and `ueba_jobs` (durable work and outcomes). Profiles are unique per tenant,
entity type and identifier. Findings are unique per tenant/profile/detector/day.
Composite tenant foreign keys protect profile/finding and finding/evidence links.
Evidence is selected only from tenant-scoped records. Event references deliberately
have no event foreign key, so event retention preserves finding hashes without
holding whole event payloads indefinitely. APIs mark missing events unavailable.

Only the latest profile baseline is retained, with a rolling configured window.
Findings retain the baseline used for the assessment. Findings, evidence hashes,
analyst history, jobs and inactive profiles currently have **indefinite retention**;
there is no automatic UEBA deletion. Plan storage and approved organizational
retention before deployment. Existing event retention still applies; if events were
deleted before analysis, coverage/confidence may be lower. Missing telemetry is
not proof of inactivity. Raw payloads, credentials and command lines are never
copied into UEBA responses.

Transient job failures roll back the complete assessment and retry with bounded
backoff using existing worker retry limits. Deterministic IDs and tenant locks
prevent retry duplicates. FAILED jobs expose safe errors and can be retried.
Automatic daily scheduling, retractions for late events after finalization,
adaptive drift handling, maintenance of a trusted-clean baseline, cross-day
sequences, and calibrated probabilities are outside this initial implementation.

Validation results and environment limits are recorded in the implementation
handoff. Unit/component success alone does not establish production readiness.

## Implementation validation handoff

Executed on 2026-10-17:

| Check | Passed | Failed | Skipped |
|---|---:|---:|---:|
| Full Python regression suite | 349 | 0 | 20 |
| Final UEBA + migration suite after review fixes | 32 | 0 | 0 |
| Frontend Vitest suite | 27 | 0 | 0 |

The focused suite overlaps the full suite; counts are not additive. Final fixes
were validated by the focused suite rather than rerunning the entire Python suite.
Ruff passed, mypy passed for all 38 source files, TypeScript checking passed,
`npm run build` passed, and `git diff --check` passed. An initial Python test
attempt had 16 passes and nine setup errors from Windows temporary-directory access;
isolated-directory reruns outside the sandbox resolved those setup errors.

Clean installation, stepwise upgrades, and an explicit pre-UEBA schema upgrade
were tested with SQLite. Live PostgreSQL migration/concurrency and Redis/OpenSearch
checks remain unverified: `AEGIS_INTEGRATION`, `AEGIS_POSTGRES_TEST_URL`, `REDIS_URL`,
and `OPENSEARCH_URL` were unset, and a Docker check outside the sandbox confirmed
that the Docker Desktop Linux engine pipe was unavailable. Browser-driven end-to-end
QA was not run; frontend interactions were tested with React Testing Library/Vitest.
The existing local application database was not migrated during validation.

Changed files:

- Engine/API/models: `aegis/ueba.py`, `aegis/ueba_api.py`, `aegis/db.py`, `aegis/api.py`.
- Operations/security: `aegis/worker.py`, `aegis/config.py`, `aegis/security.py`,
  `aegis/cli.py`, `compose.yaml`.
- Schema: `migrations/versions/0011_ueba.py`.
- Console: `web/components/ueba.tsx`, `web/components/console.tsx`,
  `web/components/investigation.tsx`, `web/components/storylines.tsx`,
  `web/lib/navigation.ts`, `web/lib/strings.ts`.
- Tests: `tests/test_ueba.py`, `tests/test_migrations.py`, `web/tests/ueba.test.tsx`.
- Documentation: `README.md`, `docs/ueba.md`.

No commits, pushes, history rewrites, database resets, prior migration edits, CI
changes, or dependency additions were made.
