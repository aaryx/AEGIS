# SOAR workflows

AEGIS now has versioned workflows at `/api/v1/soar`. Existing `/playbooks` single-action response APIs and their agent integrations retain their behavior. The console Playbooks page opens the new workflow library; legacy response records remain accessible through the existing API/CLI.

## Architecture

- `aegis/soar.py`: strict declarative schemas, tenant-scoped source/input validation, typed adapter protocol, queueing, and one-step transactional advancement.
- `aegis/soar_api.py`: library/version APIs, explicit source triggers, history, decisions and audit access.
- `soar_playbooks`: tenant-unique names and current enabled version. `soar_versions`: immutable-through-API definition snapshots. `soar_runs`: pinned version, input references, source metadata snapshot, deadline, cursor, attempts and bounded step history.
- `aegis.worker.process_once` polls the workflow queue alongside existing detection/search work. No new service or message broker is needed.
- Every workflow mutation takes the tenant organization row write lock. This permits one in-flight workflow step per tenant, serializes competing API decisions, and works with PostgreSQL and SQLite. Different PostgreSQL tenants can advance concurrently. SQLite serializes writes database-wide.
- Each step and its local effects commit together. A worker crash rolls back the current transaction; a restarted worker resumes from the persisted cursor. Local note retries cannot duplicate a committed note. No leases or external side effects are involved.
- Audit records use the existing signed, checkpointed audit chain. History contains safe result metadata, not raw events or exception messages.

## Migration and operation

Back up the database using the existing operating procedure, then run:

```powershell
.venv/Scripts/alembic upgrade head
.venv/Scripts/aegis-worker
```

Revision `0009` follows `0008`, adds three tables, tenant-composite foreign keys, unique version/request/source constraints, and queue indexes. `0001` excludes these later-owned tables from its metadata-based bootstrap, consistent with previous additions. Destructive downgrades remain disabled. No migration is automatically applied to a running production database by this change.

Configuration (existing settings/environment loading):

| Setting | Default | Meaning |
|---|---:|---|
| `SOAR_QUEUE_CAPACITY` | 100 | Active executions per tenant, including approval waits |
| `SOAR_BATCH_SIZE` | 20 | Maximum candidate steps per worker iteration |
| `RESPONSE_APPROVAL_SECONDS` | existing platform default | Approval validity, rechecked by the worker |

Keep the existing worker running for execution and approval-wait timeout processing. API cancellation/approval also checks the wall-clock deadline. A stopped worker delays persisted timeout transitions until it resumes. Disabling a playbook prevents new runs; explicitly cancel existing runs to stop them.

## Definition format

Save this as `review-definition.json`:

```json
{
  "description": "Enrich a high severity incident and record a review note",
  "trigger": {
    "source": "incident",
    "conditions": [
      {"field": "severity", "op": "gte", "value": "high"},
      {"field": "status", "op": "eq", "value": "OPEN"}
    ],
    "required_fields": ["severity", "status"],
    "required_evidence_fields": []
  },
  "input_schema": {},
  "output_schema": "aegis.action-result.v1",
  "timeout_seconds": 300,
  "steps": [
    {"id": "enrich", "action": "enrich", "retries": 1, "timeout_seconds": 10},
    {"id": "note", "action": "incident_note", "when": {"field": "severity", "value": "critical"}, "on_false": "summary"},
    {"id": "summary", "action": "summary"}
  ]
}
```

Unknown properties, actions and input names are rejected. At most 32 ordered steps, 3 automatic retries per step, 30 seconds per step and 3600 seconds per execution are permitted. Forward-only `on_false` branches and no workflow-trigger action prevent loops and recursion. A false condition without `on_false` skips to the next step. Conditions use the metadata snapshot taken when queued, so branches are deterministic across retries; adapters re-resolve tenant-owned source/target records when acting.

`source` supports `alert`, `incident`, `storyline`. Filters support severity ordering (including informational), incident/alert status equality, alert `rule_id` equality, and alert/storyline risk threshold (0–100). Missing filter fields do not match. Required evidence fields may be `host`, `username`, `source_ip`, `destination_ip`, `event_id`; each must appear in at least one linked event. Evidence checks inspect at most 2000 linked events and fail closed beyond this bound. They never copy raw evidence to the execution.

Input schemas deliberately accept only tenant-owned references: `{"target_id":"entity"}` and/or `{"ioc_id":"ioc"}`. All declared references are required; undeclared inputs are rejected. The output schema is the fixed versioned `ActionResult` envelope, returned as JSON Schema by the validation endpoint. Definitions cannot contain executable code, templates, shell commands, URLs, connector credentials or arbitrary action parameters. Do not put secrets in definition descriptions or names, which are visible to playbook readers.

## Adapters and safety

| Action | Behavior |
|---|---|
| `enrich` | Returns allowlisted source metadata and optional IOC confidence/severity |
| `incident_note` | Adds a deterministic review note to an incident/storyline's incident; suppressed in dry run |
| `simulate_block_ip` | Requires an IP entity with a valid IP address |
| `simulate_disable_account` | Requires a user entity |
| `simulate_isolate_host` | Requires a host entity |
| `summary` | Generates a deterministic structured source/status/step-count summary |

All containment outputs say simulation and `external_changed: false`. They do not write entity policy, invoke legacy response adapters, dispatch agent commands, or contact external systems. Non-dry-run containment simulations require a different human approver for **each step**. Approval is invalidated if the approver is disabled, loses permission, changes tenant, or approval expires. Dry runs remain simulations and never write notes. The requester must still be an active authorized user at execution time.

Adapters implement `Adapter.execute(db, run, step) -> ActionResult`. This release intentionally only registers bounded local adapters. Timeout is checked around adapter work, with local effects rolled back on overrun; it is cooperative, not a process-killing sandbox. Do not add blocking I/O to this interface. A real connector requires a separate durable outbox, connector-specific authorization, bounded network timeouts, idempotency/fencing and reconciliation before registration. This release cannot perform real containment, even after approval.

The deadline includes queue time, retries and approval waits. Cancellation takes effect between atomic steps: a committed step remains in history and is not undone. Rejection cancels the execution and is audited. Automatic retries use bounded exponential delay. Explicit retries resume only the failed step, retain history, require an unexpired deadline, and cap total action attempts at four. Timeout and cancellation are terminal.

## Authorization

- All roles with `playbooks.read` may inspect definitions. Execution reads and decisions also require the existing composite evidence read scope.
- Security administrators create/version/enable playbooks using the new `playbooks.write` permission.
- Senior analysts and higher execute/cancel/retry with `playbooks.execute`; starting a run additionally requires `incidents.update` and evidence scope because workflows can add notes.
- SOC managers and higher approve/reject using `playbooks.approve`. Self-approval and self-rejection are denied.
- Execution audit reads require `audit.read`.
- API keys must explicitly include required scopes. Tenant-owned input and source lookups never use unscoped identifiers.

## API

All paths below are relative to `/api/v1/soar`, with existing bearer/session authentication and CSRF rules.

| Method/path | Request/result |
|---|---|
| `POST /validate` | Definition JSON ? validation result and output JSON Schema; malformed input returns 422 |
| `GET /playbooks?offset=0&limit=50` | Tenant library |
| `POST /playbooks` | `{name, definition, enabled, expected_version}`; 0 creates, current version appends |
| `GET /playbooks/{id}` | Current metadata and latest 100 definition versions |
| `POST /playbooks/{id}/execute` | `{source_type, source_id, inputs, dry_run, idempotency_key}` ? durable run |
| `GET /executions?status=WAITING_FOR_APPROVAL&offset=0&limit=50` | Filtered history/approval queue |
| `GET /executions/{id}` | State, pinned version, safe inputs, timestamps and step attempts |
| `POST /executions/{id}/decision` | `{decision: "approve" | "reject" | "cancel" | "retry"}` |
| `GET /executions/{id}/audit` | Audit history (bounded to 500 records) |

Example creation body:

```json
{"name":"Incident review","enabled":true,"expected_version":0,"definition":{"description":"Safe review","trigger":{"source":"incident"},"steps":[{"id":"summary","action":"summary"}]}}
```

Example execution body:

```json
{"source_type":"incident","source_id":"INC-existing","inputs":{},"dry_run":true,"idempotency_key":"incident-review-001"}
```

Reusing a request key with a different payload returns 409. Even different request keys cannot trigger a second execution of the same source/type/playbook/version/dry-run mode. Different inputs for an already triggered source return 409. Publish a new version for deliberate reprocessing, or use the bounded failed-step retry control. Triggers are explicit authenticated submissions, not automatic detection hooks, so replay and generated notes cannot recursively launch workflows.

## CLI and console

```powershell
$env:AEGIS_TOKEN = "<existing authorized token>"
aegis soar list
aegis soar validate review-definition.json
aegis soar save review-create-body.json
aegis soar execute <playbook-id> incident <incident-id> review-request-001
# Default is dry run; containment simulations still never touch external systems:
aegis soar execute <playbook-id> incident <incident-id> review-request-002 --no-dry-run --target-id <entity-id>
aegis soar inspect <execution-id>
# Use another authorized human's session/token:
aegis soar approve <execution-id>
aegis soar decision <execution-id> reject
aegis soar decision <execution-id> cancel
```

The existing console's **Playbooks** page includes a paginated library, version JSON, validation/editor, explicit source execution form, dry-run indicators, polling execution history, pending approval filter, per-attempt timeline, failure codes, independent approval/rejection, retry and cancellation controls. Buttons honor permissions; API authorization is authoritative. It does not show fabricated success metrics. Failed mutations display the backend error.

## Verification and limits

`tests/test_soar.py` covers definitions/version pinning, branching, triggers, duplicate submissions, concurrent SQLite workers, rollback/recovery, retries, timeout/cancel, approval revocation, tenant boundaries, safe simulations, notes, audit events and CLI routing. `web/tests/playbooks.test.tsx` verifies persisted states, permissions, approval/filter requests, error display, retries and terminal controls. A real PostgreSQL concurrency test lives in `tests/test_postgres_integration.py` and requires `AEGIS_POSTGRES_TEST_URL`; unavailable integrations are skipped.

Intentional limits: sequential workflows only; no arbitrary expression language, parallel DAG, automatic ingestion hooks, freeform note templates, real connectors or AI-generated summaries. Only the latest 100 versions are returned by the detail API, though all are retained. Timeouts require a running worker to materialize and cannot forcibly interrupt Python code. Local adapter results expose only minimal metadata. Browser end-to-end checks and PostgreSQL/Redis/OpenSearch integration checks require their configured runtimes; unit tests are not substitutes for those deployment checks.

### Verification results (2026-10-17)

- Full Python suite: **280 passed, 15 skipped, 3 warnings** (135.59 seconds). Skips cover unconfigured PostgreSQL and external dependency integration tests; those integrations were not verified.
- Final focused SOAR run after decision-audit changes: **21 passed, 3 warnings** (7.15 seconds).
- Earlier migration/storyline stage: **24 passed**; expanded SOAR/security/audit/durability stage: **141 passed**.
- Frontend: **16 passed across 5 test files**; `npm run typecheck` and production `npm run build` passed. The initial build detected a Windows encoding issue in the new component; UTF-8 conversion resolved it and the build/tests were rerun successfully.
- Ruff checks passed for all changed Python files; targeted mypy passed for both new backend modules; `git diff --check` passed.
- Browser end-to-end tests were not run. Migration tests used temporary databases; the existing local application database was not migrated.
- The system Python had no pytest, and initial virtual-environment tests hit Windows permissions on the existing pytest temporary directory. Tests subsequently ran with approved access and distinct temporary directories. The three successful-run warnings are existing FastAPI/Starlette and Typer/Click deprecations.

Reproduce backend checks with `.venv/Scripts/python -m pytest -q --basetemp=.pytest_temp/soar-check` and frontend checks from `web` with `npm run typecheck`, `npm test`, and `npm run build`.


## Intelligence engine extension

Migration 0010 adds an optional `observable_id: observable` input and the `enrich_observable` action, which queues read-only intelligence through the existing notification worker and waits durably. Later steps may branch on `intel_verdict`, `intel_confidence`, and `intel_status`. This extends the local-only adapter description above without performing provider network I/O inside a workflow transaction. See [intelligence setup, semantics, and safety limits](intelligence.md). Existing containment approvals are unchanged.
