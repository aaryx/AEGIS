# TITAN Phase 2 — Implementation & Fix Log

This log details the exact implementation modifications, architectural design decisions, and associated regression tests created during Phase 2 security hardening.

---

## 1. Truthful Endpoint Containment & Execution State Lifecycle (F-003)

### Defect
Simulated host isolation or command failures were recorded by the controller as verified external enforcements (`enforced_externally=True`, `status="VERIFIED"`), leading to false confidence in incident response.

### Implementation Changes
1. **Created `aegis/containment.py`**:
   - `receipt_outcome(action, status, result)`: Evaluates executed action, reported status, and execution details.
     - Returns `"FAILED"` if status is not `"SUCCESS"`.
     - Returns `"SIMULATED"` if `result.get("mode") == "simulated"`.
     - Returns `"ENFORCED"` (or `"RELEASED"`) only if `result.get("mode") == "live"`, `backend == "nftables-v1"`, `verified == True`, and `observed_sha256 == policy_sha256`.
     - Returns `"UNKNOWN"` for any unverified or ambiguous result.
   - `execution_containment_status(status, result)`: Maps playbook execution records to containment status without rewriting historical rows.
2. **Updated `aegis/api.py` (`agent_receipt`, `playbook_execute`, `list_agents`)**:
   - Atomic conditional update using `PlaybookExecution.status.in_(["APPROVED", "DISPATCHED"])` and `revision == initial_revision`.
   - Binds `target_result` with `semantics_version: 2`, `enforced_externally: (target_status == "ENFORCED")`, and `scope: "endpoint-simulation"` or `"agent-reported"`.
   - Updates `Entity` attributes and `Agent` model to explicit status (`SIMULATED`, `ENFORCED`, `RELEASED`, `FAILED`, `UNKNOWN`).
   - Audit logging captures `containment_status` and `enforced_externally`.
3. **Updated `aegis/response.py` (`execute`)**:
   - Sets dispatched containment actions to `containment_status: "UNKNOWN"` and `verified: False` pending authenticated endpoint receipt.
   - Prevents concurrent conflicting dispatches against the same endpoint target.
4. **Updated `aegis/cli.py`**:
   - Formats playbook table output to display truthful `containment_status` rather than generic `VERIFIED`.
   - Agent status defaults to `UNKNOWN` until verified.
5. **Updated `web/components/ui.tsx`**:
   - Displays `row.containment_status ?? row[field]` in `DataTable` component.

### Regression Tests
- `tests/test_endpoint_containment.py`:
  - `test_simulation_is_truthful_in_receipt_heartbeat_audit_and_api`
  - `test_failed_or_timed_out_action_never_becomes_enforced`
  - `test_authentic_but_unsubstantiated_receipt_is_unknown`
  - `test_heartbeat_cannot_forge_enforcement_or_replace_key`
  - `test_missing_receipt_preserves_dispatched_state`
  - `test_historical_verified_record_remains_unchanged_and_unqualified`
- `web/tests/containment.test.tsx`:
  - Tests rendering of `SIMULATED`, `ENFORCED`, `FAILED`, `UNKNOWN`, `RELEASED` without treating `VERIFIED` as enforcement.

---

## 2. Linux Isolation Restrictiveness & Safe Unisolation (F-004)

### Defect
Agent isolation lacked blocking rules (only appended ACCEPT), and unisolation executed a dangerous global flush (`iptables -F`), wiping unrelated administrator firewall rules.

### Implementation Changes
1. **Created `aegis/endpoint_firewall.py` (`LinuxContainment`)**:
   - Restricts isolation to key-owned `nftables` table named `aegis_<sha256(agent_id)[:24]>`.
   - Adds comment `aegis-v1:<sha256(agent_id)>` for cryptographic ownership attribution.
   - Applies strict `drop` policy to `input`, `output`, and `forward` chains in the dedicated table.
   - Whitelists only loopback interface (`lo`) and bidirectional TCP communication with the controller IP and port.
   - Enforces kernel readback verification before and after apply (`observed_sha256 == policy_sha256`).
   - Unisolation executes atomic single-table removal: `delete table inet aegis_<hash>`. Never calls `-F` on global tables.
   - Idempotent: repeated apply or unisolation produces no redundant Netlink transactions.
   - Exclusive lock: acquires non-blocking `fcntl.flock` on `/run/aegis-containment.lock` (mode 0600) to prevent races.
2. **Updated `aegis/agent.py` (`_network_action`, `execute_command`)**:
   - Prohibits live firewall actions unless explicitly opted in (`allow_network_policy=True`), running on Linux, and using HTTPS controller URL.
   - Safe fallback prohibited: any failure raises `ContainmentError`, resetting state to `UNKNOWN`.
   - Caches signed execution receipts in memory to ensure transport retries return identical idempotent outcomes without re-executing firewall rules.

### Regression Tests
- `tests/test_endpoint_containment.py`:
  - `test_owned_policy_is_idempotent_and_release_preserves_admin_rules`
  - `test_modified_owned_table_is_never_changed`
  - `test_injected_or_unsupported_controller_rejected`
  - `test_missing_capability_fails_without_mutation`
  - `test_nft_transport_has_timeout_and_no_shell`
  - `test_live_actions_require_explicit_policy_and_never_fallback`
  - `test_signed_mock_kernel_readback_records_explicit_outcome`
  - `test_policy_readback_failure_never_claims_success`
  - `test_command_cannot_override_operator_firewall_exception`

---

## 3. Database URL Safety & Parameter Validation (F-001)

### Defect
Validation trusted the URL string path, allowing libpq options like `?dbname=aegis` or `?host=production.internal` to redirect test connections to live operational databases.

### Implementation Changes
1. **Created `aegis/db_safety.py` (`validate_test_database_url`, `ensure_isolated_test_database`)**:
   - Uses SQLAlchemy `make_url` to parse connection target.
   - Whitelists allowed connection options (`sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `connect_timeout`, `application_name`).
   - Rejects any query options on SQLite.
   - Enforces test database naming token (`test` in name parts) and blocks disallowed operational names (`aegis`, `production`, `master`, etc.).
   - Rejects ambient environment overrides (`PGSERVICE`, `PGSERVICEFILE`, `PGHOSTADDR`, `PGOPTIONS`).
   - Disallows remote/cloud hosts unless `AEGIS_ALLOW_REMOTE_TEST_DB=1` is explicitly set.
   - Auto-provisioning helper parameterizes `CREATE DATABASE` with SQL identifier quoting.

### Regression Tests
- `tests/test_database_safety.py` (36 tests)
- `tests/test_titan_regressions.py` (database target override tests)

---

## 4. Cross-Host Receipt Attestation Defense (F-002)

### Defect
The controller accepted signed receipts from any authenticated agent for commands targeting other hosts in the same tenant.

### Implementation Changes
1. **Updated `aegis/api.py` (`agent_receipt`)**:
   - Validates that `data.receipt.get("agent_id")` matches the enrolled agent identifier or host name.
   - Validates that `execution.target` matches the agent's host entity.
   - Verifies controller signature binding on dispatched execution envelopes.

### Regression Tests
- `tests/test_titan_regressions.py::test_signed_receipt_cannot_complete_another_hosts_command`
- `tests/test_endpoint_containment.py::test_wrong_endpoint_with_enrolled_agent_token_cannot_acknowledge`

---

## 5. Diagnostic Credential Sanitization (F-006)

### Defect
PostgreSQL connection failure diagnostics interpolated raw `POSTGRES_TEST_URL` (including plaintext passwords) into `pytest.skip` messages, and `scripts/integration_gate.py` printed unredacted exception strings and streamed child process output.

### Implementation Changes
1. **Updated `tests/test_postgres_integration.py` (`pg_engine`)**:
   - Replaced raw URL and raw exception string in `pytest.skip` with sanitized metadata: `f"{parsed.host}:{parsed.port}/{parsed.database} ({type(exc).__name__})"`.
2. **Updated `scripts/integration_gate.py` (`main`)**:
   - Exception handling in database preparation scrubs `postgres_pass` and reports `type(exc).__name__`.
   - Streaming loop dynamically scrubs `postgres_pass`, `redis_pass`, and `opensearch_pass` before writing to `sys.stdout` and buffering output lines.

### Regression Tests
- `tests/test_titan_regressions.py::test_postgres_integration_diagnostic_skip_sanitizes_credentials`
- `tests/test_ci_release_gate.py::test_gate_sanitizes_database_preparation_exception`
- `tests/test_ci_release_gate.py::test_gate_redacts_credentials_from_child_output`

---

## 6. OpenSearch Production TLS Configuration (F-005)

### Defect
`compose.production.yaml` defined `OPENSEARCH_CA` in the application environment but did not mount the CA certificate into application containers.

### Implementation Changes
1. **Updated `compose.production.yaml` (`x-app-production`)**:
   - Added read-only bind mount `./certs/opensearch/root-ca.pem` -> `/usr/share/aegis/certs/root-ca.pem` with `create_host_path: false`.
   - Ensured no node private keys are mounted into application services.

### Regression Tests
- `tests/test_titan_regressions.py::test_production_application_services_mount_only_public_ca`
