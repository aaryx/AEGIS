# TITAN Phase 2 — Defect Register & Security Findings

This register documents all confirmed findings, severities, evidence, and resolution status evaluated during Phase 2 audit and hardening.

---

## F-001 — HIGH — Test Database Connection Target Bypass
- **Classification:** Independently reproduced | Fixed and regression-tested
- **Component:** `aegis/db_safety.py:validate_test_database_url`
- **Description:** Operator-supplied test URLs containing libpq query parameters (e.g. `?dbname=aegis`, `?host=production.internal`, `?service=production`) could bypass string checks and direct test migrations or writes against operational data.
- **Evidence:** `tests/test_titan_regressions.py:test_database_target_override_rejected` and `test_ambiguous_test_database_rejected`.
- **Resolution:** Validates parsed SQLAlchemy connection target, strictly restricts allowed query parameters (`sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `connect_timeout`, `application_name`), rejects ambient libpq environment overrides, requires single explicit local host unless explicitly overridden, and parameterizes SQL identifiers.
- **Status:** **FIXED & REGRESSION TESTED (Offline)**.

---

## F-002 — HIGH — Cross-Host Command Attestation via Unbound Receipt
- **Component:** `aegis/api.py:agent_receipt`
- **Classification:** Independently reproduced | Fixed and regression-tested
- **Description:** A compromised or validly signed agent key from host B could acknowledge a command dispatched to host A within the same tenant, marking the command VERIFIED and mutating containment state.
- **Evidence:** `tests/test_titan_regressions.py:test_signed_receipt_cannot_complete_another_hosts_command` and `tests/test_endpoint_containment.py:test_wrong_endpoint_with_enrolled_agent_token_cannot_acknowledge`.
- **Resolution:** `aegis/api.py` resolves tenant-owned agent identity and enforces that `receipt.agent_id` strictly matches the enrolled agent identifier and name before accepting receipt.
- **Status:** **FIXED & REGRESSION TESTED (Offline/Mocked)**.

---

## F-003 — HIGH — Simulated or Failed Endpoint Containment Recorded as Real Enforcement
- **Component:** `aegis/agent.py`, `aegis/api.py`, `aegis/response.py`, `aegis/containment.py`, `web/components/ui.tsx`, `aegis/cli.py`
- **Classification:** Independently reproduced | Fixed and regression-tested
- **Description:** Default simulation mode or live isolation failures previously returned receipts that the controller marked as `enforced_externally=True`, `scope=endpoint-live`, and host status `ISOLATED`. Responders and UI were misled into believing containment was active when no firewall rules were installed.
- **Evidence:**
  - `tests/test_endpoint_containment.py::test_simulation_is_truthful_in_receipt_heartbeat_audit_and_api`
  - `tests/test_endpoint_containment.py::test_failed_or_timed_out_action_never_becomes_enforced`
  - `tests/test_endpoint_containment.py::test_authentic_but_unsubstantiated_receipt_is_unknown`
  - `web/tests/containment.test.tsx`
- **Resolution:**
  1. Created `aegis/containment.py` implementing truthful state transitions (`REQUESTED`, `APPROVED`, `DISPATCHED`, `SIMULATED`, `ENFORCED`, `FAILED`, `UNKNOWN`, `RELEASED`).
  2. Simulation mode records `mode=simulated`, `outcome=SIMULATED`, `enforced_externally=False`, `scope=endpoint-simulation`.
  3. Live isolation failures record `outcome=FAILED`, leaving host isolation state as `UNKNOWN` rather than `ISOLATED`.
  4. Real enforcement requires verified kernel readback matching cryptographic policy hash (`observed_sha256 == policy_sha256`).
  5. API, Entity attributes, Agent records, Audit logs, CLI table output, and Web UI `DataTable` consistently reflect explicit containment state.
  6. Historical `VERIFIED` records are preserved and mapped to `UNKNOWN` containment status without rewriting historical database records.
- **Status:** **FIXED & REGRESSION TESTED (Offline/Mocked)**.

---

## F-004 — HIGH — Destructive Linux Firewall Flush & Ineffective Isolation Policy
- **Component:** `aegis/agent.py`, `aegis/endpoint_firewall.py`
- **Classification:** Independently reproduced | Fixed and regression-tested (Mocked Netlink)
- **Description:** Previous agent isolation only appended ACCEPT rules without a DROP policy, allowing egress/ingress traffic to continue. Unisolation executed `iptables -F`, dangerously flushing all administrator-managed firewall rules across the host.
- **Evidence:** Source code analysis of `aegis/agent.py:unisolate_host` and `isolate_host`. Verified on mocked netlink transactions in `tests/test_endpoint_containment.py::test_owned_policy_is_idempotent_and_release_preserves_admin_rules`.
- **Resolution:**
  1. Replaced arbitrary iptables shell calls with `aegis/endpoint_firewall.py:LinuxContainment` utilizing key-owned `nftables-v1` netlink JSON commands.
  2. Table name is deterministically bound to agent identity (`aegis_<sha256(agent_id)[:24]>`).
  3. Base chains (`input`, `output`, `forward`) apply strict `drop` policy.
  4. Only allows loopback and TCP communication with the designated AEGIS controller IP and port.
  5. Unisolation deletes only the exact AEGIS-owned table (`delete table inet <table_name>`); never flushes global tables or touches administrator-managed chains.
  6. Readback snapshot verification guarantees kernel state matches expected policy hash.
  7. Atomic flock lock on `/run/aegis-containment.lock` prevents concurrent modification races.
  8. Live firewall modification requires explicit opt-in (`--allow-network-policy`) and HTTPS controller URL; dry-run/simulation never touches host network stack.
- **Status:** **FIXED & REGRESSION TESTED (Mocked Subprocess)**. *Note: Live Linux VM network namespace testing is required before production deployment.*

---

## F-005 — MEDIUM — Application CA Certificate Missing in Production Container Overlay
- **Component:** `compose.production.yaml:x-app-production`
- **Classification:** Independently reproduced | Fixed and regression-tested (Static)
- **Description:** `compose.production.yaml` defined `OPENSEARCH_CA` path in application environment but mounted certificates exclusively into OpenSearch containers, causing TLS handshake failure upon container startup.
- **Evidence:** `tests/test_titan_regressions.py::test_production_application_services_mount_only_public_ca`.
- **Resolution:** Added read-only bind mount of public root CA (`./certs/opensearch/root-ca.pem`) into API, worker, initialize, retention, and notifications services. No private keys are exposed to application containers.
- **Status:** **FIXED & REGRESSION TESTED (Static YAML Configuration)**. *Note: Live OpenSearch TLS handshake remains blocked by missing cluster infrastructure.*

---

## F-006 — MEDIUM — Integration Failure Diagnostics Can Expose Database Credentials
- **Component:** `tests/test_postgres_integration.py:pg_engine`, `scripts/integration_gate.py:main`
- **Classification:** Independently reproduced | Fixed and regression-tested
- **Description:**
  1. When PostgreSQL was unreachable, `pg_engine` in `tests/test_postgres_integration.py` skipped tests with `pytest.skip(f"PostgreSQL test instance unavailable at {POSTGRES_TEST_URL}: {exc}")`, which printed raw connection strings including passwords into console output and JUnit XML test reports.
  2. In `scripts/integration_gate.py`, unhandled database preparation exceptions printed raw exception messages to stderr, and child pytest stdout was streamed without secret redaction.
- **Evidence:**
  - `tests/test_titan_regressions.py::test_postgres_integration_diagnostic_skip_sanitizes_credentials`
  - `tests/test_ci_release_gate.py::test_gate_sanitizes_database_preparation_exception`
  - `tests/test_ci_release_gate.py::test_gate_redacts_credentials_from_child_output`
- **Resolution:**
  1. Updated `pg_engine` to sanitize target diagnostics using parsed `host:port/database` metadata and exception class name only; never interpolates raw URL or exception message.
  2. Updated `scripts/integration_gate.py` to scrub `postgres_pass`, `redis_pass`, and `opensearch_pass` from all streamed child process lines and database preparation error diagnostics.
- **Status:** **FIXED & REGRESSION TESTED (Offline/Mocked)**.

---

## F-007 — INFORMATIONAL — Qualification Evidence Overstates Deployment Guarantees
- **Component:** Qualification documentation (`docs/validation/ironclad-phase7/REPORT.md`, `STATUS.md`)
- **Classification:** Independently reproduced | Documented & Clarified
- **Description:** Previous reports treated SQLite and mocked integration tests as live PostgreSQL and distributed cluster proof.
- **Resolution:** This audit explicitly separates offline/mocked unit tests from live staging integration.
- **Status:** **DOCUMENTED & CLARIFIED**.

---

## Hypotheses & Standing Operational Risks

- **H-001 (Ingest Concurrency Backpressure):** Concurrent ingest counting before insert can exceed `queue_capacity` under high worker contention.
- **H-002 (Lock Ordering & Deadlocks):** Lock ordering across tenant, audit head, and window state requires verification under multi-worker PostgreSQL load.
- **H-003 (Agent Key Revocation Race):** Agent key rotation or revocation concurrently racing command receipt processing requires deterministic PostgreSQL race validation.
- **H-004 (Transport Gate Encryption):** PostgreSQL and Redis transport encryption (TLS) is not enforced by default settings. Production deployment requires mandatory transport encryption.
