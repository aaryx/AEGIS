# TITAN Phase 2 — Test Matrix & Verification Evidence

This document records the complete execution matrix, test suites, exact commands, exit codes, passed/skipped/failed metrics, durations, infrastructure dependencies, and limitations.

---

## 1. Test Execution Summary

| Suite / Check | Command | Exit Code | Passed | Skipped | Failed | Duration | Environment / Mocking |
|---|---|---|---|---|---|---|---|
| **Containment Regressions** | `.venv/Scripts/python -m pytest tests/test_endpoint_containment.py -v -p no:cacheprovider` | 0 | 35 | 0 | 0 | 13.20s | Mocked Netlink & Subprocess |
| **Titan Target Boundaries** | `.venv/Scripts/python -m pytest tests/test_titan_regressions.py -v -p no:cacheprovider` | 0 | 15 | 0 | 0 | 1.34s | Mocked DB & Offline YAML |
| **Database Safety** | `.venv/Scripts/python -m pytest tests/test_database_safety.py -q -p no:cacheprovider` | 0 | 36 | 0 | 0 | 0.82s | Offline Unit Tests |
| **CI Release Gate & Secrets** | `.venv/Scripts/python -m pytest tests/test_ci_release_gate.py -v -p no:cacheprovider` | 0 | 18 | 0 | 0 | 1.15s | Mocked Subprocess & Port Checks |
| **Agent Core & Security** | `.venv/Scripts/python -m pytest tests/test_agent.py tests/test_agent_security.py tests/test_agent_nonce_replay_invariant.py -q -p no:cacheprovider` | 0 | 25 | 0 | 0 | 8.52s | SQLite & Memory |
| **SOC E2E Acceptance** | `.venv/Scripts/python -m pytest tests/test_soc_end_to_end_acceptance.py tests/test_ironclad_qualification.py -q -p no:cacheprovider` | 0 | 11 | 0 | 0 | 12.63s | SQLite & Memory |
| **Full Backend Suite** | `.venv/Scripts/python -m pytest tests -q -p no:cacheprovider --junitxml=docs/validation/project-titan-phase2/full.xml` | 0 | 495 | 27 | 0 | 216.22s (3m 36s) | Offline / Mocked Services |
| **Frontend Unit & UI** | `npm test` (in `web/`) | 0 | 35 | 0 | 0 | 4.23s | Vitest & React Testing Library |
| **Frontend Production Build** | `npm run build` (in `web/`) | 0 | Completed | 0 | 0 | 4.90s | Next.js Turbopack Prerender |
| **Code Style & Linting** | `.venv/Scripts/python -m ruff check aegis tests scripts` | 0 | All passed | 0 | 0 | 0.45s | Local Source Tree |
| **Static Type Verification** | `.venv/Scripts/python -m mypy aegis` | 0 | 41 source files | 0 | 0 | 1.62s | Local Source Tree |
| **Static Security Analysis** | `.venv/Scripts/python -m bandit -r aegis -ll` | 0 | 0 issues (0 Med, 0 High) | 0 | 0 | 1.25s | Local Source Tree |

---

## 2. Infrastructure-Dependent Skipped Tests (27 Total)

All 27 skips across the 522 collected backend tests are strictly accounted for by missing external database and search engine daemon infrastructure. No test was skipped due to application failure or broken assertions.

| Test File | Test Name | Skip Reason | Required Live Infrastructure |
|---|---|---|---|
| `tests/test_integration.py` | `test_real_dependency_connectivity` | `Set AEGIS_INTEGRATION=1 with PostgreSQL, Redis and OpenSearch configured` | Live PostgreSQL, Redis, OpenSearch |
| `tests/test_integration.py` | `test_real_redis_queue_semantics_and_delivery` | `Set AEGIS_INTEGRATION=1 with PostgreSQL, Redis and OpenSearch configured` | Live Redis 7.x |
| `tests/test_postgres_integration.py` | `test_postgres_cerberus_concurrent_evidence_conflict[False]` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_cerberus_concurrent_evidence_conflict[True]` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_concurrent_rate_limiting` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_multiprocess_concurrent_audit_writes` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_concurrent_audit_writes_and_chain_integrity` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_concurrent_detection_window_appends` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_transaction_rollback_and_retry_behavior` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_worker_restart_and_duplicate_event_handling` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_simultaneous_duplicate_event_ingestion_race` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_multi_tenant_concurrent_audit_isolation` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_concurrent_entity_and_relationship_upserts` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_lock_timeout_and_abort_recovery` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_schema_migration_previous_to_current` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_concurrent_rule_activation_and_replay` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_concurrent_storyline_correlation` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_soar_transactional_concurrency` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_ioc_cache_and_lookup_persistence` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_soar_approval_and_recovery_persistence` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_opensearch_indexing_and_isolation` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x & OpenSearch 2.x |
| `tests/test_postgres_integration.py` | `test_postgres_cross_tenant_database_constraints` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_postgres_integration.py` | `test_postgres_full_e2e_ioc_to_soar_simulated_containment_pipeline` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_ueba_live.py` | `test_live_ingest_to_ueba_evidence_actions_and_storyline` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_ueba_live.py` | `test_live_concurrent_submission_and_workers` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_ueba_live.py` | `test_live_worker_rollback_and_retry` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |
| `tests/test_ueba_live.py` | `test_live_scoped_keys_and_composite_tenant_constraints` | `AEGIS_POSTGRES_TEST_URL environment variable not configured` | Live PostgreSQL 16.x |

---

## 3. Evidence Classification Breakdown

- **Independently Reproduced & Verified:**
  - F-001 (DB URL target override)
  - F-002 (Wrong host attestation via receipt)
  - F-003 (Simulated containment reported as enforced)
  - F-004 (Destructive unisolation & missing isolation drop policy)
  - F-005 (Production app CA missing mount)
  - F-006 (Diagnostic credential leakage in pytest.skip and gate error)
- **Mocked / Simulated Evidence (Not Real Host Modification):**
  - All 35 tests in `tests/test_endpoint_containment.py` mock the `/usr/sbin/nft` subprocess execution.
  - The developer's host network rules and tables were never modified.
- **Blocked by Missing External Infrastructure:**
  - Live PostgreSQL 16 multi-worker concurrency and lock contention tests.
  - Live Redis 7 queue backpressure and delivery tests.
  - Live OpenSearch TLS 1.3 mutual handshake and cluster bootstrap tests.
  - Disposable Linux VM network namespace live firewall ruleset apply/rollback tests.
