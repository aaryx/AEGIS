# AEGIS TITAN Phase 6 — Production Qualification Evidence Matrix

**Date**: 2026-10-20  
**Repository**: `https://github.com/aaryx/AEGIS.git`  
**Branch**: `feature/ironclad-qualification`  
**Phase 6 Engineering Commit**: [`5dba7a08b5f3eb65c192667104ae05d53c3938e3`](https://github.com/aaryx/AEGIS/commit/5dba7a08b5f3eb65c192667104ae05d53c3938e3)  
**Phase 6 Documentation Commit**: [`9edf365a6fef65c71a3e6ffb46f5c5314fbcf260`](https://github.com/aaryx/AEGIS/commit/9edf365a6fef65c71a3e6ffb46f5c5314fbcf260)  
**Verified Remote CI Runs**: [39389299960](https://github.com/aaryx/AEGIS/actions/runs/39389299960) & [39390774035](https://github.com/aaryx/AEGIS/actions/runs/39390774035)  
**Document Ref**: `docs/validation/project-titan-phase6/EVIDENCE_MATRIX.md`  

---

## 1. Evidence Matrix Overview

This matrix catalogs every production qualification requirement, the exact command used to evaluate it, the measured exit status and result, the generated machine-readable artifact, the audit confidence level, and any remaining environmental gaps.

Confidence Taxonomy:
- **HIGH (VERIFIED IN CI / LOCALLY)**: Executed against live operating system sockets, real Linux kernel subsystems, or real disk/process environments.
- **HIGH (MOCKED ONLY)**: Logic, envelope, and error flows validated against realistic API mocks; real cloud credentials required for physical validation.
- **OPEN (BLOCKED)**: Genuinely dependent on external enterprise credentials, bare-metal hardware, or prolonged execution time.

---

## 2. Comprehensive Evidence Matrix

| # | Qualification Requirement | Verification Command | Exit Code / Result | Artifact / Telemetry Location | Confidence Level | Remaining Gap / Required Owner Action |
|:---:|---|---|:---:|---|:---:|---|
| **1** | **Positive TLS Handshake & CA Chain** | `pytest tests/test_phase6_tls_and_rotation.py::test_positive_tls_handshake_with_valid_ca_and_san` | `0` (PASSED in 0.73s) | `tests/test_phase6_tls_and_rotation.py` | **HIGH (VERIFIED LOCALLY)** | Requires issuing certificates from corporate Root CA for staging hostnames. |
| **2** | **Untrusted CA Rejection** | `pytest tests/test_phase6_tls_and_rotation.py::test_negative_tls_untrusted_ca_rejected` | `0` (PASSED) | `tests/test_phase6_tls_and_rotation.py` | **HIGH (VERIFIED LOCALLY)** | None. Fails closed with `SSLCertVerificationError`. |
| **3** | **Hostname Mismatch Rejection** | `pytest tests/test_phase6_tls_and_rotation.py::test_negative_tls_hostname_mismatch_rejected` | `0` (PASSED) | `tests/test_phase6_tls_and_rotation.py` | **HIGH (VERIFIED LOCALLY)** | None. Hostname mismatch rejected fail-closed. |
| **4** | **Expired Certificate Rejection** | `pytest tests/test_phase6_tls_and_rotation.py::test_negative_tls_expired_certificate_rejected` | `0` (PASSED) | `tests/test_phase6_tls_and_rotation.py` | **HIGH (VERIFIED LOCALLY)** | None. Expired certs rejected fail-closed. |
| **5** | **Zero-Downtime Certificate Rotation Drill** | `pytest tests/test_phase6_tls_and_rotation.py::test_certificate_rotation_drill` | `0` (PASSED) | `tests/test_phase6_tls_and_rotation.py` | **HIGH (VERIFIED LOCALLY)** | Requires verifying `pg_reload_conf()` on production PostgreSQL server. |
| **6** | **Redis TLS Client & Reconnection** | `pytest tests/test_phase6_tls_and_rotation.py::test_redis_transport_tls_client_wiring_and_reconnection` | `0` (PASSED) | `tests/test_phase6_tls_and_rotation.py` | **HIGH (VERIFIED LOCALLY)** | Requires production Redis cluster running `--tls-port 6379 --port 0`. |
| **7** | **PostgreSQL libpq TLS Argument Preservation** | `pytest tests/test_phase6_tls_and_rotation.py::test_postgres_connect_kwargs_preserves_libpq_tls_parameters` | `0` (PASSED) | `tests/test_phase6_tls_and_rotation.py` | **HIGH (VERIFIED LOCALLY)** | None. Connection parameters preserved. |
| **8** | **Production Compose & HBA Invariants** | `pytest tests/test_phase6_tls_and_rotation.py::test_production_compose_and_hba_transport_security_invariants` | `0` (PASSED) | `compose.production.yaml`<br/>`deploy/postgres/pg_hba.conf` | **HIGH (VERIFIED LOCALLY)** | None. Confirms `hostnossl reject` and `scram-sha-256`. |
| **9** | **Real Linux Kernel Network Namespace Containment** | `sudo -E env ... bash scripts/test_containment_linux.sh` | `0` (PASSED in CI) | [CI Run 39389299960](https://github.com/aaryx/AEGIS/actions/runs/39389299960)<br/>Job `118516668408` | **HIGH (VERIFIED IN CI)** | Target bare-metal Linux fleet requires verifying local SELinux/AppArmor profiles. |
| **10** | **nftables Kernel Table & Drop Policy** | `sudo -E env ... bash scripts/test_containment_linux.sh` | `0` (PASSED in CI) | `local-data/linux_containment_evidence.json` | **HIGH (VERIFIED IN CI)** | Tested on Ubuntu 24.04 Azure runner kernel; fleet hosts pending canary. |
| **11** | **Ed25519 Signed Receipt Verification** | `pytest tests/test_phase6_containment_logic.py::test_ed25519_receipt_cryptographic_verification` | `0` (PASSED in 0.15s) | `tests/test_phase6_containment_logic.py` | **HIGH (VERIFIED LOCALLY & CI)** | None. Cryptographically verified against public key. |
| **12** | **Tampered Policy Hash Fail-Closed Detection** | `pytest tests/test_phase6_containment_logic.py::test_mismatched_policy_hash_fails_closed` | `0` (PASSED) | `tests/test_phase6_containment_logic.py` | **HIGH (VERIFIED LOCALLY & CI)** | None. Mismatches evaluate to `UNKNOWN`. |
| **13** | **Quarantine Release & Table Teardown** | `sudo -E env ... bash scripts/test_containment_linux.sh` | `0` (PASSED in CI) | `local-data/linux_containment_evidence.json` | **HIGH (VERIFIED IN CI)** | None. Table confirmed deleted via `snapshot() is None`. |
| **14** | **Multi-Worker Concurrency (4 OS Processes)** | `python scripts/soak_test.py --workers 4 --duration 15 --rate 100` | `0` (PASSED in 15.94s) | `local-data/soak_results.json` | **HIGH (VERIFIED LOCALLY)** | 4 distinct OS processes actively and concurrently processed batches. |
| **15** | **Multi-Tenant Ingestion & Isolation Under Load** | `python scripts/soak_test.py --workers 4 --duration 15 --rate 100` | `0` (PASSED, 0 leaks) | `local-data/soak_results.json` | **HIGH (VERIFIED LOCALLY)** | 4 isolated tenant organizations verified with zero cross-tenant contamination. |
| **16** | **High Throughput Telemetry Benchmark** | `python scripts/soak_test.py --workers 4 --duration 15 --rate 100` | `0` (1,160 events, 70.25 EPS) | `local-data/soak_results.json`<br/>`local-data/soak_checkpoints.json` | **HIGH (VERIFIED LOCALLY)** | 70.25?86.59 EPS achieved on SQLite (Windows lock ceiling). Requires PostgreSQL for 100+ EPS. |
| **16b** | **Windows 64-bit Process RSS, Telemetry Gate & False-Pass Hardening** | `pytest tests/test_phase6_soak_harness.py` | `0` (17 passed in 49.66s) | `tests/test_phase6_soak_harness.py`<br/>`scripts/soak_test.py` | **HIGH (VERIFIED IN WORKING TREE)** | Explicit ctypes handle signatures fix 64-bit RSS capture (`float | None`); pre-stop event drain eliminates unconsumed items; false-pass prevention strictly gates unconsumed work, reconciliation mismatch, worker crash, or missing telemetry; `--checkpoint-interval`, `--checkpoint-file`, and `--allow-missing-telemetry` CLI flags added. Uncommitted in working tree. |
| **17** | **Multi-Tenant Audit Chain Durability** | `python scripts/soak_test.py --workers 4 --duration 15 --rate 100` | `0` (4/4 valid) | `local-data/soak_results.json` | **HIGH (VERIFIED LOCALLY)** | 100% HMAC chain continuity verified across all tenants post-load. |
| **18** | **24-Hour Continuous Multi-Worker Soak Run** | Documented resumable staging command | `NOT EXECUTED` | `scripts/soak_test.py` | **OPEN (BLOCKED BY EXECUTION TIME)** | Operator must execute 24h command on persistent staging VM. |
| **19** | **Authenticated Backup Envelope (`AGBK` v1)** | `pytest tests/test_phase6_cloud_backup_and_recovery.py::test_encrypted_backup_creation_and_cold_restore_drill` | `0` (PASSED in 0.82s) | `tests/test_phase6_cloud_backup_and_recovery.py` | **HIGH (VERIFIED LOCALLY & CI)** | None. Fernet AES-128-CBC + PBKDF2 100k verified. |
| **20** | **Cold DB Restore & 100% Reconciliation** | `pytest tests/test_phase6_cloud_backup_and_recovery.py::test_encrypted_backup_creation_and_cold_restore_drill` | `0` (PASSED) | `tests/test_phase6_cloud_backup_and_recovery.py` | **HIGH (VERIFIED LOCALLY & CI)** | Restored fresh isolated database with 100% row count reconciliation and valid audit chains. |
| **21** | **Tamper Rejection (Ciphertext & Checksum)** | `pytest tests/test_phase6_cloud_backup_and_recovery.py::test_restore_rejection_corrupted_ciphertext` | `0` (PASSED) | `tests/test_phase6_cloud_backup_and_recovery.py` | **HIGH (VERIFIED LOCALLY & CI)** | Rejects wrong key, altered ciphertext, and tampered pre-encryption SHA-256 header digest. |
| **22** | **S3 KMS & Object Lock WORM Adapter** | `pytest tests/test_phase6_cloud_backup_and_recovery.py::test_mock_s3_backup_upload_with_kms_encryption_and_object_lock` | `0` (PASSED) | `tests/test_phase6_cloud_backup_and_recovery.py` | **HIGH (MOCKED ONLY)** | Requires physical AWS credentials with KMS and Object Lock WORM bucket. |
| **23** | **GCS CMEK Storage Adapter** | `pytest tests/test_phase6_cloud_backup_and_recovery.py::test_mock_gcs_backup_upload_with_cmek` | `0` (PASSED) | `tests/test_phase6_cloud_backup_and_recovery.py` | **HIGH (MOCKED ONLY)** | Requires physical GCP credentials with Cloud KMS CMEK key. |
| **24** | **Static Analysis, Linters & Typecheck** | `ruff check aegis tests scripts`<br/>`mypy aegis`<br/>`bandit -r aegis scripts -ll -q` | `0` (0 errors across all tools) | Terminal & CI logs | **HIGH (VERIFIED LOCALLY & CI)** | Zero lint, type, or security warnings in codebase. |
| **25** | **Dependency Security Audits** | `pip_audit --skip-editable`<br/>`npm --prefix web audit` | `0` (0 vulnerabilities) | Terminal & CI logs | **HIGH (VERIFIED LOCALLY & CI)** | Clean dependency tree across Python and Node.js (`requirements.lock` updated: certifi 2026.10.23, filelock 4.2.4; web: next 16.4.3, vitest 4.1.12, undici 7.30.1, vite 8.3.5 resolving all 5 npm advisories). |
| **26** | **Frontend Tests, Typecheck & Production Build** | `npm --prefix web test`<br/>`npm --prefix web run typecheck`<br/>`npm --prefix web run build` | `0` (35 passed, 0 errors, build success) | Web `dist/` bundle | **HIGH (VERIFIED LOCALLY & CI)** | Next.js 16 Turbopack production bundle compiled successfully. |
| **27** | **Remote GitHub Actions Full CI Pipeline** | `gh run view 39390774035` | `0` (SUCCESS in 10m23s) | [CI Run 39390774035](https://github.com/aaryx/AEGIS/actions/runs/39390774035) | **HIGH (VERIFIED IN CI)** | End-to-end regression, drills, containerized integration, and kernel containment verified. |

---

## 3. Summary of Environmental Qualifications vs Blockers

| Domain | Tested & Qualified Scope | Unqualified / Open Scope | Action Required to Close |
|---|---|---|---|
| **Transport TLS** | Client connection pool logic, loopback TLS handshakes, rotation drills, untrusted/expired cert rejection. | Production enterprise PKI certificates (`*.aegis.internal`) mounted to live containers. | Operator mounts signed certs and reloads daemons. |
| **Linux Containment** | Ephemeral network namespace, `/usr/sbin/nft` drop rules, loopback/controller whitelist, signed Ed25519 receipts, rollback. | Live production enterprise Linux host fleet with custom AppArmor/SELinux profiles. | Operator runs agent containment canary on staging host. |
| **Multi-Worker Soak** | 4-worker multiprocessing harness, multi-tenant synthetic ingestion, rate control, checkpoints, audit durability (1,380 events in 15.9s). | Continuous uninterrupted 24-hour run. | Operator launches background 24h run on staging server. |
| **Cloud Disaster Recovery** | `AGBK` v1 authenticated encryption, cold database restore, 100% row reconciliation, audit verification, S3/GCS mock adapters. | Physical AWS S3 Object Lock / GCP Cloud Storage buckets and KMS keys. | Operator provisions cloud bucket with Object Lock and executes one drill. |
