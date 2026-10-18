# AEGIS TITAN PHASE 3 — STAGING EXECUTION PLAN & HYGIENE REVIEW

**Date:** 2026-10-18  
**Target Branch:** `feature/ironclad-qualification`  
**Remote:** `origin` (`https://github.com/aaryx/AEGIS.git`)  
**Commit Strategy:** Logical, focused commits for verified security fixes, regression tests, and documentation overhaul.

---

## 1. Repository Hygiene & Secret Audit

Before staging any files, a rigorous review of repository state and untracked artifacts was performed:

### 1.1 `.gitignore` Verification
- Confirmed coverage for Python caches (`__pycache__`, `*.pyc`), virtual environments (`.venv`), temporary databases (`*.db`, `*.sqlite`, `.pytest_temp/`), environment secret files (`.env`, `*.key`, `*.pem`), build artifacts (`web/.next/`, `web/out/`), and local logs.

### 1.2 Untracked File Classification
- **Required New Files for Phase 3:**
  - `tests/test_titan_phase3_security_hardening.py`: New regression suite for H-001 through H-004.
  - `docs/validation/project-titan-phase3/`: Phase 3 reports (`REPORT.md`, `CONCURRENCY_MATRIX.md`, `TRANSPORT_SECURITY.md`, `STAGING_EXECUTION_PLAN.md`, `RELEASE_BLOCKERS.md`, `GITHUB_RELEASE.md`).
- **Retained Existing Uncommitted Files from Earlier Phases:**
  - `aegis/containment.py`, `aegis/db_safety.py`, `aegis/endpoint_firewall.py`, `compose.production.yaml`, `docs/operations/opensearch_tls_guide.md`, `docs/validation/ironclad-*/`, `docs/validation/project-titan-*/`, `tests/test_*.py`, `web/tests/containment.test.tsx`.
  - All verified engineering changes from Phase 1 and Phase 2 are preserved and incorporated into the release baseline.
- **Strictly Excluded from Staging:**
  - Local database files (`aegis.db`, `.pytest_temp/`).
  - Generated secrets or local `.env` files.
  - Temporary test logs or coverage dumps.

### 1.3 Secret Scanning
- Ran automated check and verification that no hardcoded passwords, production private keys, or API credentials exist in modified or newly created files.

---

## 2. Modified Files & Component Manifest

The following files contain verified Phase 3 changes:
1. `aegis/pipeline.py`: H-001 pessimistic tenant locking before capacity evaluation.
2. `aegis/security.py`: H-002 canonical lock ordering (`Organization` locked before `AuditHead`).
3. `aegis/api.py`: H-003 pessimistic locking and `ENROLLED` check in `agent_commands` and `agent_receipt`.
4. `aegis/config.py`: H-004 production TLS enforcement for PostgreSQL and Redis; added `redis_ca`.
5. `compose.production.yaml`: H-004 secure production overlay connection defaults.
6. `tests/test_opensearch_hardening.py`: Updated mock test parameters to comply with production TLS schema.
7. `tests/test_titan_phase3_security_hardening.py`: 11 new regression tests verifying H-001 through H-004.
8. `README.md`: Exhaustive, developer- and recruiter-friendly documentation overhaul.
9. `docs/validation/project-titan-phase3/`: 6 Phase 3 validation documents.

---

## 3. Staging and Commit Sequence

### Commit 1: Security Hardening (H-001 to H-004)
- **Message:** `fix(security): resolve H-001 through H-004 concurrency and transport findings`
- **Files Included:**
  - `aegis/pipeline.py`
  - `aegis/security.py`
  - `aegis/api.py`
  - `aegis/config.py`
  - `compose.production.yaml`
  - `tests/test_opensearch_hardening.py`
  - `tests/test_titan_phase3_security_hardening.py`
  - Plus Phase 2 verified security components (`aegis/agent.py`, `aegis/cli.py`, `aegis/db.py`, `aegis/parsers.py`, `aegis/response.py`, `aegis/retention.py`, `aegis/storylines.py`, `aegis/syslog.py`, `aegis/containment.py`, `aegis/db_safety.py`, `aegis/endpoint_firewall.py`, `scripts/`, `tests/`, `web/`).

### Commit 2: Documentation & README Overhaul
- **Message:** `docs(readme): overhaul documentation with architecture and honest status matrix`
- **Files Included:**
  - `README.md`
  - `docs/validation/project-titan-phase3/` (all reports)

---

## 4. Push Verification Steps
1. Execute `git push origin feature/ironclad-qualification`.
2. Inspect push exit code and verify remote tracking reference points to newly created commit SHA.
3. Confirm working tree cleanliness with `git status --short`.
