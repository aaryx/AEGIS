# AEGIS Security Testing & Verification Methodology

## 1. Automated Security Gates

The AEGIS CI/CD pipeline and local verification toolchain enforce mandatory automated security gates:

```bash
# 1. Static Application Security Testing (SAST)
ruff check .
python -m mypy aegis tests scripts

# 2. Automated Vulnerability Scanning
bandit -r aegis
pip-audit

# 3. Security Test Suite Execution
pytest tests/test_security.py tests/test_hardening.py tests/test_agent.py tests/test_retention.py
```

---

## 2. Threat Verification Test Cases

| Target Vulnerability | Test Implementation | Expected Verification Result |
|---|---|---|
| **Argon2id CPU DoS** | `test_security.py::test_timing_and_credential_defense` | Invalid usernames verify against constant-time dummy hash; zero CPU spikes or dynamic Argon2id hashing on missing accounts. |
| **Cross-Tenant Access (IDOR)** | `test_security.py::test_cross_tenant_isolation` | Requests attempting to query or modify entities, alerts, rules, or events belonging to another tenant receive `404 Not Found` or `403 Forbidden`. |
| **Self-Approval in SOAR** | `test_security.py::test_playbook_approval_workflow` | Requesters cannot approve their own playbook request; API returns `403 A different human operator must approve`. |
| **Agent Receipt Tampering** | `test_agent.py::test_agent_api_registration_and_containment_lifecycle` | Controller computes canonical hash of receipt result and rejects invalid or forged hashes with `400 Bad Request`. |
| **Audit Log Tampering** | `test_security.py::test_tamper_evident_audit_log` | Direct SQL mutation, truncation, or gap in audit chain is caught immediately by `verify_audit()` returning `False`. |
| **SSRF via Webhooks** | `test_integrations.py::test_ssrf_prohibited_destinations` | Outbound requests targeting link-local, multicast, or private IPs in production throw `ValueError("Integration resolved to a prohibited address")`. |
| **CSV Formula Injection** | `test_security.py::test_export_csv_formula_injection` | Cells starting with `=`, `+`, `-`, `@`, `\t`, `\r`, `%` are prefixed with `'` to neutralize execution in Excel and LibreOffice Calc. |
| **Legal Hold Bypass** | `test_retention.py::test_retention_dry_run_and_execution_with_legal_hold` | Events attached to open cases or active alerts are preserved during retention cleanup; non-held expired records are pruned. |
