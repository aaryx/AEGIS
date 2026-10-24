# Security Policy

The AEGIS team takes the security of our SIEM/SOAR platform, its dependencies, and our users' data with the highest priority. This document outlines our vulnerability disclosure policy, response SLAs, and reporting procedures.

---

## Supported Versions

Security updates and patches are actively provided for the following releases:

| Version | Supported | Status |
| :--- | :---: | :--- |
| `0.1.x` (Release Candidate) | :white_check_mark: | Active Qualification Branch (`feature/ironclad-qualification`) |
| `< 0.1.0` (Development) | :x: | Unsupported; please upgrade to the latest qualified commit |

---

## Reporting a Vulnerability

**DO NOT submit security vulnerabilities through public GitHub issues, pull requests, or public discussions.**

If you discover a security vulnerability, privilege escalation, tenant isolation bypass, cryptographic flaw, or sensitive data exposure in AEGIS, please report it confidentially using one of the following methods:

### 1. GitHub Private Vulnerability Reporting (Recommended)
Submit a confidential advisory directly to repository maintainers via GitHub:
**[Submit Private Security Advisory](https://github.com/aaryx/AEGIS/security/advisories/new)**

### 2. Encrypted Email
Contact the primary security maintainer directly:
- **Contact:** Aaryan Singh
- **Email:** `aaryansingh24082005@gmail.com`
- **Subject Line:** `[SECURITY] AEGIS Vulnerability Report - <Brief Component Description>`

---

## What to Include in Your Report

To help us triage and remediate the issue quickly, please provide:
1. **Description:** A detailed explanation of the vulnerability and its potential impact.
2. **Affected Component:** Specific module (`aegis/security.py`, `aegis/api.py`, `aegis/endpoint_firewall.py`, etc.), endpoint, or CLI command.
3. **Proof of Concept:** Step-by-step reproduction instructions or a minimal reproducible script.
4. **Environment:** Operating system, Python/Node.js versions, and deployment mode (local SQLite vs. Docker Compose).
5. **Mitigation:** Any temporary workaround or proposed code fix, if available.

> [!IMPORTANT]
> **Sanitization Requirement:** When submitting proof-of-concept scripts or logs, ensure that all tokens, session cookies, passwords, and private identifiers are completely redacted. Never execute destructive attacks against third-party or production environments.

---

## Vulnerability Handling & Response SLA

Our coordinated disclosure process follows these milestones:

| Milestone | Target Response Time | Action |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | Within 48 hours | Confirm receipt of report and assign a tracking identifier. |
| **Triage & Reproduction** | Within 5 business days | Verify exploitability, assess severity via CVSS v3.1, and scope affected modules. |
| **Remediation & Fix** | Within 14 business days | Author, peer-review, and validate fixes in an isolated security worktree with regression tests. |
| **Public Disclosure** | Coordinated | Publish release advisory and patch release simultaneously following validation. |

---

## Security Architecture & Defensive Invariants

When evaluating potential vulnerabilities, note the following core security invariants enforced in AEGIS:

1. **Server-Side Authorization:** Every sensitive API endpoint enforces role-based access control (RBAC) via `Depends(require(...))`. Frontend UI elements do not substitute for server authorization.
2. **Multi-Tenant Isolation:** Database operations enforce strict organization scoping (`organization_id`). Cross-tenant entity access evaluates uniformly to `404 Not Found` or `403 Forbidden`.
3. **Cryptographic Nonce & Freshness:** Endpoint agent commands are signed with controller Ed25519 keys, evaluated within a 300-second timestamp window, and rejected upon nonce reuse.
4. **Tamper-Evident Hash Chains:** Audit log transitions are linked via HMAC-SHA256 sequential entry hashes coupled to durable `AuditHead` records.
5. **Fail-Closed Active Response:** Endpoint containment applies strict netfilter (`nftables` / `netsh`) drop policies that isolate untrusted network traffic while preserving controller and loopback connectivity. Containment actions require mandatory approval and signed execution receipts.
