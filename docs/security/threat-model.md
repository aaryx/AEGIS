# AEGIS Security Threat Model & Trust Boundaries

**Target System**: AEGIS SIEM/SOAR Platform  
**Architecture Profile**: Multi-tenant distributed SIEM with endpoint response agent, deterministic detection engine, evidence-grounded AI advisory layer, and immutable audit trail.  

---

## 1. Trust Boundaries and System Context

```
+-----------------------------------------------------------------------------------+
| UNTRUSTED EXTERNAL PERIMETER                                                      |
|   Telemetry Sources (Syslog/REST), External Webhook Endpoints, Browser Clients    |
+-----------------------------------------------------------------------------------+
                                    | (TLS 1.3 / API Keys / Session Cookies)
                                    v
+-----------------------------------------------------------------------------------+
| TRUST BOUNDARY 1: API & Ingestion Gateways (FastAPI, Rate Limiting, Schemas)      |
|   - Strict request body byte bounds (64KB event, 2MB request)                     |
|   - Timing-safe Argon2id authentication with constant-time dummy hash             |
|   - Tenant-scoped JWT / SessionToken authorization with RBAC                      |
|   - SSRF-hardened egress client (Loopback / Private IP / Metadata blocked)        |
+-----------------------------------------------------------------------------------+
                                    | (PostgreSQL connection pool / Redis / OpenSearch)
                                    v
+-----------------------------------------------------------------------------------+
| TRUST BOUNDARY 2: Core State & Durable Persistence                                |
|   - aegis_runtime: SELECT, INSERT, UPDATE on operational tables                   |
|     * REVOKE DELETE ON events_metadata                                            |
|     * REVOKE UPDATE, DELETE ON audit_logs (append-only)                           |
|   - aegis_maintenance: Narrowly scoped retention pruning                         |
|     * REVOKE UPDATE, DELETE ON audit_logs (audit chain strictly protected)        |
|     * Bounded batch pruning respecting Legal Hold (CaseEvidence, active alerts)   |
+-----------------------------------------------------------------------------------+
                                    | (Authenticated Command Channel / Signed Receipts)
                                    v
+-----------------------------------------------------------------------------------+
| TRUST BOUNDARY 3: SOAR & Endpoint Agent Execution                                 |
|   - Mandatory two-person independent human approval on HIGH_IMPACT actions        |
|   - Self-approval strictly prohibited; approval expiration enforced               |
|   - User-space endpoint daemon: netsh/iptables network containment                |
|   - Controller IP allowlisting before deny-all rules applied                      |
|   - Cryptographic HMAC/SHA-256 execution receipts verified by controller API      |
+-----------------------------------------------------------------------------------+
```

---

## 2. Threat Analysis Matrix (STRIDE)

| Threat Category | Attack Vector / Scenario | Architectural Mitigation | Residual Risk |
|---|---|---|---|
| **Spoofing** | Compromised agent or adversary submits fake containment receipt | Controller re-computes `hashlib.sha256(canonical(payload))` and performs constant-time comparison before marking action `VERIFIED`. | Endpoint agent runs in user-space; a root/kernel compromise on the endpoint can spoof local posture. |
| **Tampering** | Rogue DBA or compromised service attempts to alter audit history | HMAC-SHA256 hash chaining anchored on `Organization.audit_head`. PostgreSQL trigger revokes `UPDATE` and `DELETE` on `audit_logs`. `verify_audit()` detects truncation, deletion, or reordering. | Threat actors with database superuser privileges and secret key access could reconstruct the chain; external WORM archiving is required for compliance. |
| **Repudiation** | Operator approves their own host containment or modifies parameters | Strict two-person approval state machine: requester cannot approve; modification of action or target invalidates idempotency key; approver revalidated at execution. | Authorized SOC Manager credentials could be abused if physical token is stolen. |
| **Information Disclosure** | Cross-tenant telemetry access via direct object manipulation (IDOR) | Mandatory `organization_id` scoping in every database query, OpenSearch filter, and correlation cache key. | Application-level query omission; mitigated by automated tenant-isolation regression test suite. |
| **Denial of Service** | Argon2id CPU exhaustion via invalid username bombardment | Precomputed `DUMMY_PASSWORD_HASH` initialized once at module load with identical cost parameters. Password verification executes constant single verification pass without dynamic hashing. | High-frequency distributed requests; mitigated by per-IP and per-account rate limiters. |
| **Elevation of Privilege** | Analyst triggers host isolation without SOC Manager approval | Server-side role enforcement checks `playbooks.approve` before permitting execution of `HIGH_IMPACT` actions. | Compromised senior admin credentials; mitigated by session revocation and audit trail. |
| **SSRF** | Adversary configures outbound webhook targeting internal cloud metadata (169.254.169.254) | `validate_endpoint` enforces scheme HTTPS, allowlisted operator hosts, and strictly rejects link-local, multicast, loopback (`ip.is_loopback`), and private IPs (`ip.is_private`) in non-test profiles. | DNS rebinding during connection; mitigated by socket address pinning (`addresses[0]`). |
| **Formula Injection** | Malicious log payload containing spreadsheet formulas (`=cmd|...`) exported to CSV | `sanitize_csv_cell()` strips leading whitespace and prefixes any value starting with `=`, `+`, `-`, `@`, `\t`, `\r`, `%` with a single quote (`'`). | Operators importing raw JSON into external tooling without formula neutralization. |

---

## 3. Endpoint Agent Trust Boundary Limitations

1. **User-Space Operation**: The AEGIS agent operates as a background service and relies on standard OS firewall controls (`netsh advfirewall` on Windows, `iptables`/`nftables` on Linux). It does not provide kernel-level rootkit evasion or hypervisor-level isolation.
2. **Attacker with Root/SYSTEM Privileges**: If an adversary has already obtained elevated kernel or root privileges on the monitored endpoint, they may terminate the agent process or tamper with firewall rules directly.
3. **Receipt Semantics**: An execution receipt proves that the agent received the command and executed the firewall modification; it does not independently prove that an adversarial rootkit has not bypassed user-space packet filtering.
