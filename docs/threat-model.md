# Threat model

## Assets and boundaries

Assets: immutable log evidence, identity/session/API credentials, tenant data,
incident notes, rules/exceptions, response approvals, AI context, reports, audit
chain/key and integration configuration. Boundaries: source → ingestion;
browser/CLI → API; API → DB/Redis/search; worker → parser/rules; evidence → AI;
operator approval → response provider; app containers → host/network.

| Actor / threat | Mitigation | Residual risk |
|---|---|---|
| Unauthenticated attacker / credential stuffing | Argon2id, rate limiting, lockout, safe errors, no registration | Distributed source attacks and deliberate lockout need perimeter controls |
| Compromised collector / poisoning | Scoped API key, bounded strict schema, raw evidence hashes, source sequence conflict rejection | An authorized collector can submit false but well-formed logs; provenance/signing is not attestation |
| Malicious log source / XSS or log injection | React escaped text, escaped HTML reports, structured JSON logging, no command evaluation | Analyst terminal exports must remain treated as untrusted text |
| Compromised analyst / IDOR | Server-side role checks and tenant filtering on direct/indirect access | Broad read rights inside one tenant are intentional SOC policy |
| Insider / evidence tampering | No edit-evidence API, raw hashes, audit chain and PostgreSQL audit trigger | Host/DB admins remain powerful; WORM export and independent backups needed |
| Malicious rule / denial of service | Declarative schema, bounded counts/windows/operators, no arbitrary code/regex | Many expensive enabled rules can still consume resources; benchmark tenant policy |
| Malicious playbook / command execution | Fixed action set, typed target checks, separate approval, no shell provider | A future external provider must implement its own least privilege/idempotency |
| AI prompt injection | Untrusted-data prompt boundary, minimized context, strict output/citations, no tool execution | Semantic hallucinations cannot be eliminated by schema validation |
| Compromised integration / SSRF | Endpoint configuration is administrator-controlled; AI only HTTPS, no redirects | Production egress policies must restrict configured provider destinations |
| Cross-tenant state leakage | Tenant IDs in records, search filters, window keys and fingerprints | DB-level RLS is not enabled; application query discipline remains essential |
| Search outage / evidence loss | PostgreSQL durable inbox, retries/backoff, dead letters and explicit retry | PostgreSQL outage rejects acceptance; source must buffer/retry |
| Queue/storage exhaustion | Bounded bodies/batches/queue, rate limits, visible queue health | Evidence retention requires an operator capacity/backup policy |
| Session theft / CSRF | HttpOnly, secure cookies in production, SameSite, CSRF, rotation, logout | Endpoint or browser compromise can act with the user's privileges |

## Trust assumptions

Host administrators, deployment configuration and reviewed plugin code are trusted.
Plugins run with process permissions and are not sandboxed. No untrusted package
auto-discovery or runtime installation exists. Environment secrets and database
backups require host-level protection and separate access control.

## Operational tests

Verify authentication/CSRF, every role's permitted operations, indirect evidence
IDOR, key revocation, reset-token replay, source sequence conflicts, audit mutation,
oversized JSON, unsafe operators, dangerous actions, independent approval and
malicious rendered log text. Test both SQLite and PostgreSQL paths; SQL type
behavior differs. Exercise search/queue outages and verify accepted evidence
survives. Restore a backup into an isolated network and validate evidence hashes.
