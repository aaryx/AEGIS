# Security controls

Current hardening adds database-enforced tenant links, immutable original evidence,
a non-superuser runtime role, stronger composite API-key permission checks and
approval revalidation. See [hardening.md](hardening.md); its current deployment
and scan results supersede the initial runtime-role notes below.

- Argon2id password hashes; 14-character minimum for created/reset passwords.
- Opaque random expiring sessions, hashed at rest, refresh rotation and revocation.
- HttpOnly SameSite=Strict cookies; per-session CSRF tokens and exact-origin checks.
- Six code-defined roles mapped to granular permissions, enforced server-side.
- Tenant filters on direct and indirect resource access; no browser-only authorization.
- Scoped expiring/revocable API keys; plaintext disclosed only at creation.
- Shared Redis rate counters in distributed mode; account lockout after five failures.
- Bounded bodies, events, batches, search windows, rules, AI context and outputs.
- Strict schemas, safe YAML loading, allowlisted query fields/operators; no arbitrary regex.
- ORM parameter binding, escaped report HTML, React text rendering and safe CSV export.
- Audit chains use HMAC and serialized organization heads; PostgreSQL migration
  adds a trigger rejecting updates/deletes of audit records.
- Container least privilege, non-root app processes, read-only app filesystems,
  private service network and loopback-only published ports.
- Security headers, safe API errors and request IDs; access logs omit request bodies.

Audit integrity assumes the audit key is protected independently from the database.
A database administrator can remove triggers; an application/server compromise
that obtains the HMAC key can forge records. Export audit heads/records to a
separate append-only/WORM destination to strengthen the operational trust boundary.

The default local Compose uses authenticated HTTP OpenSearch only on an isolated
Docker network. It is not an encrypted production network. Enable verified TLS
between services for a production deployment. PostgreSQL's initial image user
owns the schema; provision a separate runtime role with limited DML privileges
after migrations when deploying production. Built-in permission sets are not
editable custom roles.

The current Next.js CSP permits inline framework bootstrap/style content. It
blocks external scripts, objects, framing and arbitrary connections but is not a
nonce-based strict CSP. Logs are never rendered with dangerouslySetInnerHTML.

Run `python scripts/dev.py security` for Bandit, Python dependency and npm audits.
CI additionally builds images, scans them and produces SBOMs. A clean automated
scan is not a penetration-test or production certification.
