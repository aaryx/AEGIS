# AEGIS

**Security Intelligence & Operations Platform**

AEGIS connects a FastAPI security core, an operational Typer CLI, and a Next.js
SOC console. Alerts are generated from ingested evidence by deterministic
detection rules; the interface has no separate dashboard dataset.

## Architecture

**Production Hardening & Remediation:**
- **Concurrency & Work Claiming**: Removed tenant-wide serialization locks on batch ingest and worker claiming. Workers claim event batches concurrently using PostgreSQL `FOR UPDATE SKIP LOCKED`.
- **Automated Data Lifecycle**: Integrated `aegis/retention.py` engine with legal hold protection, dedicated maintenance database identity, and OpenSearch index lifecycle management.
- **Timing-Safe Anti-DoS**: Precomputed Argon2id dummy password hash eliminates CPU-exhaustion DoS on unknown username lookups.
- **Cryptographic SOAR & Endpoint Daemon**: Active host isolation (Windows `netsh` / Linux `iptables`) with two-person approval, expiration windows, and canonical HMAC/SHA-256 execution receipts.
- **Native Protocol Ingestion**: High-throughput RFC 5424 and RFC 3164 Syslog engine supporting UDP, TCP octet-counting/newline framing (RFC 6587), and TLS.
- **SSRF & Export Hardening**: Outbound webhook requests reject loopback and private networks in production; CSV exports neutralize spreadsheet formula injection.

Documentation:
- [System Architecture](docs/architecture/system-architecture.md)
- [Security Threat Model](docs/security/threat-model.md)
- [Production Hardening Assessment](docs/security/production-hardening-assessment.md)
- [Deployment Runbook](docs/operations/deployment.md)
- [Backup & Disaster Recovery](docs/operations/backup-and-restore.md)
- [Incident Response & SOAR](docs/operations/incident-response.md)
- [Retention & Data Lifecycle](docs/operations/retention-and-data-lifecycle.md)
- [Monitoring & Alerting](docs/operations/monitoring-and-alerting.md)
- [Performance Testing](docs/testing/performance-testing.md)
- [Security Testing](docs/testing/security-testing.md)
- [Rollback Runbook](docs/operations/rollback.md)

### Implemented capabilities

- Evidence-preserving RFC 5424/3164 Syslog, Linux authentication, web access, Windows JSON event, journald, Docker, and Cloud export parsers.
- Stable event identities, batched durable acceptance, concurrent worker claiming with `SKIP LOCKED`, dead-letter isolation, and OpenSearch outbox indexing.
- 34 behavioral detections: match, threshold, distinct/sum aggregation, ordered sequence, periodicity, and numeric baseline deviation.
- IOC matching, risk factors, rule cooldowns, audited rule versions/exceptions, compromise-chain incident association, and semantic entity relations.
- Alerts, incidents, cases, immutable analyst notes, investigation timelines, formula-safe CSV export, and printable HTML reports.
- Session authentication, six RBAC roles, scoped API keys, lockout, CSRF, password-reset tokens, tenant isolation, and HMAC-linked audit records.
- Automated data lifecycle engine with legal hold exemptions, dry-run previews, and separate maintenance credentials.
- Endpoint response agent with process termination, live network containment, and cryptographic receipt verification.

## Quick start: Docker

Requires Docker Compose, **8 GB available memory recommended**, at least 15 GB
free disk, and Python 3.12+ for the one-time secret generator. On Linux,
OpenSearch may require `vm.max_map_count=262144` on the host.

```sh
python scripts/configure.py
docker compose up -d --build
docker compose ps
```

The generator creates a private, ignored `.env` containing random secrets.
Sign in using `BOOTSTRAP_USERNAME` and `BOOTSTRAP_PASSWORD` from that file.
No credentials are included in source control. Initialization applies migrations,
creates the initial administrator, installs rules and provisions search access.

- **Web:** http://localhost:3000
- **API:** http://localhost:8000/api/v1
- **OpenAPI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

Only Web/API bind host loopback ports. PostgreSQL, Redis and OpenSearch have no
published host ports. This Compose configuration is a local deployment profile;
see [deployment](docs/deployment.md) before exposing it beyond your machine.

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
# POSIX: source .venv/bin/activate
python -m pip install -c requirements.lock -e ".[dev]"
aegis login
# Set AEGIS_TOKEN to the returned short-lived bearer token.
aegis status
aegis simulate attack-chain
aegis alerts list --json
aegis incidents list
aegis hunt --query 'outcome = "failure"'
aegis investigate <alert-id>
aegis reports generate <incident-id>
aegis audit verify
```

The simulator generates logs only. It does not attack hosts. The attack chain
contains 12 failed logins, one successful login, privilege elevation, encoded
PowerShell telemetry and a connection to a documentation-range IOC.

```sh
aegis ingest file demo-data/auth.json
aegis ingest file demo-data/web.json
aegis rules test --all
```

IDs use `ALT-<UUID>` / `INC-<UUID>`; use the actual IDs returned by list commands.

## Local development without Docker

```sh
python -m pip install -c requirements.lock -e ".[dev]"
npm --prefix web ci
aegis bootstrap
python scripts/dev.py dev
```

Without service URLs, local mode uses SQLite and bounded local event search.
It shares the domain logic but is limited to one worker. Do not point a local
process at the Compose `.env` and assume it uses Compose PostgreSQL: Compose
injects its internal service URLs. See [configuration](docs/configuration.md).

## Verification

```sh
pytest
aegis rules test --all
python scripts/dev.py lint
python scripts/dev.py typecheck
python scripts/dev.py security
npm --prefix web test
npm --prefix web run build
npx --prefix web playwright install chromium
python scripts/e2e.py
# Against a running Compose deployment:
python scripts/acceptance.py
```

`scripts/e2e.py` starts an isolated real API with synthetic evidence and a built
Next.js server. It requires ports 8000 and 3000 to be free. The Compose acceptance
script authenticates using local bootstrap configuration without printing secrets.
Current verified results and genuine limitations are recorded in
[verification](docs/verification.md).

## Operations

```sh
docker compose logs --tail=100 api worker
docker compose down
```

Volumes survive `down`. Do not use `down -v` unless intentionally destroying the
deployment's evidence. No automatic retention deletion is enabled.

## Documentation

[Architecture](docs/architecture.md) · [Getting started](docs/getting-started.md) ·
[Installation](docs/installation.md) · [Configuration](docs/configuration.md) ·
[CLI](docs/cli.md) · [API](docs/api.md) · [Detection engine](docs/detection-engine.md) ·
[Rule format](docs/rule-format.md) · [Hunting](docs/threat-hunting.md) ·
[Incident response](docs/incident-response.md) · [AI](docs/ai.md) ·
[Security](docs/security.md) · [Deployment](docs/deployment.md) ·
[Threat model](docs/threat-model.md) · [Troubleshooting](docs/troubleshooting.md) ·
[Contributing](docs/contributing.md) · [Plugin interfaces](docs/plugins.md)
