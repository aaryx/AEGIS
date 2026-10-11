# Configuration

New hardening settings: DETECTION_LATENESS_SECONDS (120), DETECTION_WINDOW_LIMIT
(10,000), INTEGRATION_ALLOWED_HOSTS (JSON array, default empty),
INTEGRATION_MAX_BYTES (2 MB), INTEGRATION_TIMEOUT_SECONDS (10),
INTEGRATION_MAX_ATTEMPTS (6), RESPONSE_APPROVAL_SECONDS (3,600), and
POSTGRES_RUNTIME_PASSWORD (separate runtime database credential).
See [hardening.md](hardening.md) for integration secrets and upgrade behavior.

Backend precedence: explicit Settings constructor values (tests), environment,
`.env`, then validated defaults. CLI connection precedence: command-line `--url`,
`AEGIS_URL`, selected TOML profile, then `http://localhost:8000`. Tokens are read
only from `AEGIS_TOKEN`; the CLI does not persist them.

Example `~/.config/aegis/config.toml`:

```toml
[profiles.default]
url = "http://localhost:8000"
[profiles.soc]
url = "https://aegis.example.org"
```

Use `aegis --profile soc status`. Credentials do not belong in the profile file.

| Variable | Purpose / default |
|---|---|
| ENVIRONMENT | development, testing, production |
| DATABASE_URL | SQLAlchemy URL; default local SQLite |
| REDIS_URL | Shared window/rate-limit state; omitted in local mode |
| OPENSEARCH_URL | Event search; omitted in local mode |
| OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD | Search application credentials |
| OPENSEARCH_CA | Trusted CA path for a TLS search endpoint |
| AUDIT_SECRET | HMAC key; use 32+ random characters and back it up separately |
| PUBLIC_ORIGIN | Exact browser origin; default http://localhost:3000 |
| COOKIE_SECURE | Enable for HTTPS; mandatory in production |
| SESSION_HOURS | 8; allowed 1–24 |
| MAX_REQUEST_BYTES | 2,000,000 |
| MAX_EVENT_BYTES | 65,536 |
| MAX_BATCH_EVENTS | 500 |
| QUEUE_CAPACITY | 100,000 unfinished events |
| WORKER_BATCH_SIZE | 100 |
| WORKER_MAX_ATTEMPTS | 6 |
| MAX_SEARCH_DAYS | 31 |
| RETENTION_DAYS | 90; administrative eligibility, no automatic deletion |
| AI_PROVIDER | local, openai, azure |
| AI_API_KEY / AI_ENDPOINT / AI_MODEL | External provider configuration |
| AI_MAX_TOKENS | 1,500 output-token ceiling |
| AI_EVIDENCE_LIMIT | 20 minimized events per request |

Production startup requires PostgreSQL, Redis, OpenSearch, an audit secret,
HTTPS origin and secure cookies. Do not use an empty audit key outside temporary
development. The Compose-generated `.env` selects development transport defaults
because Web/API are loopback-only; it uses distributed storage nonetheless.

Compose substitutes internal database/Redis/search URLs in container environment.
Host CLI calls the API and needs only AEGIS_URL/AEGIS_TOKEN. Avoid printing
`docker compose config` without `--quiet`: rendered configuration contains secrets.
