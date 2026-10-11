# Troubleshooting

| Symptom | Check |
|---|---|
| Docker cannot connect | Start Docker Desktop/Engine; `docker info` must work |
| OpenSearch startup failure | 8 GB Docker memory, free disk, host vm.max_map_count and generated strong password |
| Initialize exits nonzero | `docker compose logs initialize`; verify DB credentials and search admin provisioning |
| Login rejected | Exact bootstrap username/password, five-failure lockout, origin and secure-cookie configuration |
| 403 on browser mutation | CSRF cookie/header, PUBLIC_ORIGIN, role permission |
| 403 in CLI | AEGIS_TOKEN present, token scope and expiration, command permission |
| Accepted events but no alert | Worker heartbeat, queue state, missing grouping field, threshold/window, exceptions, timestamp |
| Search empty after ingestion | Wait for worker plus search refresh; check range/source timestamps and dead letters |
| 409 updating | Reload revision/version; do not overwrite another analyst's changes |
| AI summary says local fallback | External timeout, model/API compatibility, key, response validation; no external success implied |
| No external containment | Installed provider is local-policy-only; result explicitly states no remote enforcement |
| Local search range rejected | Narrow range or use OpenSearch; local eligible window capped at 50k events |
| Dead letters | Repair underlying dependency/parser issue, inspect last_error type, use system retry |

Request errors include X-Request-ID. Application logs emit error type and request ID
without credentials or log payloads. Reproduce failures in a protected development
environment for full diagnostics; production responses do not include stack traces.

Event timestamps in fixed sample web files are historical. Set a matching search
range or use `aegis simulate` for current synthetic timestamps. Simulation feeds
the normal pipeline; it does not insert alert or incident records directly.
