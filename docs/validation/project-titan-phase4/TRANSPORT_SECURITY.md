# PostgreSQL and Redis transport

Status: configuration and local Redis SSL-stack verification complete; deployed service handshakes **not qualified**.

## Enforced policy

Production application and maintenance PostgreSQL URLs require the supported PostgreSQL scheme, an explicit hostname, `sslmode=verify-full` and nonempty `sslrootcert`. `verify-ca` is rejected because hostname validation is required. Duplicate/empty query parameters and host/hostaddr/service overrides are rejected. Bootstrap psycopg connections now preserve URL TLS parameters instead of dropping them. SQLAlchemy connections preserve TLS query options and impose connect/lock/statement bounds of 5/5/30 seconds.

Production Redis requires `rediss://`, hostname, password and required certificate verification. An ACL username may accompany the password; username alone is insufficient. Hostname validation cannot be disabled through URL query parameters. Only `db`, `ssl_cert_reqs=required` and `ssl_check_hostname=true` are allowed in production query strings; configure custom trust through `REDIS_CA`. Without REDIS_CA, redis-py uses system trust. This is intentional system-CA support, not disabled verification. A private-CA deployment must supply its CA bundle.

API and worker share `aegis.transport.redis_client`: hostname checking, required certificates, CA bundle and three-second socket/connect timeouts. Tests inspect actual connection-pool arguments. Untrusted, invalid, absent custom CA files and wrong hostnames fail in actual redis-py loopback TLS connections. No Redis command/authentication or cluster routing is exercised by those handshake tests.

Settings error rendering hides input values; credential-bearing database/Redis URLs are excluded from settings repr. SQLAlchemy hides statement parameters. Callers must not serialize raw Settings/model dumps or validation `.errors()` input payloads into logs. Existing worker diagnostics log exception class names rather than connection strings. Test credentials and ephemeral private keys are never evidence artifacts.

## Production Compose prerequisites

`compose.yaml` remains explicitly development-oriented with plaintext local services. Use both files for production:

```text
docker compose -f compose.yaml -f compose.production.yaml config --quiet
docker compose -f compose.yaml -f compose.production.yaml up -d
```

Only the first command was executed locally. Before starting services, provision:

- `certs/postgres/server.pem`, `server-key.pem`: server certificate with DNS SAN `postgres`, matching key readable by the PostgreSQL container UID with libpq/PostgreSQL-appropriate permissions. The production HBA file rejects all non-TLS TCP (`hostnossl ... reject`) and requires SCRAM on TLS (`hostssl ... scram-sha-256`). Container-local Unix socket connections are restricted to `peer` authentication strictly for the container's `postgres` system user, and `scram-sha-256` for all other database users; permissive `trust` authentication is strictly prohibited.
- `certs/redis/server.pem`, `server-key.pem`, `root-ca.pem`: certificate with DNS SAN `redis`. Redis plaintext port is disabled; TLS listens on port 6379. The password remains mandatory. This configuration uses server-authenticated TLS plus Redis authentication, **not mutual TLS** (`tls-auth-clients no`).
- `certs/opensearch/root-ca.pem`: application trust bundle must include the issuers of PostgreSQL, Redis and OpenSearch certificates because this overlay shares one mounted bundle. Existing OpenSearch node certificate/key requirements remain. Separate trust bundles may be mounted in a deployment-specific overlay with corresponding URLs/CA settings.
- HTTPS `PUBLIC_ORIGIN`, secure secret injection, and separate runtime/bootstrap/maintenance PostgreSQL passwords. The overlay preserves bootstrap and maintenance role-specific URLs; CLI also receives production policy.

This repository configures standalone Redis, not Sentinel or Redis Cluster. Those topologies require separate routing/failover/client verification before support can be claimed. Certificates are operator-provisioned and not generated or committed here. Missing files cause startup/connection failure; a valid-looking path in Settings alone does not prove a valid CA or handshake.

## Required live checks

1. PostgreSQL: prove negotiated TLS and peer identity using valid certificates; repeat with wrong hostname, untrusted issuer, missing/invalid CA and plaintext connection. Confirm no plaintext TCP authentication succeeds and bootstrap/migrations/retention retain TLS and intended privileges.
2. Redis: authenticated PING and rate-limit transactions over TLS; reject plaintext, incorrect password, untrusted CA and hostname mismatch; outage/restart recovery.
3. OpenSearch: validate TLS, least-privilege credentials, durable outbox outage/recovery and index operations.
4. Rotate CA/server certificates and verify application restart/reconnection behavior; inspect sanitized error paths.

Docker was installed but its daemon was unavailable. Compose validation passed; production containers and production certificates were not exercised. CI's existing development Compose integration does not satisfy these production TLS checks.
