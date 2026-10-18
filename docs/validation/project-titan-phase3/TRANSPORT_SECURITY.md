# AEGIS TITAN PHASE 3 — TRANSPORT SECURITY & TLS AUDIT

**Date:** 2026-10-18  
**Scope:** Verification of transport encryption, certificate validation, hostname verification, and fail-closed configurations for PostgreSQL, Redis, and OpenSearch in AEGIS production environments.

---

## 1. Executive Summary

A comprehensive audit was conducted on connection initialization, schema validation, and deployment overlays for all external data stores. Prior to Phase 3, production settings enforced HTTPS and CA verification exclusively for OpenSearch, allowing potential plaintext transport or unverified TLS for PostgreSQL and Redis.

In Phase 3:
1. **PostgreSQL:** Production mode enforces `sslmode=verify-full` or `sslmode=verify-ca` accompanied by an explicit `sslrootcert` CA path. Plaintext connections (`sqlite` or unencrypted `postgresql`) and opportunistic/unverified TLS (`sslmode=require`, `prefer`, `allow`, `disable`) are strictly rejected.
2. **Redis:** Production mode enforces `rediss://` encrypted URIs, verifies that certificate verification is not disabled (`ssl_cert_reqs=none` is prohibited), and requires authentication credentials. Application workers pass `ssl_cert_reqs="required"` and `ssl_ca_certs` to the connection pool.
3. **OpenSearch:** Production mode strictly requires `https://` and mandatory CA bundle path validation (`opensearch_ca`).

---

## 2. Service-by-Service Audit & Policy Matrix

### 2.1 PostgreSQL Transport Security

| Configuration Parameter | Required in Production | Behavior on Missing / Invalid | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Protocol Scheme** | `postgresql+psycopg://` | Fails closed: raises `ValueError("Production requires PostgreSQL")` | `test_production_rejects_plaintext_postgres` |
| **`sslmode` Parameter** | `verify-full` or `verify-ca` | Fails closed: raises `ValueError("Production requires verified PostgreSQL TLS ... sslmode=require alone does not verify certificates or hostnames")` | `test_production_rejects_sslmode_require_without_certificate_validation` |
| **`sslrootcert` Parameter** | Valid path to CA bundle | Fails closed: raises `ValueError("Production requires PostgreSQL CA certificate path (sslrootcert) for TLS verification")` | `test_production_rejects_sslmode_require_without_certificate_validation` |
| **Credential Redaction** | Yes | Loggers and error messages sanitize connection URLs and passwords. | Zero password leaks in log audits. |

> **Security Note:** In libpq and psycopg (v3), `sslmode=require` encrypts traffic but skips root CA validation and hostname checking, leaving connections vulnerable to Active-in-the-Middle (AitM) certificate spoofing. AEGIS explicitly forbids `sslmode=require` in production, requiring `sslmode=verify-full` for end-to-end identity and encryption guarantees.

### 2.2 Redis Transport Security

| Configuration Parameter | Required in Production | Behavior on Missing / Invalid | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Protocol Scheme** | `rediss://` | Fails closed: raises `ValueError("Production requires TLS for Redis (rediss://)")` | `test_production_rejects_plaintext_or_insecure_redis` |
| **Certificate Verification** | `ssl_cert_reqs=required` | Fails closed: query parameters setting `ssl_cert_reqs=none`, `optional`, or `0` raise `ValueError("Production Redis TLS certificate verification must not be disabled")` | `test_production_rejects_plaintext_or_insecure_redis` |
| **Authentication** | Password or User credentials | Fails closed: raises `ValueError("Production requires authenticated Redis connection")` | `test_production_rejects_plaintext_or_insecure_redis` |
| **CA Certificate** | `redis_ca` field or system trust | Configured in `Settings.redis_ca` and injected into `Redis.from_url(..., ssl_ca_certs=settings.redis_ca)`. | `test_production_valid_configuration_succeeds` |

### 2.3 OpenSearch Transport Security

| Configuration Parameter | Required in Production | Behavior on Missing / Invalid | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Protocol Scheme** | `https://` | Fails closed: raises `ValueError("Production requires HTTPS for OpenSearch")` | `test_opensearch_production_enforces_https_and_ca` |
| **CA Certificate** | `opensearch_ca` | Fails closed: raises `ValueError("Production requires CA certificate validation for OpenSearch (opensearch_ca)")` | `test_opensearch_production_enforces_https_and_ca` |
| **Client Verification** | `verify_certs=True` | Injected into OpenSearch client initialization with CA bundle. | `test_opensearch_client_enforces_certificate_verification` |

---

## 3. Deployment Configuration Verification

### `compose.production.yaml` Overlay
The production Docker Compose overlay was updated to supply secure connection parameters by default:

```yaml
x-app-production: &app-production
  environment:
    ENVIRONMENT: production
    COOKIE_SECURE: "true"
    DATABASE_URL: postgresql+psycopg://aegis_runtime:${POSTGRES_RUNTIME_PASSWORD:-${POSTGRES_PASSWORD}}@postgres:5432/aegis?sslmode=verify-full&sslrootcert=/usr/share/opensearch/config/certs/root-ca.pem
    REDIS_URL: rediss://:${REDIS_PASSWORD:?Run python scripts/configure.py}@redis:6379/0?ssl_cert_reqs=required
    OPENSEARCH_URL: https://opensearch:9200
    OPENSEARCH_CA: /usr/share/opensearch/config/certs/root-ca.pem
  volumes:
    - type: bind
      source: ./certs/opensearch/root-ca.pem
      target: /usr/share/opensearch/config/certs/root-ca.pem
      read_only: true
      bind:
        create_host_path: false
```

- In development and test environments (`ENVIRONMENT=development` or `testing`), unencrypted SQLite and local loopback Redis remain supported so engineers and automated CI can execute without requiring local TLS infrastructure.
- In production (`ENVIRONMENT=production`), unencrypted or insecure settings trigger immediate startup failure (`ValidationError`).
