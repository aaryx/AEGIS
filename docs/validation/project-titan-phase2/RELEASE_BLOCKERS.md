# TITAN Phase 2 — Release Blockers & Operational Risks

## Current Production-Pilot Decision: **BLOCKED**

Passing 495 offline backend tests and 35 frontend tests qualifies code correctness under unit/mocked assumptions, but does **NOT** qualify AEGIS for a live production pilot.

The production-pilot release remains **BLOCKED** pending live staging integration and environment qualification.

---

## 1. Mandatory Release Blockers

### Blocker 1: Live Linux Host Containment Qualification in Disposable Network Namespace
- **Status:** BLOCKED by host testing restrictions (Tested via Mocked Netlink only).
- **Risk:** While `aegis/endpoint_firewall.py` uses Netlink JSON transactions, kernel readback, and exclusive file locking, real Linux kernel nftables interactions, handle assignment, systemd integration, and persistent rule survival have not been verified in a real Linux kernel environment.
- **Required Action:** Deploy the agent to an isolated Linux staging VM with pre-existing firewall rules; execute live isolation, verify packet drops for unauthorized ports, verify controller reachability, and execute unisolation verifying zero leakage of administrator rules.
- **Precaution:** Must NEVER be run on developer host or shared systems.

### Blocker 2: Live PostgreSQL Multi-Worker Concurrency Qualification
- **Status:** BLOCKED by missing PostgreSQL daemon (21 integration tests skipped).
- **Risk:** High-concurrency operations (such as rate limiting, audit head updates, detection window state updates, and simultaneous duplicate event ingestion) have only been verified under SQLite threading models. SQLite does not exhibit PostgreSQL row-level locks, statement timeouts, or transaction abort behaviors.
- **Required Action:** Run `scripts/integration_gate.py` against a dedicated PostgreSQL 16 test container (`aegis_test`) to verify all 21 skipped integration tests pass with zero skips.

### Blocker 3: Live Distributed Redis Queue Semantics
- **Status:** BLOCKED by missing Redis daemon.
- **Risk:** Distributed queue backpressure, worker leasing, and failover recovery have not been validated against a real Redis instance.
- **Required Action:** Run `tests/test_integration.py::test_real_redis_queue_semantics_and_delivery` against a live Redis 7.x instance.

### Blocker 4: Live OpenSearch TLS Handshake & Security Bootstrap
- **Status:** BLOCKED by missing OpenSearch cluster.
- **Risk:** While `compose.production.yaml` now mounts the public root CA into application containers, live TLS 1.3 handshakes, certificate SAN verification, hostname matching (e.g. `opensearch`), and credentials bootstrap have not been validated.
- **Required Action:** Deploy `compose.production.yaml` in an isolated staging environment and execute live index operations over HTTPS with `verify_certs=True`.

### Blocker 5: Mandatory Transport Encryption Invariant
- **Status:** UNRESOLVED CONFIGURATION GAP.
- **Risk:** PostgreSQL and Redis connection strings in standard configuration do not enforce TLS (`sslmode=require` / `rediss://`), risking credential interception on non-isolated network links.
- **Required Action:** Require TLS transport for all backend database and cache connections in production deployment profiles.

---

## 2. Risk Classification Summary

| Item | Classification | Impact | Path to Resolution |
|---|---|---|---|
| Linux Endpoint Containment | Mocked & Unit-Tested | False containment or network isolation failure on live Linux hosts | Execute automated disposable network namespace drill |
| PostgreSQL Multi-Worker Concurrency | Blocked by missing infra | Race condition or transaction deadlock under multi-worker load | Execute full suite against live PostgreSQL `aegis_test` |
| Redis Distributed Queue | Blocked by missing infra | Event queue drops or backpressure starvation under load | Execute Redis integration suite |
| OpenSearch TLS Handshake | Blocked by missing infra | Silent TLS downgrade or container startup failure | Staging TLS handshake validation drill |
| Transport Gate Encryption | Confirmed config gap | Cleartext credential transit on untrusted networks | Enforce TLS in production settings schema |

---

## 3. Exact Next Required Actions

1. **Deploy Staging Test Pod**: Spin up disposable Docker Compose staging environment containing PostgreSQL 16, Redis 7, and OpenSearch 2.x with TLS enabled.
2. **Execute CI Release Gate**:
   ```bash
   python scripts/integration_gate.py
   ```
   Verify 0 skips and 100% pass across all mandatory integration fixtures.
3. **Run Live Network Namespace Containment Drill**:
   Execute agent network isolation tests inside a dedicated Linux network namespace (`ip netns`).
4. **Independent Release Auditor Sign-off**:
   Following zero-skip staging gate and container TLS proof, re-evaluate production-pilot readiness.
