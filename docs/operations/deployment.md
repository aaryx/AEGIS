# AEGIS Production Deployment Guide

## 1. Prerequisites & Architecture Profiles

| Component | Minimum Specification (Local Dev) | Recommended Specification (Production) |
|---|---|---|
| **CPU / RAM** | 4 vCPU / 8 GB RAM | 8+ vCPU / 32 GB RAM |
| **Operating System** | Linux (Ubuntu 22.04+ / RHEL 9+) or Windows 11 | Linux (Ubuntu 24.04 LTS / RHEL 9+) |
| **Python** | Python 3.12+ (tested through 3.14) | Python 3.12 container runtime |
| **Node.js** | Node 20 LTS or Node 22 | Node 22 LTS container runtime |
| **PostgreSQL** | PostgreSQL 16+ (or local SQLite for dev) | PostgreSQL 17 with replication & SSL |
| **Redis** | Redis 7+ | Redis 7+ with persistent AOF & password |
| **OpenSearch** | OpenSearch 2.x or 3.x (single-node) | OpenSearch 3.x multi-node cluster |

---

## 2. Quickstart Deployment (Local Development)

```bash
# 1. Initialize Python virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.lock

# 2. Generate deployment configuration & random secrets
python scripts/configure.py

# 3. Start services via Docker Compose
docker compose up -d --build

# 4. Verify deployment health
docker compose ps
curl -s http://localhost:8000/api/v1/system/liveness
curl -s http://localhost:8000/api/v1/system/readiness
```

SOC Console UI is accessible at `http://localhost:3000`.  
FastAPI Backend is accessible at `http://localhost:8000`.

---

## 3. Production Hardening Configuration

In production (`ENVIRONMENT=production`), AEGIS enforces strict initialization checks:
- Mandatory PostgreSQL backend (`postgresql+psycopg://`).
- Mandatory Redis and OpenSearch instances.
- Mandatory 32+ character `AUDIT_SECRET`.
- Mandatory HTTPS (`COOKIE_SECURE=true`, `PUBLIC_ORIGIN=https://...`).
- Separation of `aegis_runtime` from `aegis_maintenance` database credentials.

### Service Architecture in `compose.yaml`

- `postgres`: Primary durable storage with custom healthcheck.
- `redis`: Shared rate-limit buckets and caching with AOF persistence.
- `opensearch`: High-volume search projection with role-based access.
- `initialize`: Runs Alembic migrations, provisions tenant, seeds detection rules, and configures database permissions.
- `api`: Stateless FastAPI application instances.
- `worker`: Horizontal detection workers consuming event batches concurrently via `SKIP LOCKED`.
- `retention`: Scheduled data lifecycle worker executing bounded pruning and OpenSearch index lifecycle management.
- `notifications`: Async webhook and notification delivery worker.
- `web`: Next.js SOC console with standalone Turbopack production bundle.
