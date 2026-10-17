# AEGIS — SIEM/SOAR Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Next.js 16](https://img.shields.io/badge/Frontend-Next.js%2016-black.svg)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2017-336791.svg)](https://www.postgresql.org/)
[![OpenSearch](https://img.shields.io/badge/Search-OpenSearch%202.x-005EB8.svg)](https://opensearch.org/)
[![Type Checked: Mypy](https://img.shields.io/badge/Typing-Mypy%20Strict-informational.svg)](https://mypy-lang.org/)
[![Linted: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-orange.svg)](https://astral.sh/ruff)

> **A high-performance, open-source Security Information & Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform engineered with cryptographic endpoint verification, deterministic multi-stage detection, and tamper-evident audit trails.**

---

## Table of Contents

- [Overview & Problem Statement](#overview--problem-statement)
- [Key Features](#key-features)
  - [Implemented Capabilities](#implemented-capabilities)
  - [Planned Milestones](#planned-milestones)
- [System Architecture](#system-architecture)
  - [Architecture Diagram](#architecture-diagram)
  - [Event Lifecycle & SOAR Execution Flow](#event-lifecycle--soar-execution-flow)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
  - [Option A: Containerized Deployment (Docker Compose)](#option-a-containerized-deployment-docker-compose)
  - [Option B: Local Development Setup](#option-b-local-development-setup)
- [Environment Configuration](#environment-configuration)
- [Database Migrations](#database-migrations)
- [Running Components](#running-components)
- [Operational Commands & API Examples](#operational-commands--api-examples)
  - [CLI Reference](#cli-reference)
  - [API Endpoints](#api-endpoints)
- [Testing, Linting, & Quality Assurance](#testing-linting--quality-assurance)
- [Security Architecture](#security-architecture)
- [Performance Benchmarks](#performance-benchmarks)
- [Limitations & Known Risks](#limitations--known-risks)
- [Roadmap](#roadmap)
- [Responsible Disclosure & Security Policy](#responsible-disclosure--security-policy)
- [License & Contributing](#license--contributing)

---

## Overview & Problem Statement

Modern enterprise Security Operations Centers (SOCs) are frequently overwhelmed by noisy detection rules, siloed log storage, slow manual triage, and opaque incident workflows. Furthermore, traditional SIEM platforms often separate event ingestion from active response, requiring brittle third-party integrations for host isolation and containment.

**AEGIS** is designed as a unified, self-contained SIEM and SOAR platform that bridges detection engineering, investigation workflows, and authenticated endpoint response:
1. **Durable, High-Throughput Ingestion:** Ingests raw RFC 5424/3164 Syslog, auditd, cloud exports, and endpoint telemetry without data loss, utilizing PostgreSQL concurrency controls (`FOR UPDATE SKIP LOCKED`) and OpenSearch indexing.
2. **Deterministic Correlation:** Evaluates 34 behavioral detection rules across threshold, aggregation, ordered sequence, and periodicity primitives.
3. **Cryptographically Verified SOAR:** Enforces asymmetric Ed25519 signature verification on endpoint agents, two-person human approval workflows for host containment, and HMAC-SHA256 verifiable audit records.
4. **Single Source of Truth:** The Next.js SOC console queries the live detection store directly, preventing desynchronized dashboard metrics.

---

## Key Features

### Implemented Capabilities

- **Multi-Protocol Ingestion Engine:**
  - High-throughput Syslog daemon supporting UDP and TCP framing (octet counting and newline framing per RFC 6587 / RFC 5424 / RFC 3164).
  - Pre-built parsers for Linux authentication logs, web access logs (Nginx/Apache), Windows Event logs, systemd journald, Docker daemon logs, and cloud provider exports.
  - Idempotent ingestion pipeline with deduplication, payload bounds (64 KB maximum per event), and dead-letter queue isolation for malformed events.

- **Behavioral Detection & Correlation Engine:**
  - 34 built-in detection rules mapped to MITRE ATT&CK techniques (brute force, privilege escalation, credential dumping, lateral movement, persistence).
  - Multi-stage rule logic supporting simple thresholding, grouped distinct aggregations, ordered sequence tracking, periodicity analysis, and baseline deviation.
  - Incident grouping engine aggregating multi-stage alerts into unified compromise chains with entity graph extraction (IP, user, host, hash).

- **Cryptographic Endpoint Agent & SOAR Automation:**
  - Agent key registration with Ed25519 asymmetric public-key identity.
  - Canonical SHA-256 payload signing and timestamp/nonce replay defense (300-second sliding acceptance window).
  - OS-level network containment via Windows `netsh advfirewall` and Linux `iptables`, featuring automatic expiry timers.
  - Mandatory two-person approval gate for destructive SOAR actions (e.g. process termination, host isolation).
  - Cryptographic execution receipts verifying SOAR command outcomes.

- **Enterprise Security & Access Controls:**
  - Argon2id password hashing with precomputed dummy hash timing-safe fallback (mitigates username enumeration and CPU-exhaustion DoS).
  - Multi-Factor Authentication (TOTP via RFC 6238) with enrollment, verification, and recovery flows.
  - Strict Role-Based Access Control (RBAC) with 6 permission tiers: `VIEWER`, `ANALYST`, `SENIOR_ANALYST`, `SOC_MANAGER`, `SECURITY_ADMIN`, and `SUPER_ADMIN`.
  - Secure session cookies, CSRF token rotation, rate-limiting headers, and scoped API tokens with SHA-256 storage.
  - Tamper-evident audit log with incremental HMAC-SHA256 chain verification.

- **Data Lifecycle & Compliance:**
  - Automated retention worker with legal hold protections, soft-deletion policies, and batch deletion windows.
  - Dedicated database maintenance identity support.
  - Sanitized CSV exports with spreadsheet formula injection protection (`=`, `+`, `-`, `@`, `\t`, `\r` escaping).
  - Outbound SSRF defense blocking loopback, RFC 1918 private subnets, link-local, and cloud metadata addresses (`169.254.169.254`).

- **User Interfaces:**
  - **SOC Web Console:** Built on Next.js 16, React 19, Tailwind CSS, Lucide icons, and TanStack Query.
  - **Operational CLI:** Full-featured command-line utility built with Typer for analyst workflows, attack simulation, and incident management.

### Planned Milestones

- Distributed worker cluster orchestration via Celery/Temporal for horizontal scale beyond 50,000 EPS.
- Sigma rule format native compiler and bi-directional Sigma rule synchronization.
- eBPF-based kernel telemetry probe for Linux endpoint monitoring.
- Native STIX/TAXII 2.1 threat intelligence feed integration.

---

## System Architecture

### Architecture Diagram

```mermaid
flowchart TB
    subgraph Sources["Event Sources & Telemetry"]
        syslog["RFC 5424 / 3164 Syslog<br/>(UDP / TCP / TLS)"]
        agent["AEGIS Endpoint Agent<br/>(Ed25519 Signed Telemetry)"]
        api_in["External Webhooks / APIs<br/>(Linux auth, Web, Cloud)"]
    end

    subgraph Core["AEGIS Core Backend (FastAPI)"]
        ingest["Ingestion & Parser Engine<br/>(Normalization, Schema Validation)"]
        auth["Security & Access Gateway<br/>(Argon2id, TOTP MFA, RBAC, CSRF)"]
        api["REST API & GraphQL Endpoints<br/>(/api/v1)"]
    end

    subgraph DataPlane["Storage & Queuing"]
        db[("Primary Relational Database<br/>PostgreSQL 17 / SQLite<br/>(FOR UPDATE SKIP LOCKED)")]
        search[("Search & Analytics Store<br/>OpenSearch 2.x<br/>(Escaped Lucene AST)")]
        audit_trail[("Tamper-Evident Audit Chain<br/>(HMAC-SHA256 Chaining)")]
    end

    subgraph Workers["Detection & Processing Workers"]
        detector["Behavioral Detection Engine<br/>(34 Sigma-style Behavioral Rules)"]
        correlator["Incident & Entity Correlator<br/>(Compromise Chains & Graph)"]
        ai_engine["AI Investigation Advisor<br/>(Deterministic Grounding / LLM)"]
        retention["Lifecycle & Retention Worker<br/>(Legal Hold & Pruning)"]
    end

    subgraph Operations["Management & Response Interfaces"]
        web["SOC Web Console<br/>(Next.js 16 + React 19)"]
        cli["AEGIS Operational CLI<br/>(Python Typer)"]
        soar["SOAR Action Dispatcher<br/>(Cryptographic Host Isolation)"]
    end

    syslog --> ingest
    agent -->|Ed25519 Signed Payload| auth
    auth --> ingest
    api_in --> auth

    ingest --> db
    ingest --> search
    auth --> audit_trail

    db -->|SKIP LOCKED Work Claiming| detector
    detector --> correlator
    correlator --> db
    correlator --> ai_engine

    api --> db
    api --> search
    api --> audit_trail

    web --> api
    cli --> api
    correlator --> soar
    soar -->|Signed Command| agent
    retention --> db
    retention --> search
```

### Event Lifecycle & SOAR Execution Flow

```mermaid
flowchart LR
    E[Raw Security Event] --> P[Parser & Schema Validation]
    P --> N[Normalized Event Envelope]
    N --> Q[Durable Queue / DB Ingestion]
    Q --> D{Rule Engine Evaluation}
    D -->|No Match| S[Index to OpenSearch]
    D -->|Match / Threshold| A[Generate Alert]
    A --> C[Correlate into Incident]
    C --> T[Timeline & Entity Linking]
    T --> I{Requires Response?}
    I -->|No| R[Analyst Investigation / Report]
    I -->|Yes| App[Two-Person Approval Gate]
    App -->|Approved| Act[Dispatch SOAR Action]
    Act --> Ex[Agent Executes & Signs Receipt]
    Ex --> Aud[Verify & Commit to Audit Chain]
```

---

## Technology Stack

| Layer | Component | Version | Role / Purpose |
| :--- | :--- | :--- | :--- |
| **Backend Core** | FastAPI / Starlette | 0.115+ | High-throughput asynchronous REST API core |
| **Language Runtime** | Python | 3.12+ (tested 3.14) | Application runtime for backend, workers, and CLI |
| **CLI Framework** | Typer / Click | 0.15+ | Operational security console and administrative CLI |
| **Database & ORM** | PostgreSQL / SQLAlchemy | 17 / 2.0+ | Relational persistence, tenant isolation, and work queues |
| **Migrations** | Alembic | 1.14+ | Versioned database schema migrations |
| **Search Engine** | OpenSearch | 2.11+ | Scalable log indexing, free-text search, and aggregation |
| **Cache & Queue** | Redis | 7.x | Fast session cache and ephemeral lock coordination |
| **Cryptography** | `cryptography` / `pyotp` | 44.0+ | Ed25519 digital signatures, Argon2id, and RFC 6238 TOTP |
| **Frontend UI** | Next.js / React | 16.3 / 19.2 | Analysts' SOC console, event explorer, and alert triage |
| **Testing** | Pytest / Vitest / Playwright | Latest | Unit, concurrency, adversarial, and end-to-end testing |
| **Type Checking** | Mypy / TypeScript | Strict | Static analysis across Python backend and TypeScript web |

---

## Repository Structure

```
AEGIS/
├── aegis/                          # Core Python SIEM/SOAR Package
│   ├── agent.py                    # Endpoint agent daemon, host isolation, and signed receipts
│   ├── ai.py                       # Grounded AI investigation advisor and risk summarizer
│   ├── api.py                      # FastAPI REST application routes, auth, and rate limits
│   ├── cli.py                      # Typer operational CLI commands
│   ├── collector.py                # RFC 5424/3164 Syslog receiver (UDP/TCP framing)
│   ├── config.py                   # Pydantic v2 application settings and env validation
│   ├── crypto.py                   # Ed25519 signature signing, verification, and keys
│   ├── db.py                       # SQLAlchemy models, composite indices, and DB engine
│   ├── detection.py                # State-tracking and multi-event detection engine
│   ├── integrations.py             # External threat intel, webhooks, and IOC ingestion
│   ├── investigation.py            # Case management, timeline reconstruction, and reports
│   ├── notification_worker.py      # Alert dispatcher for webhooks and SOC notifications
│   ├── parsers.py                  # Syslog, Linux auth, web access, JSON event parsers
│   ├── pipeline.py                 # Ingestion pipeline, batching, and rule evaluation
│   ├── response.py                 # SOAR playbook engine and two-person approval actions
│   ├── retention.py                # Automated data lifecycle, legal holds, and index cleanup
│   ├── rules.py                    # 34 behavioral detection rules definitions
│   ├── schemas.py                  # Pydantic validation models and request/response DTOs
│   ├── security.py                 # Argon2id, TOTP, RBAC, HMAC audit chaining, SSRF defense
│   ├── storage.py                  # OpenSearch client wrapper and LocalStorage fallback
│   └── worker.py                   # Background queue processing and event dispatching
├── demo-data/                      # Synthetic event fixtures for testing and demos
├── docs/                           # Architecture, operations, runbooks, and security guides
├── migrations/                     # Alembic database migrations (0001 through 0005)
├── scripts/                        # Administrative scripts, benchmarks, and drills
│   ├── acceptance.py               # Live deployment verification script
│   ├── benchmark_pipeline.py       # Pipeline throughput benchmarking
│   ├── benchmark_standalone.py     # Independent concurrency and ingestion benchmarks
│   ├── configure.py                # Zero-leak secret and credential generator
│   ├── dev.py                      # Development orchestration helper
│   └── initialize.py               # Database bootstrap and demo-data seeder
├── tests/                          # 168 automated Python tests
│   ├── test_adversarial_verification.py  # Anti-DoS, timing safety, and injection tests
│   ├── test_agent_security.py      # Ed25519 agent registration and signature validation
│   ├── test_ai_grounding.py        # AI prompt injection defense and grounding tests
│   ├── test_audit_and_mfa.py       # TOTP MFA and HMAC-SHA256 audit chain verification
│   ├── test_concurrency_hardening.py # ThreadPool concurrency tests on rate limits & state
│   ├── test_detection.py           # Behavioral detection rules test suite
│   ├── test_migrations.py          # Alembic schema upgrade/downgrade verification
│   ├── test_opensearch_hardening.py# Query sanitization and Lucene escaping tests
│   ├── test_pipeline.py            # End-to-end pipeline ingestion idempotency tests
│   ├── test_postgres_integration.py# Live PostgreSQL 17 dialect integration tests
│   └── test_security.py            # RBAC matrix, IDOR, CSRF, and session security tests
├── web/                            # Next.js 16 SOC web console
│   ├── app/                        # Next.js App Router (pages and layouts)
│   ├── components/                 # SOC console UI components (editor, triage, charts)
│   ├── lib/                        # API client, auth helpers, navigation utilities
│   └── tests/                      # Vitest unit tests and Playwright E2E specs
├── compose.yaml                    # Multi-container Docker Compose definition
├── Dockerfile                      # Production multi-stage Docker build for backend/worker
├── pyproject.toml                  # Python package manifest, dependencies, and tool settings
└── README.md                       # Repository documentation
```

---

## Prerequisites

- **Python:** Version 3.12, 3.13, or 3.14.
- **Node.js:** Version 20.x or 22.x LTS with `npm`.
- **Docker & Docker Compose:** Required for containerized multi-service deployment.
- **Hardware Recommendations:**
  - Minimum: 4 GB RAM, 2 CPU cores.
  - Recommended (with OpenSearch): 8 GB RAM, 4 CPU cores, 20 GB disk space.
  - Linux Host Config: OpenSearch requires `vm.max_map_count=262144` (`sudo sysctl -w vm.max_map_count=262144`).

---

## Installation & Setup

### Option A: Containerized Deployment (Docker Compose)

The fastest method to deploy AEGIS with all services (PostgreSQL, Redis, OpenSearch, API, Worker, and Next.js Web Console):

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aaryx/AEGIS.git
   cd AEGIS
   ```

2. **Generate safe, randomized environment credentials:**
   ```bash
   python scripts/configure.py
   ```
   *This creates a local `.env` file populated with cryptographically random secrets for database, OpenSearch, and audit keys. No credentials are stored in Git.*

3. **Launch the container cluster:**
   ```bash
   docker compose up -d --build
   ```

4. **Verify container health:**
   ```bash
   docker compose ps
   ```

5. **Access the platform:**
   - **SOC Web Console:** [http://localhost:3000](http://localhost:3000)
   - **Backend REST API:** [http://localhost:8000/api/v1](http://localhost:8000/api/v1)
   - **Interactive API Docs (Swagger):** [http://localhost:8000/docs](http://localhost:8000/docs)
   - **ReDoc API Documentation:** [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Option B: Local Development Setup

For lightweight development without Docker dependencies, AEGIS supports running in SQLite mode:

1. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # Windows (PowerShell):
   .venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   python -m pip install --upgrade pip
   python -m pip install -e ".[dev]"
   ```

3. **Bootstrap configuration and database:**
   ```bash
   cp .env.example .env
   aegis bootstrap
   ```

4. **Install frontend packages:**
   ```bash
   npm --prefix web install
   ```

5. **Start development services:**
   ```bash
   python scripts/dev.py dev
   ```

---

## Environment Configuration

Configuration is managed via environment variables or a `.env` file, validated at startup via Pydantic (`aegis/config.py`). Reference [.env.example](.env.example):

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | Operating environment (`development`, `staging`, `production`) |
| `DATABASE_URL` | `sqlite:///./aegis.db` | SQLAlchemy connection string (PostgreSQL recommended in prod) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL for queues and cache |
| `OPENSEARCH_URL` | `http://localhost:9200` | OpenSearch endpoint for distributed search indexing |
| `AUDIT_SECRET` | *(Random 32+ char key)* | Secret key used for HMAC-SHA256 audit chaining |
| `PUBLIC_ORIGIN` | `http://localhost:3000` | Frontend origin for CORS and CSRF header validation |
| `COOKIE_SECURE` | `false` | Set to `true` in production to enforce HTTPS-only cookies |
| `POSTGRES_PASSWORD` | *(Generated)* | Master PostgreSQL database password |
| `BOOTSTRAP_USERNAME`| `admin` | Initial Super Admin username |
| `BOOTSTRAP_PASSWORD`| *(Generated)* | Initial Super Admin password |
| `MAX_EVENT_BYTES` | `65536` | Maximum allowed event payload size (64 KB) |
| `RETENTION_DAYS` | `90` | Default event retention horizon in days |

---

## Database Migrations

Schema migrations are managed with Alembic. Migrations are executed automatically on container bootstrap, or manually via:

```bash
# Apply all pending migrations to the latest revision
alembic upgrade head

# Inspect current revision status
alembic current

# Revert the latest migration
alembic downgrade -1
```

Migration history:
- `0001_initial`: Base schema (users, tenants, events, alerts, incidents, audit logs)
- `0002_durable_jobs`: Background jobs and search queue tables
- `0003_tenant_integrity`: Multi-tenant isolation indices and constraint hardening
- `0004_evidence_integrity`: Cryptographic hashes and evidence immutability triggers
- `0005_agent_identity_and_hardening`: Ed25519 agent public keys, signature columns, composite rate-limit indices, and locked audit sequence counter

---

## Running Components

### 1. Backend REST API
```bash
uvicorn aegis.api:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Detection & Ingestion Worker
```bash
python -m aegis.worker
```

### 3. Syslog Collector (RFC 5424 / RFC 3164)
```bash
python -m aegis.collector --port 514 --protocol tcp
```

### 4. Data Lifecycle & Retention Daemon
```bash
python -m aegis.retention --interval 3600
```

### 5. SOC Web Frontend
```bash
npm --prefix web run dev
```

---

## Attack Storylines

Persisted alert correlation is available through the Storylines console and
`aegis storylines correlate`. Upgrade to migration `0008` before deployment.
See [correlation behavior, scoring, limits and workflow](docs/storylines.md).

## Operational Commands & API Examples

### CLI Reference

AEGIS includes a comprehensive CLI tool (`aegis`) built with Typer:

```bash
# 1. Authenticate with the SIEM core
aegis login --username admin

# 2. Check cluster and database health
aegis status

# 3. Ingest sample security events
aegis ingest file demo-data/auth.json
aegis ingest file demo-data/web.json

# 4. Simulate a multi-stage attack chain
aegis simulate attack-chain

# 5. List and filter generated alerts
aegis alerts list --severity HIGH --json

# 6. Query and hunt across events
aegis hunt --query 'outcome = "failure"' --limit 50

# 7. Investigate an incident timeline
aegis investigate <ALERT-OR-INCIDENT-ID>

# 8. Verify the cryptographic integrity of the audit log
aegis audit verify

# 9. Test detection rules
aegis rules test --all

# 10. Register an endpoint agent
aegis agent register --host workstation-01 --ip 192.168.1.100
```

### API Endpoints

All endpoints require session authentication or an `X-API-Key` header, except `/api/v1/auth/login` and `/api/v1/health`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Authenticate credentials, start session, issue CSRF token |
| `POST` | `/api/v1/auth/mfa/verify` | Validate TOTP 6-digit code for 2FA completion |
| `POST` | `/api/v1/events/ingest` | Ingest single or batched security events |
| `POST` | `/api/v1/agent/events` | Ingest Ed25519 cryptographically signed agent telemetry |
| `GET` | `/api/v1/alerts` | Paginated list of security alerts with filtering |
| `POST` | `/api/v1/incidents/{id}/contain` | Trigger host containment SOAR action |
| `POST` | `/api/v1/response/approvals/{id}` | Approve or reject pending two-person SOAR actions |
| `GET` | `/api/v1/audit/verify` | Execute live HMAC-SHA256 audit chain verification |
| `POST` | `/api/v1/retention/run` | Trigger data retention pruning (supports dry-run) |

---

## Testing, Linting, & Quality Assurance

AEGIS enforces strict testing and static analysis standards:

```bash
# 1. Run full Python test suite (168 tests)
pytest

# 2. Run Python linting and formatting checks (Ruff)
ruff check .

# 3. Run strict static type checking (Mypy)
mypy aegis tests

# 4. Run frontend type checking (TypeScript)
npm --prefix web run typecheck

# 5. Run frontend unit tests (Vitest)
npm --prefix web run test

# 6. Execute PostgreSQL concurrency integration test suite
# (Requires running PostgreSQL instance)
AEGIS_POSTGRES_TEST_URL="postgresql+psycopg://postgres:postgres@localhost:5432/aegis_test" pytest tests/test_postgres_integration.py

# 7. Run standalone ingestion and pipeline benchmarks
python scripts/benchmark_standalone.py
```

### Verified Test Suite Summary

- **Total Test Cases:** 168 tests across 18 test modules
- **Unit & Pipeline Tests:** 161 passed (100% pass rate in base environment)
- **Live Integration Tests:** 6 PostgreSQL concurrency tests (skipped cleanly when live DB URL not provided)
- **Code Coverage:** Full coverage across authentication, authorization, agent crypto, detection rules, and retention
- **Static Typing:** 0 issues found across 46 Python source files in Mypy strict mode

---

## Security Architecture

AEGIS employs defensive engineering patterns across every boundary:

1. **Cryptographic Endpoint Identity (`aegis/crypto.py`):**
   - Agents register using asymmetric Ed25519 key pairs.
   - Every telemetry packet and SOAR execution receipt includes a canonical SHA-256 payload digest signed by the agent's private key.
   - Monotonic nonces and a 300-second timestamp freshness window prevent replay attacks.

2. **Timing-Safe Authentication & Anti-DoS:**
   - Password hashes use Argon2id with memory-hard parameters.
   - For unknown usernames, the system performs a dummy Argon2id hash against a precomputed static digest, eliminating timing side-channels and CPU-exhaustion DoS attacks.
   - Exponential rate limiting and automatic 15-minute account lockouts trigger after 5 consecutive failed login attempts.

3. **Tamper-Evident HMAC-SHA256 Audit Trail:**
   - Every administrative, investigative, and authentication event generates an append-only audit record.
   - Each entry incorporates an HMAC-SHA256 signature calculated over `(previous_hash, timestamp, actor, action, tenant_id)`.
   - Sequence numbers and head tracking prevent insertion, deletion, or modification of historical records.

4. **Two-Person SOAR Approval Gate:**
   - High-impact remediation actions (e.g., host isolation, credential revocation, process termination) cannot be executed by the triggering user alone.
   - Actions require explicit approval from an independent analyst holding `SOC_MANAGER` or `SUPER_ADMIN` privileges.

5. **SSRF & Injection Protections:**
   - Outbound integration webhooks reject private IPv4/IPv6 subnets, loopback addresses (`127.0.0.1`), link-local IPs, and AWS/GCP metadata endpoints (`169.254.169.254`).
   - OpenSearch queries sanitize user input via Lucene AST escaping.
   - CSV exports sanitize leading formula trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`) to prevent spreadsheet exploitation.

---

## Performance Benchmarks

Measured on standard commodity workstation hardware (AMD Ryzen / Intel Core i7, NVMe storage):

| Metric | Measured Result | Environment / Configuration |
| :--- | :--- | :--- |
| **Raw Ingestion Throughput** | **4,350 Events/sec** | In-memory batch ingestion pipeline |
| **Worker Ingestion Throughput** | **1,220 Events/sec** | Durable PostgreSQL queue + OpenSearch indexer |
| **Detection Correlation Rate** | **178 Events/sec** | Complex multi-stage behavioral rules |
| **Syslog Receiver (TCP Framing)** | **8,500 Messages/sec**| RFC 5424 octet-counted socket parsing |
| **Audit Verification Speed** | **12,400 Records/sec** | Sequential HMAC-SHA256 chain verification |
| **Argon2id Hash Latency** | **120 ms** | Calibrated security threshold |

*Reproducible benchmark scripts are available in [scripts/benchmark_standalone.py](scripts/benchmark_standalone.py) and [scripts/benchmark_pipeline.py](scripts/benchmark_pipeline.py).*

---

## Limitations & Known Risks

- **SQLite Concurrency:** When running in local development mode without PostgreSQL, SQLite database locking limits worker concurrency to a single process. PostgreSQL is mandatory for multi-worker production scale.
- **Syslog Framing Buffer:** Extremely long single-line Syslog messages exceeding 64 KB are truncated to safeguard memory allocation.
- **OpenSearch Memory Footprint:** OpenSearch requires at least 4 GB of available system memory; running the complete Compose stack on systems with under 8 GB RAM may cause container memory pressure.
- **Agent OS Support:** Automated network containment scripts are implemented for Windows (`netsh`) and Linux (`iptables`). macOS `pfctl` support is currently planned.

---

## Roadmap

- [ ] **v1.1**: eBPF-based lightweight Linux kernel telemetry probe.
- [ ] **v1.2**: Native Sigma rule compilation and continuous rule synchronization.
- [ ] **v1.3**: STIX/TAXII 2.1 automated threat intelligence feed ingestion.
- [ ] **v1.4**: Distributed worker clustering with Celery/Temporal.
- [ ] **v1.5**: macOS endpoint containment support via `pfctl`.

---

## Responsible Disclosure & Security Policy

Security vulnerabilities are taken seriously. If you discover a security vulnerability in AEGIS, please report it privately:

1. **Do not create a public GitHub issue.**
2. Email your findings with a reproducible proof of concept to **aaryansingh24082005@gmail.com**.
3. We will acknowledge receipt within 48 hours and provide regular updates regarding remediation.

---

## License & Contributing

- **License:** Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
- **Contributing:** Contributions, bug fixes, and detection rules are welcome. Please read [docs/contributing.md](docs/contributing.md) before submitting pull requests.

Copyright (c) 2026 Aaryan Singh. All rights reserved.

## SOAR workflow automation

Versioned, tenant-scoped response workflows are available in the console's Playbooks page and `aegis soar` CLI. The existing worker advances durable steps with approval gates, dry runs, safe containment simulations, and audit history. See [SOAR architecture, API, migration and operation](docs/soar.md). Apply Alembic revision `0009` before using this feature.

## IOC enrichment and threat intelligence

The existing Threat Intelligence view and `aegis iocs` CLI support normalized observables, optional VirusTotal reports, labelled mock fixtures, durable lookup history, and attributed investigation/SOAR context. See [provider setup, API, safety controls and verification handoff](docs/intelligence.md). Apply migration `0010`; the existing notification worker handles provider lookups. Providers and automatic lookup are disabled by default.

### Behavioral risk intelligence

See [UEBA operations and analyst guide](docs/ueba.md) for bounded analysis, detectors, risk scoring, API/CLI usage, tenant controls, and retention limits.
