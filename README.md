# AEGIS - Security Intelligence & Operations Platform

[![CI Verification](https://github.com/aaryx/AEGIS/actions/workflows/ci.yml/badge.svg?branch=feature/ironclad-qualification)](https://github.com/aaryx/AEGIS/actions/runs/40081421870)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12+-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![FastAPI: 0.135](https://img.shields.io/badge/Backend-FastAPI%200.135-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js: 16.4.3](https://img.shields.io/badge/Frontend-Next.js%2016.4.3-black.svg?logo=next.js&logoColor=white)](https://nextjs.org)
[![PostgreSQL: 17](https://img.shields.io/badge/Database-PostgreSQL%2017-336791.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![OpenSearch: 3.5](https://img.shields.io/badge/Search-OpenSearch%203.5-005EB8.svg?logo=opensearch&logoColor=white)](https://opensearch.org)
[![Redis: 7.4](https://img.shields.io/badge/Cache-Redis%207.4-DC382D.svg?logo=redis&logoColor=white)](https://redis.io)
[![Backend Tests](https://img.shields.io/badge/Pytest-622%20Passed%20%7C%2031%20Skipped-brightgreen.svg)](tests/)
[![Integration Gate](https://img.shields.io/badge/Integration-62%20Passed%20(0%20Skips)-brightgreen.svg)](scripts/integration_gate.py)
[![Frontend Tests](https://img.shields.io/badge/Vitest-35%20Passed-brightgreen.svg)](web/tests/)
[![Security Audits](https://img.shields.io/badge/CVEs-0%20Known%20Vulnerabilities-brightgreen.svg)](requirements.lock)

> **AEGIS is an open-source, multi-tenant Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform engineered with Ed25519 cryptographic endpoint attestation, multi-stage behavioral detection, automated attack storyline correlation, authenticated cloud backup envelopes, and tamper-evident HMAC-SHA256 audit trails.**

---

## Release & Qualification Status

| Verification Gate | Result | Qualification Status |
| :--- | :---: | :--- |
| **Codebase Qualification** | **PASSED** | **CODE QUALIFIED** across 622 unit/regression tests and 62 live integration tests |
| **Remote GitHub Actions CI** | **PASSED** | **[Run 40081421870](https://github.com/aaryx/AEGIS/actions/runs/40081421870)** — All 38 pipeline steps succeeded |
| **Dependency Security (CVEs)** | **PASSED** | 0 vulnerabilities across Python (`requirements.lock`) and Node.js (`package-lock.json`) |
| **Secret Scan Audit** | **PASSED** | 0 secrets in current working tree and reachable Git history |
| **Production Readiness Gate** | **BLOCKED** | **Blocked on 4 documented external operational prerequisites** (see below) |

> [!IMPORTANT]
> **Production Readiness Blockers:** While the codebase is fully verified in continuous integration, production deployment remains blocked until operators fulfill four external infrastructure requirements:
> 1. **Enterprise PKI:** Real CA-signed certificates (`*.aegis.internal`) mounted to daemons.
> 2. **Target Fleet Linux Containment Canary:** Host-level verification on physical bare-metal enterprise Linux hosts.
> 3. **Physical Cloud Disaster Recovery Drill:** Verification against physical AWS S3 Object Lock / GCP CMEK storage.
> 4. **24-Hour Continuous Multi-Worker Soak:** A 24-hour non-stop ingestion test executed on persistent staging infrastructure.

---

## Table of Contents

1. [Architectural Overview](#architectural-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Key Subsystems](#key-subsystems)
4. [Technology Stack](#technology-stack)
5. [Repository Structure](#repository-structure)
6. [Prerequisites and Installation](#prerequisites-and-installation)
7. [Environment Configuration](#environment-configuration)
8. [Running AEGIS](#running-aegis)
9. [CLI Usage](#cli-usage)
10. [Testing and Quality Assurance](#testing-and-quality-assurance)
11. [Security Architecture & Controls](#security-architecture--controls)
12. [Deployment Profiles](#deployment-profiles)
13. [External Qualification Blockers](#external-qualification-blockers)
14. [Contributing and Security Reporting](#contributing-and-security-reporting)
15. [License](#license)

---

## Architectural Overview

AEGIS unifies SIEM telemetry collection with SOAR active response through a zero-trust, tenant-isolated architecture:

- **Ingestion & Normalization:** High-throughput RFC 5424/3164 Syslog receiver and HTTP ingestion endpoints with strict JSON schema validation, payload bounding (64 KB max), and pessimistic tenant locking (`lock_tenant`) preventing queue saturation.
- **Behavioral Detection Engine:** 34 built-in rules evaluating sliding-window thresholding, distinct aggregations, and ordered sequence progressions mapped directly to the MITRE ATT&CK enterprise matrix.
- **Attack Storyline Correlation:** Dynamic incident clustering that groups disparate alerts by temporal proximity (default 30m window) and shared entity indicators (hosts, usernames, internal IPs, file hashes).
- **Cryptographic Endpoint Attestation:** Asymmetric Ed25519 keypair enrollment, controller-signed command envelopes, monotonic nonces, freshness windows (300s), and signed execution receipts.
- **Host Network Containment:** Operating-system firewall controls (`nftables` on Linux, `netsh` on Windows) that isolate compromised endpoints with a default-drop policy while strictly preserving loopback and controller communication.
- **Tamper-Evident Audit Trails:** Append-only sequential HMAC-SHA256 entry hash chains coupled to durable `AuditHead` records, with support for cryptographic checkpoints and WORM / S3 Object Lock anchoring.
- **Disaster Recovery & Cold Restore:** Authenticated `AGBK` v1 backup envelopes combining AES-128-CBC Fernet encryption with PBKDF2-HMAC-SHA256 (100,000 iterations) and pre-encryption SHA-256 integrity verification.

---

## Architecture Diagram

```mermaid
flowchart TD
    subgraph Clients["Clients & Producers"]
        Syslog["Syslog Sources (UDP/TCP)"]
        Agents["AEGIS Endpoint Agents (Ed25519)"]
        UI["Next.js 16 Web Console"]
        CLI["Typer CLI (aegis)"]
    end

    subgraph Edge["Edge Layer (Docker / Reverse Proxy)"]
        EdgeProxy["Reverse Proxy / TLS Terminator"]
    end

    subgraph CoreServices["AEGIS Core Services"]
        API["FastAPI API Server (:8000)"]
        Worker["Background Event Worker"]
        Retention["Automated Retention Daemon"]
        Notify["Notification Delivery Worker"]
    end

    subgraph DataPlane["Data & Storage Plane"]
        PG[("PostgreSQL 17\n(State & Outbox)")]
        Redis[("Redis 7.4\n(Queues & Locks)")]
        OS[("OpenSearch 3.5\n(Observables & Telemetry)")]
    end

    Syslog -->|RFC 5424/3164| API
    Agents -->|Attested Receipts & Poll| API
    UI -->|Session / CSRF| EdgeProxy
    CLI -->|Bearer Token / API Key| EdgeProxy
    EdgeProxy --> API

    API -->|Write Events & Outbox| PG
    API -->|Enqueue Work| Redis
    API -->|Audit Chain Mutations| PG

    Worker -->|Claim Batches (SKIP LOCKED)| PG
    Worker -->|Deduplicate & Correlate| Redis
    Worker -->|Index Observables| OS

    Retention -->|Scheduled Purge| PG
    Notify -->|Webhook Dispatch| EdgeProxy
```

---

## Key Subsystems

### 1. Ingestion & Outbox Reliability
- **Durable Outbox Pattern:** Ingested events are recorded in transactional outbox tables before acknowledgment, ensuring zero event loss during worker crashes.
- **Batch Processing:** Events are processed in configurable worker batches (`WORKER_BATCH_SIZE`, default: 100) using PostgreSQL `FOR UPDATE SKIP LOCKED`.
- **Clock Skew Defense:** Ingestion strictly enforces a bounded event timestamp delta (`MAX_EVENT_CLOCK_SKEW_SECONDS`, default: 86,400s) to prevent timestamp manipulation attacks.

### 2. Behavioral Detection Engine
- **MITRE ATT&CK Coverage:** Rules map to Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, and Exfiltration.
- **Rule Verification:** Canonical rule compiler verified via `aegis rules test --all` (34 passed, 0 failed in 1.82s).
- **Rule Primitives:**
  - *Threshold:* Alert upon $N$ occurrences within sliding duration $D$.
  - *Aggregation:* Alert upon distinct threshold across entity fields.
  - *Sequence:* Multi-stage ordered transitions (e.g., repeated authentication failures followed immediately by successful logon).

### 3. SOAR Engine & Active Response Governance
- **Human-in-the-Loop Safeguards:** Destructive actions (such as endpoint network isolation or account revocation) require mandatory two-person authorization from `SOC_MANAGER` or `SECURITY_ADMIN`.
- **Simulation Dry-Run:** Playbook rules support execution dry-runs that compute containment impacts without modifying endpoint state.
- **Fail-Closed Execution:** If approval tokens expire or policy hashes mismatch, the execution state machine fails closed into `UNKNOWN` / `REJECTED`.

### 4. Endpoint Attestation & Network Containment
- **Asymmetric Envelopes:** Agents enroll via one-time tokens and generate Ed25519 keypairs. The controller verifies agent public keys; the agent verifies controller signatures.
- **Isolation Firewall:** Network containment applies host netfilter rules that drop all inbound and outbound traffic while strictly preserving:
  * Loopback interface communication (`127.0.0.1/8`, `::1`).
  * Dedicated control plane connection to the AEGIS controller IP and port.
- **Zero Global Flush:** The engine never issues global firewall flushes (`iptables -F` or `netsh advfirewall reset`), eliminating host lockouts.

---

## Technology Stack

| Layer | Component | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | FastAPI | 0.135.1 | High-performance asynchronous REST API |
| **ASGI Server** | Uvicorn | 0.41.0 | Asynchronous HTTP/1.1 and WebSocket server |
| **Database ORM** | SQLAlchemy | 2.0.48 | Typed relational modeling and pessimistic locking |
| **Database Migrations** | Alembic | 1.18.4 | Linear migration DAG with revision integrity |
| **Primary Database** | PostgreSQL | 17-alpine | Relational persistence, outbox, and audit logs |
| **Cache & Queues** | Redis | 7.4.8-alpine | In-memory queueing, rate-limiting, and locks |
| **Search Engine** | OpenSearch | 3.5.0 | Telemetry indexing and observable searching |
| **Password Hashing** | Argon2id | `argon2-cffi` 25.1 | Memory-hard key derivation and verification |
| **Cryptography** | Cryptography | >= 43.0.0 | Ed25519 signing, AES-128 Fernet, HKDF, PBKDF2 |
| **CLI Application** | Typer & Rich | 0.24.1 / 14.3.3 | Interactive administrative command-line interface |
| **Frontend Framework** | Next.js (App Router) | 16.4.3 | Server-rendered React operations console |
| **Frontend UI Library** | React | 19.2.4 | Responsive component rendering |
| **Frontend Testing** | Vitest | 4.1.12 | Unit and component testing suite |

---

## Repository Structure

```text
AEGIS/
├── .github/
│   ├── ISSUE_TEMPLATE/          # Bug report, feature request, and security templates
│   ├── workflows/
│   │   └── ci.yml               # Comprehensive 38-step GitHub Actions pipeline
│   ├── dependabot.yml           # Automated weekly dependency updates (pip, npm, actions)
│   └── pull_request_template.md # Required PR verification and security checklist
├── aegis/                       # Core Python SIEM/SOAR package
│   ├── agent.py                 # Endpoint agent logic and telemetry dispatch
│   ├── api.py                   # FastAPI application routing and middleware
│   ├── audit_anchor.py          # Tamper-evident HMAC-SHA256 audit log chains
│   ├── backup_crypto.py         # Authenticated AGBK v1 cold disaster recovery
│   ├── cli.py                   # Typer CLI implementation
│   ├── endpoint_firewall.py     # Linux (nftables) & Windows (netsh) host containment
│   ├── security.py              # Argon2id, RBAC, session management, and rate limiting
│   ├── soar.py                  # SOAR playbook engine and two-person approval gates
│   └── storylines.py            # Automated multi-alert attack correlation
├── deploy/                      # Production deployment configurations
│   └── postgres/pg_hba.conf     # Hardened host-based authentication (SCRAM-SHA-256)
├── docs/                        # Technical documentation & validation reports
│   └── validation/              # Evidence matrices, runbooks, and test records
├── migrations/                  # Alembic database migrations (0001 - 0011)
├── rules/                       # Curated behavioral detection rules (YAML)
├── scripts/                     # Developer, verification, and operations tooling
│   ├── configure.py             # Cryptographic local environment generator
│   ├── dev.py                   # Canonical developer workflow dispatcher
│   ├── initialize.py            # Database bootstrapping and admin seeding
│   ├── integration_gate.py      # Live containerized dependency gate
│   ├── recovery_drill.py        # Automated disaster recovery cold-restore drill
│   ├── soak_test.py             # 4-worker multi-tenant concurrency soak harness
│   └── test_containment_linux.sh# Linux netns and nftables containment qualification
├── tests/                       # Complete backend Pytest test suite (622 tests)
├── web/                         # Next.js 16.4.3 frontend application
│   ├── app/                     # App Router pages and layouts
│   ├── components/              # Interactive SOC console components
│   ├── lib/                     # API client and utility routines
│   └── tests/                   # Vitest unit test suites (35 tests)
├── .editorconfig                # Universal indentation and charset configuration
├── .gitattributes               # Cross-platform LF normalization and binary handling
├── .gitleaks.toml               # Secret scanning policy and test fixture allowlists
├── compose.yaml                 # Staging Docker Compose topology
├── compose.production.yaml      # Hardened production TLS overlay
├── pyproject.toml               # Python package configuration and tool metadata
├── requirements.lock            # Fully pinned Python dependency lockfile
├── CONTRIBUTING.md              # Contributor guidelines and workflow expectations
├── LICENSE                      # MIT License
└── SECURITY.md                  # Coordinated vulnerability disclosure policy
```

---

## Prerequisites and Installation

### System Requirements
- **Linux, macOS, or Windows** (with WSL2 or PowerShell 5.1+)
- **Python:** `3.12` or higher
- **Node.js:** `24.0.0` or higher (with `npm`)
- **Docker & Docker Compose:** Version 2.20+

### Local Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aaryx/AEGIS.git
   cd AEGIS
   ```

2. **Create and activate a Python virtual environment:**
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install locked Python dependencies:**
   ```bash
   python scripts/dev.py install
   ```

4. **Generate local deployment configuration:**
   ```bash
   python scripts/configure.py
   ```
   *Note: This generates random 256-bit secrets in `.env` without printing them. Never commit this file.*

---

## Environment Configuration

Configuration is environment-driven and strictly validated at startup. Refer to [`.env.example`](.env.example) for all available options:

| Variable | Required | Default | Purpose |
| :--- | :---: | :--- | :--- |
| `ENVIRONMENT` | Yes | `development` | Deployment tier: `development`, `staging`, or `production` |
| `DATABASE_URL` | Yes | `sqlite:///./aegis.db` | PostgreSQL connection URL (enforce `sslmode=verify-full` in production) |
| `REDIS_URL` | Staging/Prod | `redis://localhost:6379/0` | Redis connection URL (`rediss://` required in production) |
| `OPENSEARCH_URL` | Staging/Prod | `http://localhost:9200` | OpenSearch endpoint (`https://` required in production) |
| `AUDIT_SECRET` | Yes | *Generated* | Secret key for HMAC-SHA256 audit chain computation |
| `BOOTSTRAP_USERNAME` | Yes | `admin` | Initial administrator account name |
| `BOOTSTRAP_PASSWORD` | Yes | *Generated* | Initial administrator password |
| `PUBLIC_ORIGIN` | Yes | `http://localhost:3000` | Allowed origin for CSRF and CORS validation |
| `COOKIE_SECURE` | Yes | `false` (Dev) / `true` (Prod) | Enforces HTTPS-only cookies |

---

## Running AEGIS

### 1. Local Development Mode (SQLite & In-Memory Fallbacks)
Run all components concurrently using the developer runner:
```bash
python scripts/dev.py dev
```
This spawns:
- FastAPI API Server on `http://127.0.0.1:8000` (API documentation at `/docs`)
- Background Event Worker
- Notification Delivery Worker
- Next.js Web Console on `http://localhost:3000`

### 2. Staging Mode (Containerized with PostgreSQL, Redis & OpenSearch)
```bash
docker compose up -d --build --wait
```
Verify container health:
```bash
docker compose ps
```

### 3. Hardened Production Overlay
```bash
docker compose -f compose.yaml -f compose.production.yaml up -d
```
*Note: Requires mounting CA certificates in `./certs/` and configuring verified TLS URLs.*

---

## CLI Usage

The AEGIS CLI (`aegis`) provides rich terminal management:

```bash
# Display general help
aegis --help

# Test detection rule compilation and syntax
aegis rules test --all

# Inspect system status and queue depth
aegis system status

# Ingest an event from a JSON payload
aegis events ingest sample_event.json

# Run SOAR playbook simulation (dry run)
aegis playbooks simulate PB-CONTAIN-HOST-01 --entity host-corp-042
```

---

## Testing and Quality Assurance

AEGIS maintains a comprehensive, reproducible verification suite. All canonical verification commands are managed via `scripts/dev.py`:

```bash
# 1. Code Style & Linting (Ruff & TypeScript)
python scripts/dev.py lint

# 2. Type Checking (Mypy & TypeScript)
python scripts/dev.py typecheck

# 3. Security Audits (Bandit, pip-audit, npm audit)
python scripts/dev.py security

# 4. Backend Unit & Regression Suite (Pytest)
pytest --cov=aegis --cov-report=term-missing
# Result: 622 passed, 31 skipped in 290s (83% coverage)

# 5. Detection Rules Test Suite
aegis rules test --all
# Result: 34 passed, 0 failed in 1.82s

# 6. Frontend Unit Test Suite (Vitest)
npm --prefix web test
# Result: 35 passed across 8 test suites in 5.6s

# 7. Frontend Production Bundle Build
npm --prefix web run build
# Result: Compiled successfully; static optimization complete

# 8. Live Integration Gate (Requires Docker Compose)
python scripts/dev.py integration
# Result: 62 passed, 0 skipped (100% integration pass)

# 9. Multi-Tenant Soak Concurrency Smoke Run
python scripts/soak_test.py --workers 4 --duration 15 --rate 100
# Result: 352 events processed across 4 tenants, 0 pending, peak RSS captured, 4/4 audit chains verified
```

---

## Security Architecture & Controls

| Dimension | Implementation | Defensive Invariant |
| :--- | :--- | :--- |
| **Authentication** | Argon2id (`time_cost=3`, `memory_cost=65536`) with timing-safe dummy hash | Mitigates offline dictionary attacks and username enumeration |
| **Authorization** | Strict RBAC (`VIEWER`, `ANALYST`, `SENIOR_ANALYST`, `SOC_MANAGER`, `SECURITY_ADMIN`) | Enforced server-side on every mutating route via `Depends(require(...))` |
| **Multi-Tenancy** | Database queries scoped to `organization_id` with pessimistic row locking | Uniform 404/403 response contract; zero cross-tenant data leaks |
| **CSRF Defense** | Cryptographic token binding + origin validation on state mutations | Mitigates cross-site request forgery when using cookie authentication |
| **Audit Durability** | HMAC-SHA256 hash chains over canonical JSON + durable `AuditHead` tracking | Prevents silent record insertion, modification, or truncation |
| **Disaster Recovery** | Authenticated `AGBK` v1 envelope (Fernet AES-128 + PBKDF2 100k + SHA-256 digest) | Fails closed upon ciphertext corruption or key mismatch |
| **Active Response** | Mandatory two-person approval for destructive actions + netfilter isolation | Isolates host traffic while strictly preserving controller IP/port |

---

## Deployment Profiles

- **Development Profile:** Local SQLite file (`aegis.db`), in-memory queues, self-contained worker processes, relaxed localhost TLS.
- **Staging Profile:** Multi-container Docker Compose with standalone PostgreSQL 17, Redis 7.4, and OpenSearch 3.5 daemons.
- **Production Profile:** Hardened overlay requiring verified TLS handshakes (`sslmode=verify-full`, `rediss://`), dedicated non-root users (`uid 10001`), read-only container filesystems, dropped capabilities (`cap_drop: [ALL]`), and SCRAM-SHA-256 database authentication.

---

## External Qualification Blockers

While all software components and CI stages have passed automated verification, **Production Readiness remains BLOCKED** pending the execution of four external operational prerequisites:

1. **Enterprise PKI:** Provisioning real signed X.509 certificates (`*.aegis.internal`) from an enterprise Certificate Authority into live daemon mount points.
2. **Target Fleet Linux Containment Canary:** Executing agent containment qualification on physical enterprise Linux nodes to validate customer AppArmor and SELinux profiles.
3. **Physical Cloud Disaster Recovery Drill:** Executing a cold restore drill against live AWS S3 Object Lock or GCP Cloud Storage CMEK storage.
4. **24-Hour Continuous Multi-Worker Soak:** Executing an uninterrupted 24-hour endurance load test on dedicated staging PostgreSQL infrastructure.

---

## Contributing and Security Reporting

- **Contributing:** Please review [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, commit conventions, and pull request requirements.
- **Security Vulnerabilities:** DO NOT open public issues for security vulnerabilities. Please review [SECURITY.md](SECURITY.md) and submit confidential reports via [GitHub Private Vulnerability Reporting](https://github.com/aaryx/AEGIS/security/advisories/new) or email `aaryansingh24082005@gmail.com`.

---

## License

AEGIS is licensed under the **[MIT License](LICENSE)**.
Copyright (c) 2026 Aaryan Singh. All rights reserved.
