# AEGIS IRONCLAD PHASE 7 — STAGING SOAK & FAILURE INJECTION PLAN

**Target Environment:** Multi-Node Controlled Staging Environment  
**Execution Window:** 48 Continuous Hours  
**Audit Roles:** Senior SRE, PostgreSQL Reliability Engineer, Principal Platform Architect  
**Purpose:** Formal specification for the multi-day sustained soak and fault-injection test required to graduate AEGIS from Controlled Staging to a Limited Production Pilot.  

---

## 1. Objectives & Qualification Scope

Before AEGIS can ingest live enterprise security telemetry, it must demonstrate empirical resilience under sustained load and simulated infrastructure degradation. This soak test evaluates:
1. **Memory Stability:** Absence of heap leaks in Python API workers, background Celery/async workers, and Next.js frontend services over 48 hours.
2. **Database Connection Pool Resilience:** Prevention of connection leaks or starvation in PostgreSQL under high concurrency.
3. **Queue & Ingestion Backpressure:** Deterministic queuing and zero event loss during worker failover and restart.
4. **Audit Chain Cryptographic Continuity:** Zero hash breaks or missing sequence IDs across millions of concurrently ingested events.
5. **Fault Recovery:** Automated recovery from transient network partitions, Redis restarts, and worker process termination.

---

## 2. Infrastructure Topology

| Component | Node Spec | Configuration Details |
|---|---|---|
| **AEGIS Ingestion API** | 2 Nodes (4 vCPU, 8 GB RAM) | FastAPI running under Uvicorn with 4 worker processes per node |
| **AEGIS Background Worker** | 2 Nodes (4 vCPU, 8 GB RAM) | Polling `EventRecord` with `SKIP LOCKED`, batch size 100 |
| **PostgreSQL 17** | 1 Primary Node (8 vCPU, 32 GB RAM) | `max_connections=300`, `shared_buffers=8GB`, SSD storage |
| **OpenSearch 2.19.1** | 3-Node Cluster (4 vCPU, 16 GB RAM) | JVM heap 8 GB per node, TLS enabled on transport (9300) and HTTP (9200) |
| **Redis 7.2** | 1 Node (2 vCPU, 4 GB RAM) | `maxmemory 2gb`, `maxmemory-policy noeviction` (Rate limiting & caching) |
| **Synthetic Load Generator** | 1 Node (8 vCPU, 16 GB RAM) | Locust / Python asynchronous event streaming generator |

---

## 3. Workload Profile

### A. Traffic Distribution & Rates
- **Sustained Baseline:** 500 Events Per Second (EPS) continuous throughput for 48 hours (~86.4 million events total).
- **Periodic Burst Windows:** Every 4 hours, execute a 15-minute burst at 2,000 EPS to simulate sudden incident telemetry influx.
- **Event Composition:**
  * 50% Authentication Logs (Syslog RFC 5424, CEF format)
  * 25% Endpoint Process Execution Logs (Windows Event ID 4688 / Sysmon)
  * 15% Cloud Infrastructure Audits (AWS CloudTrail / GCP Audit)
  * 10% Agent Command Dispatches and Cryptographic Nonce Receipts

### B. Tenant Segregation
- Traffic generated across 5 distinct synthetic tenant organizations:
  * Tenant 1 (Finance): 40% volume
  * Tenant 2 (Healthcare): 30% volume
  * Tenant 3 (Retail): 15% volume
  * Tenant 4 (Tech): 10% volume
  * Tenant 5 (Isolated/Restricted): 5% volume

---

## 4. Controlled Failure Injection Schedule

To prove reliability under realistic operational faults, the following controlled disruptions will be injected into the staging cluster:

```mermaid
gantt
    title 48-Hour Staging Soak Test Execution Timeline
    dateFormat HH
    axisFormat %H:00
    section Baseline
    Sustained Ingestion (500 EPS) :active, 00, 48h
    section Fault Injections
    Fault 1: PG Network Partition (30s) :crit, 12, 1h
    Fault 2: Redis Process Restart      :crit, 24, 1h
    Fault 3: OpenSearch Search Slowdown :crit, 36, 1h
    Fault 4: Worker SIGKILL & Recovery   :crit, 42, 1h
    section Audit Checks
    Genesis Audit Hash Check :milestone, 00, 0h
    Midpoint Audit Verification :milestone, 24, 0h
    Final Audit Continuity Check :milestone, 48, 0h
```

### Fault 1: Transient Database Network Partition (Hour 12)
- **Action:** Inject 30 seconds of iptables packet drop between API workers and PostgreSQL.
- **Expected Behavior:** API ingestion buffers incoming events in memory or returns structured HTTP 429/503; worker connection pool triggers reconnection loop without process crash; zero permanently corrupted transactions.

### Fault 2: Redis Service Restart (Hour 24)
- **Action:** Execute `docker restart aegis-redis` or Kubernetes pod deletion.
- **Expected Behavior:** Rate-limiting middleware gracefully handles temporary socket errors without blocking legitimate SOC operations; reconnects within 5 seconds.

### Fault 3: OpenSearch Indexing Delay Injection (Hour 36)
- **Action:** Throttle OpenSearch indexing threads using cluster settings to introduce 5-second latency.
- **Expected Behavior:** Workers observe indexing backpressure and preserve unprocessed events in PostgreSQL `PENDING` state; queue depth increases safely without memory ballooning.

### Fault 4: Worker Process SIGKILL (Hour 42)
- **Action:** Abruptly terminate 2 active `aegis-worker` processes during peak burst.
- **Expected Behavior:** Orphaned records in `PROCESSING` state transition back to `PENDING` via heartbeat timeout; replacement worker processes pick up backlog with zero lost updates.

---

## 5. Measurable Performance Indicators & SLA Thresholds

| Metric | Target SLA | Critical Failure Threshold |
|---|---|---|
| **Ingestion API Latency (p50)** | $< 35\text{ ms}$ | $> 100\text{ ms}$ |
| **Ingestion API Latency (p95)** | $< 150\text{ ms}$ | $> 350\text{ ms}$ |
| **Ingestion API Latency (p99)** | $< 350\text{ ms}$ | $> 1,000\text{ ms}$ |
| **End-to-End Processing Time** | $< 2.0\text{ seconds}$ | $> 10.0\text{ seconds}$ |
| **Dropped Events** | Exactly `0` | $> 0$ |
| **API Error Rate (5xx)** | $< 0.001\%$ | $> 0.01\%$ |
| **Process Memory Slope** | Flat ($\pm 5\%$) after Hour 4 | Continuous upward growth (Memory leak) |
| **PostgreSQL Connection Leaks** | Active connections $\le 80\%$ of pool | Connection pool saturation |
| **Audit Chain Hash Breaks** | Exactly `0` breaks | $\ge 1$ break |

---

## 6. Audit Chain Integrity Verification Routine

At Hour 0 (Genesis), Hour 24 (Midpoint), and Hour 48 (Completion), run the standalone audit validation script:

```bash
python scripts/verify_audit_chain.py --tenant-id all --verbose
```

### Verification Criteria:
1. Every audit log record references the valid SHA-256 digest of the immediate predecessor in chronological order.
2. The HMAC signature of each record matches the master `AUDIT_SECRET`.
3. Zero missing or skipped sequence numbers exist in the tenant event log.

---

## 7. Go/No-Go Decision Criteria for Production Pilot

The platform is approved for advancement to **Limited Production Pilot** if and only if all of the following conditions are met at the conclusion of the 48-hour run:
- [ ] Ingestion throughput remained stable at $\ge 500\text{ EPS}$ across the full 48-hour duration.
- [ ] Exactly 0 events were dropped, corrupted, or unrecoverably lost.
- [ ] API p95 latency remained under 150 ms (excluding controlled fault windows).
- [ ] Memory consumption across all application services remained stable with no upward drift.
- [ ] All 4 controlled failure injections recovered automatically within SLA bounds.
- [ ] Cryptographic audit chain verification passed with 100% integrity across all tenants.
- [ ] Zero unhandled tracebacks or database deadlocks were recorded in centralized logs.
