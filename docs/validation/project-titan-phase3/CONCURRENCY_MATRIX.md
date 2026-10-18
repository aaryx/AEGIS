# AEGIS TITAN PHASE 3 — CONCURRENCY & LOCK HIERARCHY MATRIX

**Date:** 2026-10-18  
**Scope:** Concurrency controls, pessimistic lock ordering, deadlock avoidance, and capacity invariants across the AEGIS data plane.

---

## 1. Global Lock Hierarchy

To prevent AB-BA deadlocks in PostgreSQL across concurrent transactions handling tenant operations, event ingestion, audit chain updates, and SOAR execution, AEGIS enforces a strict monotonic lock ordering:

```
┌─────────────────────────────────────────────────────────┐
│ 1. Tenant State (Organization Row via lock_tenant)      │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Audit Head (AuditHead Row via with_for_update)       │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 3. Domain Entity Rows (Agent, PlaybookExecution, etc.)   │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 4. Window State (WindowState Row in Detection Workers)  │
└─────────────────────────────────────────────────────────┘
```

### Invariant Rules
1. **Never acquire a higher-ranked lock while holding a lower-ranked lock.**
   - An operation holding `AuditHead` (Rank 2) must never attempt to acquire `Organization` (Rank 1).
   - In `aegis/security.py`, `audit()` acquires `Organization` before acquiring `AuditHead`.
2. **Never hold database locks across external network operations.**
   - Outbound HTTP requests (e.g., threat intelligence providers, notification webhooks, AI model endpoints) and socket operations must execute outside of transactional lock scopes.
3. **Keep locked transactions as brief as possible.**
   - Heavy parsing, normalization, and hashing operations must be performed in memory before acquiring locks or inside bounded batch boundaries.
4. **Always scope resource locks to the tenant.**
   - All `select(...).with_for_update()` queries MUST include `where(Model.organization_id == principal.organization_id)`.

---

## 2. Concurrency Path Analysis & Invariants

| Path / Function | Lock Ordering | Concurrency Invariant | Rollback Behavior | Failure Mode |
| :--- | :--- | :--- | :--- | :--- |
| **`ingest()`** (`aegis/pipeline.py`) | 1. `Organization` (via `lock_tenant`)<br/>2. `AuditHead` (via `audit()`) | Ingestion capacity invariant: `depth + search_depth + new_count <= queue_capacity` is evaluated under tenant lock. No concurrent request can exceed capacity. | Transaction rolls back all inserted `EventRecord` rows; backlog depth remains uncorrupted. | `OverflowError` (mapped to HTTP 429) when queue capacity is reached. |
| **`audit()`** (`aegis/security.py`) | 1. `Organization`<br/>2. `AuditHead`<br/>3. `AuditLog` (append) | Monotonic HMAC-SHA256 audit chaining: `AuditHead` sequence number and hash are updated atomically under tenant lock. | Rollback leaves `AuditHead` unchanged; sequence numbers remain contiguous. | Database error if lock timeout exceeded; bounded retries safe. |
| **`revoke_agent()`** (`aegis/api.py`) | 1. `Organization` (via `lock_tenant`)<br/>2. `Agent` (`with_for_update`)<br/>3. `PlaybookExecution` (`with_for_update`)<br/>4. `AuditHead` (via `audit()`) | In-flight execution cancellation: all active commands (`REQUESTED`, `APPROVED`, `DISPATCHED`, `EXECUTING`) for the revoked agent are atomically transitioned to `CANCELLED`. | Atomic rollback restores previous agent status and execution states. | HTTP 404 if agent not found; HTTP 403 if caller lacks `agents.revoke`. |
| **`agent_commands()`** (`aegis/api.py`) | 1. `Organization` (via `lock_tenant`)<br/>2. `Agent` (`with_for_update`) | Command poll authorization: command dispatch requires the agent to exist, be owned by the tenant, and hold `status == "ENROLLED"`. | Read/update rollback leaves command in queue. | HTTP 403 if agent is revoked, missing, or unauthorized. |
| **`agent_receipt()`** (`aegis/api.py`) | 1. `Organization` (via `lock_tenant`)<br/>2. `Agent` (`with_for_update`)<br/>3. `PlaybookExecution` (`with_for_update`)<br/>4. `AuditHead` (via `audit()`) | Revocation-receipt synchronization: receipt verification requires `agent.status == "ENROLLED"`. If an agent is revoked concurrently, receipt submission is rejected. Duplicate receipts are rejected via monotonic nonce cache. | Execution remains in current state; containment status is not asserted. | HTTP 403 if agent revoked; HTTP 409 if execution already cancelled or finished; HTTP 400 if signature invalid. |
| **`advance_window()`** (`aegis/storylines.py`) | 1. `Organization` (via `lock_tenant`)<br/>2. `AuditHead` (via `audit()`)<br/>3. `WindowState` (`with_for_update`) | State isolation: window state transitions are serialized per rule and tenant. | Rollback aborts detection window without partial alert emission. | Lock timeout recovery; workers retry on next tick. |

---

## 3. High-Priority Invariants Detail

### Invariant H-001: Queue Capacity
$$\sum (\text{Pending Events} + \text{Unindexed Search Jobs} + \text{Incoming Events}) \le C_{\text{queue}}$$
- **Mechanism:** Serialized by `lock_tenant(db, organization_id)` in `aegis/pipeline.py` before querying backlog counts.
- **Multi-Tenant Isolation:** Because `lock_tenant` executes `SELECT id FROM organizations WHERE id = :id FOR UPDATE`, saturation or high contention in Tenant $T_A$ does not introduce latency or lock contention for Tenant $T_B$.

### Invariant H-002: Deadlock Freedom
- **Proof of Acyclicity:** All code paths acquire locks according to the partial order $\prec$:
  $$\text{Organization} \prec \text{AuditHead} \prec \text{Agent} \prec \text{PlaybookExecution} \prec \text{WindowState}$$
- No code path requests a lock $L_1$ while holding $L_2$ where $L_2 \prec L_1$.
- Consequently, the wait-for graph contains no cycles, eliminating deadlocks between tenant operations, audit logging, and SOAR execution.

### Invariant H-003: Agent Revocation and Receipt Atomicity
$$\text{Receipt Verified} \implies \text{Agent Enrolled at Verification Time} \land \text{Command In-Flight at Verification Time}$$
- When `revoke_agent` executes:
  1. Row lock on `Agent` is held.
  2. `agent.status` is set to `"REVOKED"`.
  3. Row locks on all targeting `PlaybookExecution` rows are held.
  4. Executions transition to `"CANCELLED"`.
- When `agent_receipt` executes:
  1. Row lock on `Agent` is acquired under `lock_tenant`.
  2. If `agent.status != "ENROLLED"`, it immediately fails closed (HTTP 403).
  3. Row lock on `PlaybookExecution` is acquired.
  4. If `execution.status` is not in `{"APPROVED", "DISPATCHED"}`, it fails closed (HTTP 409).
- **Result:** It is mathematically impossible for a revoked agent key to complete an in-flight execution, and impossible for a command to remain active after agent revocation.
