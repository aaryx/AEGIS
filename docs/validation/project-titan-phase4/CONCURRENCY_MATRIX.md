# Concurrency and transaction evidence

| Scenario | Synchronization / expected outcome | Observed local result |
| --- | --- | --- |
| Ingestion contender while first insert is uncommitted | Events signal admission attempt; owner commits only after contender reaches gate; capacity one accepts exactly one | Passed on SQLite |
| Same schedule, owner rolls back | Contender accepts; exactly one event, collector count and audit record remain | Passed on SQLite |
| Four simultaneous requests across two tenants | Barrier; one admission per tenant; duplicate succeeds as duplicate; distinct over-capacity request rejects | Passed on SQLite |
| First AuditHead creation | Capture SQL; tenant UPDATE must precede INSERT | Failed before correction, passed after |
| Receipt paused during Ed25519 verification | Revocation attempts tenant lock while receipt owns it; receipt commits first, revocation then succeeds | Passed via real HTTP routes and SQLite; no signature mocking |
| Receipt paused at execution UPDATE | Same ordering immediately before persistence | Passed; receipt evidence retained after revocation |
| Revocation precedes receipt | Existing Phase 3 tests reject both agent and operator submissions | Passed in full local suite |
| Duplicate receipts, nonce replay, signatures, command and tenant binding | Existing agent, nonce, containment and TITAN suites | Covered by full regression run |
| Deadlock / serialization / lock timeout / statement cancellation / disconnect | Inject DBAPI failure after audit write; entire transaction rolls back, event attempts unchanged; subsequent iteration succeeds | Five synthetic failure cases passed; not real disconnect evidence |
| PostgreSQL commit/rollback admission | Same controlled schedule, isolated real PostgreSQL, connection and statement time limits | Not executed locally; three new PostgreSQL cases required by release gate |
| PostgreSQL first-head concurrency | Tenant owner overlaps audit contender; both entries must persist and chain verify | Not executed locally |
| Redis outage, OpenSearch outbox recovery, database failover | Existing distributed gate and CI drills | Not executed locally; services unavailable |

## Lock map and rules

`soar.lock_tenant` issues a non-key Organization UPDATE and holds its lock through the caller's transaction. It suppresses ORM autoflush during acquisition. SQLite serializes writers globally; this is not evidence of PostgreSQL tenant parallelism.

Acquire all required tenant gates in ascending tenant-ID order before resource writes/row locks/advisory locks. No helper commits while holding a gate. Re-read mutable authorization/eligibility state after waiting. Under each gate, resource/window writes and audit appends serialize against other operations following the same gate. The earlier claim that every path takes AuditHead before resources was inaccurate: receipts legitimately touch nonce windows and executions before appending audit, all under the tenant gate.

| Path | Acquisition / transaction scope |
| --- | --- |
| Ingestion | Tenant -> capacity read -> event/collector writes -> AuditHead -> audit log; caller commit |
| Receipt / revocation | Tenant -> refreshed Agent -> execution/nonce/resource -> audit; endpoint commit |
| Audit helper | Tenant -> AuditHead creation/upsert -> locked head -> log and mirrored organization head |
| Detection worker | Candidate IDs without locks -> sorted tenant gates -> eligible event rows -> detection windows/entities -> audit/outbox; one transaction |
| UEBA worker | Candidate without lock -> tenant -> eligible job -> analysis; one transaction |
| Storyline correlation | Tenant -> PostgreSQL advisory transaction lock -> incident/member/resource rows -> audit |
| Notification dispatch | Candidate delivery IDs -> sorted tenant gates -> delivery/resources -> external delivery -> audit; retains at-least-once external delivery semantics |
| Retention cycle | Sorted tenant gates -> global expired transient rows -> bounded tenant event deletes -> audit; one transaction |
| Rate limiter | Redis transaction or independent short database WindowState transaction; no nested tenant acquisition |
| Search projection | SearchJob row locks and idempotent external indexing; does not acquire tenant gate or append audit |

API login, reset, enrollment, rule mutations, status updates and search retries now obtain the tenant gate before explicit resource locks. Bootstrap lookup reads do not authorize mutations; locked queries repeat validity checks. Existing SOAR and intelligence paths already use tenant gates.

This reduces known inversions; it is not a proof that every implicit lock, foreign-key check or future caller is deadlock-free. Runtime PostgreSQL lock waits are bounded to five seconds and statements to thirty seconds. Real multi-process adversarial load, timeout recovery and tenant fairness remain pilot prerequisites.

## Costs and operational limits

Serializing tenant writes trades throughput for correctness. Multi-tenant batches can delay unrelated tenants; retention acquires all existing tenant gates and notification delivery still holds transaction locks across bounded network calls. Qualify this contention under production-shaped load before a pilot. No larger timeout was used to hide a deadlock. No automatic replay of externally visible side effects was introduced. Poison-event retries remain bounded by existing settings; infrastructure transaction failures remain pending for later worker iterations.
