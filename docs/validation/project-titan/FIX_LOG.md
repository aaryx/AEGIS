# TITAN fix log and preservation record

Baseline: `feature/ironclad-qualification`, HEAD `33a5ea90a964e206fa63326322e46d296ae2efb1`. Initial tracked changes: 13, listed in `initial-status.txt`. Initial tracked patch saved as `initial-tracked.patch` for comparison; preexisting untracked reports/tests were preserved. No Git publishing operations.

| Change | Minimal correction | Compatibility / evidence |
|---|---|---|
| `aegis/api.py` (already modified) | Receipt target must match authenticated tenant's named host | Existing legitimate agent tests pass. Host-name and entity-ID targets retained. Wrong-host requests now 403. No schema migration. |
| `aegis/db_safety.py` (already untracked) | Effective-target parsing and fail-closed validation; SQL identifier composition | Explicit local test URLs and TLS options retained. Ambiguous filenames, substring names, unsupported backends, target overrides intentionally rejected. Remote tests need explicit opt-in and operator isolation verification. |
| `compose.production.yaml` (already untracked) | Shared application CA bind, public certificate only | Requires existing CA file; deployment not executed. |
| `tests/test_titan_regressions.py` (new) | 14 offline regressions: 12 DB/deployment checks, two signed wrong-host API cases | First eight cases failed before fixes. No real firewall commands/database services. |
| `docs/validation/project-titan/` (new) | Six handoff reports, raw logs/XML, baseline and checkpoint | Historical IRONCLAD reports unchanged. |

Focused tests were executed before broader tests. No added dependencies, public API schema changes, migration edits or unrelated formatting. Existing tests asserting simulated enforcement were not weakened to hide F-003; their passing result is explicitly insufficient.

Deferred high-risk changes: F-003 needs coherent mode/status semantics across agent/heartbeat/API/UI; F-004 needs OS-specific rule ownership, rollback and isolated network validation. Do not enable live response pending those corrections. F-006 requires failure-path diagnostic sanitization before retained credentialed live runs.

Independent reviewer should inspect additions relative to initial-tracked.patch, not attribute all existing modifications to this pass. Baseline patch was captured by PowerShell; it is review evidence, not a recovery/restore instruction.
