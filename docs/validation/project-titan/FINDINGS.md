# TITAN defect register

Severity describes impact, not test count. No CRITICAL finding established. Confirmed: four HIGH, two MEDIUM; one INFORMATIONAL evidence-quality finding. Hypotheses are separate. Fixed findings remain subject to independent verification.

## F-001 ? HIGH ? Test database connection target bypass (fixed locally)

- File/function: `aegis/db_safety.py:validate_test_database_url`.
- Scenario/preconditions: operator supplies a test URL with `?dbname=aegis`, alternate `host`, or libpq `service`; integration fixture calls create_all/migrations on resulting connection. URL path passed the old string check while driver overrides selected another target. SQLite accepted arbitrary filenames; `contest` counted as a test DB; arbitrary backends were accepted.
- Impact: migrations/test writes against operational data, despite reported safety guarantee.
- Evidence: offline SQLAlchemy `create_connect_args` returned `dbname=aegis` for validated `/aegis_test?dbname=aegis`. Six negative cases failed before correction in `regression-before.xml`.
- Existing mitigation: explicit opt-in integration variables, protected-name list; insufficient for effective target.
- Correction: use SQLAlchemy URL parsing, restrict backends/options, explicit test-name token, single explicit host, remote opt-in, reject ambient service/host-address/options overrides; parameterize CREATE DATABASE identifier.
- Reproduction/regression: `tests/test_titan_regressions.py` database tests; no connection required. Existing 36 safety cases retained.
- Verification: automated focused tests pass. No real DB connection. Naming does not prove disposability; admin DSN and actual server identity still require operator verification. Remote opt-in is not production authorization.

## F-002 ? HIGH ? Wrong endpoint can attest another host's command (fixed locally)

- File/function: `aegis/api.py:agent_receipt`.
- Scenario/preconditions: valid key for host B, authorized receipt caller, known same-tenant command for host A; if polled, controller signature is supplied. Signature proves B authored the receipt, but old code did not bind execution target to B.
- Impact: mark A command VERIFIED and update containment state using B's receipt. No cross-tenant breach established.
- Evidence: two real TestClient/SQLite/Ed25519 cases returned HTTP 200 before correction, both before and after command polling. `regression-before.xml`.
- Existing mitigation: tenant filter, signature, action/command ID, nonce, status and revision validation.
- Correction: resolve tenant-owned host and require execution target to match its ID or host name before accepting receipt.
- Regression: `test_signed_receipt_cannot_complete_another_hosts_command[False/True]` asserts 403 and unchanged DISPATCHED state. Existing positive receipt tests still pass.
- Verification: automated tests. These cases use authorized analyst transport, not enrolled-agent bearer authentication; independently repeat with agent tokens and PostgreSQL workers.

## F-003 ? HIGH ? Simulated or failed containment recorded as real enforcement (OPEN)

- Files/functions: `aegis/agent.py:isolate_host,execute_command`; `aegis/api.py:agent_receipt`; `tests/test_agent.py:test_agent_api_registration_and_containment_lifecycle`, `tests/test_soc_end_to_end_acceptance.py`.
- Scenario/preconditions: default simulation_mode=True, or live isolation raises and returns `mode=simulated_fallback`; execute_command signs SUCCESS. API sets `scope=endpoint-live`, `enforced_externally=True`, host ISOLATED without considering signed mode.
- Impact: responders rely on containment that did not occur; signed receipt authenticates a claim, not physical enforcement.
- Evidence: static branches and existing acceptance assertions explicitly expecting enforced_externally=True from a simulated agent. No live action executed.
- Mitigation: signed result includes mode; workflow LocalAdapter correctly labels simulation.
- Safe reproduction: run existing simulated agent test and inspect receipt fields; never run live containment.
- Proposed correction: signed execution mode and explicit success/failure semantics across receipt, heartbeat, entity status, UI and tests; no simulated fallback on live failure. Missing mode must not imply verified physical enforcement.
- Regression required: simulation and subprocess failure cannot set externally-enforced state; live receipt remains an authenticated endpoint assertion.
- Status: confirmed static inspection; left open because correcting receipt alone leaves heartbeat/state/UI contradictions and requires coordinated semantics. Release blocker.

## F-004 ? HIGH ? Linux containment lacks blocking; unisolation flushes unrelated firewall rules (OPEN)

- File/functions: `aegis/agent.py:isolate_host,unisolate_host`.
- Scenario/preconditions: privileged Linux agent with simulation disabled receives approved action. Isolation only appends ACCEPT rules, without a DROP/REJECT rule or policy. Unisolation runs `iptables -F`, with return code unchecked.
- Impact: false containment, removal of unrelated host firewall policy; failure may still report success. Windows block/allow precedence also needs platform verification, but is not claimed reproduced here.
- Evidence: static subprocess argument arrays. Do not reproduce on the developer machine.
- Mitigation: simulation defaults on; approval and signed command path constrain invocation.
- Proposed correction: dedicated AEGIS-owned chains/rules, atomic apply/rollback, verified return codes, safe recovery preserving existing policy and controller connectivity. Restrict pilot to no live endpoint response until qualified.
- Regression required: mock command recording followed by disposable Linux VM network tests with preexisting firewall rules; failed apply/remove must fail closed. Restart recovery and Windows firewall tests separately.
- Status: static confirmation; no live execution. Not patched by speculative cross-platform firewall changes.

## F-005 ? MEDIUM ? Application CA path absent from production containers (fixed statically)

- File: `compose.production.yaml:x-app-production`.
- Scenario: production overlay sets OPENSEARCH_CA but mounted certificates only into OpenSearch; fresh application image lacks that file.
- Impact: TLS connections/initialization fail; production overlay is not qualified deployment evidence.
- Mitigation: client verify_certs=True; fails rather than silently downgrading.
- Correction: read-only bind of public CA only to API, worker, initializer, retention, notifications; fail if host file absent. No node private key exposed to application services.
- Regression: `test_production_application_services_mount_only_public_ca` parses YAML; verifies target, shared services, read-only and no auto-create. Static wiring only, not Compose/runtime proof.
- Remaining: certificate SANs (including healthcheck localhost), permissions, production origin, OpenSearch security bootstrap, live handshake and negative TLS tests.

## F-006 ? MEDIUM ? Integration failure diagnostics can expose connection credentials (OPEN)

- Files/functions: `tests/test_postgres_integration.py:pg_engine` includes raw POSTGRES_TEST_URL and exception in pytest.skip; `scripts/integration_gate.py:main` streams raw child output and prints database preparation exception.
- Preconditions: configured URL with password, failed DB connection/preparation, artifact/log access.
- Impact: CI/staging credentials in logs. Claims that credentials never print are not supported by mocked success-output tests.
- Mitigation: normal application generic error sanitization does not protect these test paths.
- Safe reproduction: monkeypatch connect/preparation to fail with synthetic sentinel credential; assert sentinel absent from captured stderr/stdout/skip reason.
- Proposed correction: fixed safe error codes and bounded redaction before streaming; no raw DSN/driver error. Add failure-output tests. Not run; static confirmed explicit raw interpolation. Must resolve before credentialed integration runs whose logs are retained.

## F-007 ? INFORMATIONAL ? Qualification evidence overstates deployment guarantees (OPEN documentation correction supplied here)

- Files: `docs/validation/ironclad-phase7/REPORT.md`, `STATUS.md`; DR and Redis tests.
- Scenario: passing SQLite dump/restore and mocked gate tests treated as live PostgreSQL/CI proof; Redis demonstration treated as pipeline queue validation.
- Impact: inaccurate release decisions, not a standalone exploit.
- Evidence: DR test uses SQLite iterdump/executescript; gate tests replace prepare_test_database and child process; UEBA live fixture is gated first by PostgreSQL URL, not a dedicated OpenSearch-only fixture.
- Correction: this handoff labels local, mocked, blocked and not-run evidence explicitly; historical reports preserved.
- Verification: static inspection and current raw execution evidence. Independent clean-checkout and real service evidence required.

## Hypotheses / important controls not yet proven

- H-001: concurrent ingest count-then-insert can exceed queue_capacity; safely measure separate PostgreSQL sessions before deciding on reservation mechanism (bounded-impact backpressure issue).
- H-002: lock ordering among tenant, audit head and window locks may deadlock or starve under multiworker load. Inspect pg_locks and bounded statement timeouts; do not infer correctness from SQLite threads.
- H-003: agent key rotation/revocation racing receipt checks may accept a key read before revocation. Needs deterministic PostgreSQL race reproduction.
- Production PostgreSQL/Redis encryption is not enforced by Settings/Compose. This is a confirmed configuration gap; severity depends on deployment network threat model. Required transport gate remains BLOCKED.
- Exhaustive indirect cross-tenant relationship coverage and constrained runtime-role migration behavior remain unverified.
