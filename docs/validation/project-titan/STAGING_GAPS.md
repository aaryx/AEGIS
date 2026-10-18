# TITAN staging qualification handoff

No services started and no shared data modified. `infrastructure.json` records unreachable localhost ports 5432/6379/9200, 7518 MiB physical memory and 1283 MiB available at measurement. A listening port would still not establish target identity. No soak or disruptive drill authorized against an existing shared deployment.

## Prerequisites and safeguards

1. Resolve F-003/F-004 or disable live endpoint response as an enforced deployment policy; resolve credential diagnostic leak F-006 before retained credentialed runs.
2. Provision a dedicated disposable qualification stack with synthetic tenants, isolated volume/project/network, no customer credentials or outbound response destinations. Keep it separate from operational/staging application data. Obtain infrastructure-owner authorization before failure drills and prolonged load.
3. Verify effective SQLAlchemy/libpq target, explicit host/port/database/user, server identity and `current_database()`, `current_user`, `inet_server_addr()` on the connection used for setup. Require a dedicated restricted test role and recorded owner attestation. A database containing 'test' is not proof of isolation. No PG service/host-address/options overrides. Do not use cleanup commands until the target is independently checked.
4. Use a fresh database named with a separated test token. Test runtime/maintenance privileges separately from schema owner. Never run existing broad cleanup/drill scripts against shared staging simply by setting ENVIRONMENT=testing.
5. Provide PKI with correct service DNS and healthcheck SANs; mount only public CA into app containers. Configure HTTPS public origin and secret store. PostgreSQL/Redis TLS requires explicit infrastructure configuration; current overlay does not supply it.

## Required evidence matrix

| Gate | Procedure / exact relevant repository commands | Required artifact |
|---|---|---|
| Clean checkout | After user-authorized version-control workflow, reproduce `.github/workflows/ci.yml` on Python 3.12/Node 24, locked installs | Source SHA, lock hashes, runner/container versions, full logs and artifacts; dirty tree run is insufficient |
| Tenant isolation | `python -m pytest tests/test_security.py tests/test_cerberus.py tests/test_ueba.py tests/test_soar.py tests/test_intelligence.py tests/test_storylines.py -q`; repeat foreign IDs through each detail/export/approval/replay/indirect relationship against real services | Endpoint/role/resource matrix including denied indirect references and absence of foreign effects |
| PostgreSQL | `python -m pytest tests/test_postgres_integration.py tests/test_ueba_live.py -v -ra --junitxml=postgres-live.xml` using verified isolated target | Zero skipped/failed/error cases; upgrade previous-to-current and restricted-role proof |
| Agent receipts | New TITAN wrong-host tests plus `test_agent_security.py`, `test_agent_nonce_replay_invariant.py`; independently run two API processes against one DB | Exactly one accepted duplicate; wrong host/tenant/key, canceled/expired command rejected; restart and rotation/revocation races |
| Audit | Multiprocess writers, chain edits/deletions/head truncation, snapshot verification, restored all-tenant chains | Raw results and independently retained checkpoint comparison; DB+key compromise explicitly excluded |
| Event recovery | Bounded synthetic unique sequence IDs; kill one disposable worker mid-batch, restart; break search separately | Accepted IDs reconcile to processed/DEAD; no unexplained loss; duplicate/conflict behavior; projection convergence |
| SOAR | Dry-run and live-state distinction; revoked approver; simultaneous decisions; timeout/cancel/retry | No external effect in dry-run, no false success, accurate history; disposable OS VM only for agent firewall tests |
| TLS | Correct-CA success; wrong CA, wrong hostname, expired certificate, plaintext endpoint rejection | Actual socket/client outcomes for every application service; no verify=False/insecure bypass |
| Backup/restore | pg_dump verified disposable source; restore into a separately verified fresh disposable destination, without broad cleanup | Artifact checksum, encryption/access evidence, all-tenant counts/FKs/audit/evidence digests, keys and nonce continuity, measured recovery time |
| Monitoring | Exercise dependency failure, worker backlog/DEAD alerts, readiness vs liveness, notification retries, graceful stop | Alert delivery/acknowledgement, recovery evidence; a static runbook alone is insufficient |
| Supply chain | CI pip-audit/npm audit, Trivy, secret scan and CycloneDX SBOM generation | Time-stamped raw output, scanner/db versions, severity policy, retained SBOMs; scan current changes as well as HEAD |

`scripts/integration_gate.py` currently hardcodes localhost HTTP OpenSearch and auto-provisions a DB. It is a development-stack gate, not a production TLS qualification command. Do not execute it verbatim against the TLS staging deployment; adapt reviewed harness configuration first. Its zero-skip assertions are useful but its mocked unit tests prove neither service availability nor clean-checkout reproducibility.

## Bounded performance then optional soak

First define workload with the operator: events/sec, size distribution, tenants, active rules, cardinality, search mix and retention. Start with a short low-rate synthetic run; capture accepted/duplicate/rejected/dead counts, p50/p95/p99 ingest and end-to-end latency, PostgreSQL lock waits, queue depths, search retry depth, process RSS and CPU. Reconcile IDs rather than using counters alone. Set resource stop conditions before starting. No numerical capacity or SLA is asserted here.

After isolated smoke/recovery checks pass and the infrastructure owner authorizes duration and failures, use the existing `ironclad-phase7/SOAK_TEST_PLAN.md` as a draft for a 48-hour run. Review its proposed latency targets rather than silently adopting them as product requirements. Record load profile, periodic trends, fault times, recovery intervals, unexplained loss/duplicates, audit verification and restore result. Abort on integrity failure, unexpected external effect or resource threshold. Independent Antigravity verification must reproduce the attacks and judge the final source, not just read this report.
