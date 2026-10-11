# Verification record — 2026-09-28

**Historical baseline below.** The subsequent hardening changes, current test
counts, recovery measurements and remaining gates are in [hardening.md](hardening.md).
In particular, detection state is now transactional, live file collection and
outbound integrations exist, and the API image has 2 high/0 critical findings.

## Executed checks

| Check | Actual result |
|---|---|
| Python unit/API/security/pipeline suite | 100 passed, 1 optional dependency test skipped |
| Built-in positive/negative detection checks | 34 rules passed |
| Frontend Vitest tests | 5 passed |
| Python type check | No issues in 19 modules |
| TypeScript check | Passed |
| Next.js production build | Passed on Windows and in Linux container |
| Playwright local acceptance | Passed: login, dashboard, alert evidence, AI summary, incident notes, report download, hunt, rule validation, logout |
| Playwright Compose acceptance | Passed against real PostgreSQL/Redis/OpenSearch-backed API; desktop/mobile screenshots inspected |
| Docker builds/startup | API and Web built; PostgreSQL, Redis, OpenSearch, API, worker and Web healthy |
| Compose CLI/API attack-chain acceptance | Passed: ingest → worker → detections → incident → search → investigation → report → audit verification |
| Distributed integration script | 9 checks passed, including PostgreSQL audit trigger, real search cursor/tenant scope and Redis replay |
| Ruff | Passed |
| Bandit | No findings after reviewed narrow annotations for fixed developer subprocesses and protocol labels |
| Python dependency audit | No known vulnerabilities in installed audited packages; editable project has no advisory entry |
| npm audit | 0 vulnerabilities |
| Web image Docker Scout high/critical scan | 0 high/critical findings after OS updates and removal of unused package managers |
| API image Docker Scout high/critical scan | **11 remaining: 2 critical, 9 high**, in Debian perl, util-linux and zlib; scanner reports no fixed versions |
| CycloneDX SBOM | Generated for the final API image at `local-data/aegis-api.cdx.json` |

Container findings with available fixes were remediated: OpenSSL, PCRE2 and
unused bundled packaging dependencies. Remaining base-image findings are not
silently ignored or represented as a clean production image. CI includes a
fixable-high/critical gate; unfixable findings require operational review.

The optional pytest dependency test is skipped unless AEGIS_INTEGRATION=1.
Distributed verification was nevertheless run separately inside the built API
image using `scripts/integration_checks.py` against the real Compose services.

An early PostgreSQL run caught unsupported DISTINCT on JSON evidence columns;
the shared investigation queries were corrected to select through ID subqueries.
One browser run overlapped a deliberate container restart and failed at login;
the same test passed after services became healthy. No failing assertion was
removed to conceal an implementation defect.

## Genuine limits relative to the requested enterprise specification

This is an operational implementation, **not a claim that every item in the
master specification or production certification has been completed**.

- Native Windows Event Log/journald/container polling and live cloud collectors
  are not installed; exported records are ingested through working parsers.
- External threat-feed, GeoIP/ASN and email/webhook/Slack/Teams dispatch are not
  installed. IOC intelligence and durable in-application notifications work.
- External EDR/IAM/firewall containment is not installed. The provider records
  local policy intent and explicitly returns no remote enforcement.
- External OpenAI/Azure requests were not exercised with live credentials.
  Local evidence analysis works; model semantic accuracy is not guaranteed.
- MITRE coverage is a curated catalog for bundled rules, not the entire matrix.
- Role sets are code-defined; custom roles, SSO/MFA and DB-level RLS are absent.
- No automated hot/warm/delete lifecycle, legal-hold service or scheduled backup
  runner is installed. Retention does not silently remove evidence.
- Detection state has bounded 10k-event windows, per-tenant serialization,
  bucket cooldowns and limited late/out-of-order event handling. No exactly-once
  guarantee is made. Redis writes and PostgreSQL transactions are not atomic.
- Source evidence is retained in PostgreSQL as a durable authoritative copy;
  production search uses OpenSearch. Large tenants need measured partitioning,
  data lifecycle and storage cost work before high-volume rollout.
- Reports and investigation responses expose a bounded 500-event evidence scope.
  Reporting is incident-centric; executive/detection report templates are absent.
- Dashboard shows actual counts, severities, rules and entities, but not every
  requested time-series chart or field-specific pivot workflow.
- Frontend navigation is a single workspace route; deep-linkable screens,
  complete localization and nonce-based strict CSP are not implemented.
- Performance/load commands exist, but no sustained throughput/SLA numbers,
  disaster-recovery timing, penetration test or full endpoint-per-role proof is claimed.
- API image has the residual unfixed high/critical base-package findings above.
  PostgreSQL/Redis/OpenSearch vendor images were not included in the two app-image scans.
- GitHub Actions was authored but not run on GitHub in this session. Container
  build provenance is available; action references are version tags, not commit pins.

See the threat model and deployment guide for the trust assumptions and controls
required before collecting real organizational security data.
