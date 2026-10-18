# TITAN execution evidence

Date: 2026-10-18. Commands ran from `D:\Project\Aegis` using existing `.venv` (Python 3.14.3) and existing web node_modules. No clean install/checkout proof. Raw stdout/stderr and JUnit are retained here. `counts.json` is derived from XML, not estimated from test names.

## Python test runs

PowerShell set `AEGIS_POSTGRES_TEST_URL` and `AEGIS_INTEGRATION` to empty for focused/full runs, deliberately keeping external suites off unverified databases. No new skips were added. All listed paths after `--basetemp` were newly created for this audit; after completion they were moved without deletion into ignored `test-results/project-titan-temp/`.

1. Before fixes:
   `.venv/Scripts/python -m pytest tests/test_titan_regressions.py -q --tb=short --basetemp=.pytest_titan_before --junitxml=docs/validation/project-titan/regression-before.xml`
   Result: **0 passed, 8 failed, 0 skipped, 0 errors**, 1.579s, three warnings. Files: `regression-before.txt/.xml`. The initial PowerShell wrapper ended with Get-Content and returned 0; the pytest process exit code was not separately retained. Do not mistake wrapper success for test success. XML proves all eight failure reproductions.
2. First focused after fixes:
   `.venv/Scripts/python -m pytest tests/test_titan_regressions.py tests/test_database_safety.py tests/test_agent_security.py tests/test_agent_nonce_replay_invariant.py tests/test_ci_release_gate.py -q --tb=short -p no:cacheprovider --basetemp=.pytest_titan_focused --junitxml=docs/validation/project-titan/focused.xml`
   Result: **76 passed, 0 failed, 0 skipped, 0 errors**, 11.467s, exit **0**, one warning. Files: `focused.txt/.xml`.
3. Final focused (additional DB/environment/CA tests):
   `.venv/Scripts/python -m pytest tests/test_titan_regressions.py tests/test_database_safety.py tests/test_agent_security.py tests/test_agent_nonce_replay_invariant.py tests/test_ci_release_gate.py tests/test_opensearch_hardening.py -q --tb=short -p no:cacheprovider --basetemp=.pytest_titan_focused2 --junitxml=docs/validation/project-titan/focused-final.xml`
   Result: **85 passed, 0 failed, 0 skipped, 0 errors**, 11.343s, exit **0**, one warning. Files: `focused-final.txt/.xml`.
4. Full suite:
   `.venv/Scripts/python -m pytest -q -rs --tb=short -p no:cacheprovider --basetemp=.pytest_titan_full --junitxml=docs/validation/project-titan/full.xml`
   Result: **457 passed, 27 skipped, 0 failed, 0 errors**, 213.207s, exit **0**, three warnings. Files: `full.txt/.xml`.

Reconciliation: 484 total = historical 470 + 14 new tests; 457 passes = historical 443 + 14. This reconciles counts, not a claim that the baseline full suite was separately executed this turn. Skips: 21 PostgreSQL tests, 4 UEBA live tests (shared PostgreSQL fixture), 2 external-service integration tests. Full raw skip reasons are in full.txt. Skipped tests provide no positive release evidence.

Warnings: Starlette httpx TestClient deprecation; full suite also two Typer/Click stream helper deprecations. Before-fix run had two pytest cache path warnings; later runs disabled cache provider, without changing assertions/skips.

## Other checks

| Exact command | Result / exit | Duration / evidence |
|---|---|---|
| `npm.cmd --prefix web test` | 7 files, **27 passed**, no reported skipped/failed; exit 0 | Vitest 4.64s; `frontend.txt` |
| `npm.cmd --prefix web run build` | Next.js 16.4.0 build and generated routes succeeded; exit 0 | Total wall duration not captured; stage durations in `build.txt` |
| `npm.cmd --prefix web run typecheck` | PASS; exit 0 | measured 3.014s; `frontend-types.txt` |
| `.venv/Scripts/python -m ruff check aegis tests scripts` | All checks passed; exit 0 | tool wall 1.709s; `ruff.txt` |
| `.venv/Scripts/python -m mypy aegis` | No issues in 39 source files; exit 0 | Total duration not captured; `mypy.txt` |
| `.venv/Scripts/python -m bandit -r aegis scripts -ll -q` | No findings at requested threshold; exit 0 | tool wall 3.048s; annotation/no-test warnings in `bandit.txt`; not a dependency vulnerability scan |
| `.venv/Scripts/aegis rules test --all` | PASS; exit 0 | measured 3.360s; per-rule results in `rules.txt` |
| `git diff --check` | FAIL, exit **2**, preexisting EOF blank line in `tests/test_opensearch_hardening.py:130` | `diff-check.txt`; untouched by this pass, CRLF conversion warnings also present |

Durations explicitly marked not captured cannot be reconstructed from staged asynchronous polling. Test count columns do not apply to lint/build/type checks.

## Evidence boundaries

- Verified by execution: local API behavior using TestClient/SQLite, real Ed25519 signing/verification, local test suite, frontend build and test commands, offline SQLAlchemy connection argument resolution, port availability probe.
- Verified by automated tests: target ownership denial, database URL guards, CA YAML wiring, existing unit/API cases. YAML test is not Docker Compose runtime validation.
- Mocked or simulated: CI gate subprocess/preparation, OpenSearch constructor, external integrations, endpoint containment, SQLite backup/restore. Passing these does not prove real service guarantees.
- Blocked: live PostgreSQL/Redis/OpenSearch, production TLS, cross-process receipt/audit races, real restore; ports unreachable and no verified disposable infrastructure. No service start attempted.
- Not run: clean-checkout CI, browser E2E, image scan/SBOM generation, current dependency vulnerability scans, secret scanner, load benchmark/soak, disruptive recovery drills. Existing CI configuration and old reports are not fresh results.
- Not applicable: real external containment execution on this workstation; explicitly excluded from safe local qualification.

No current dependency-vulnerability clearance is claimed. Independent verification must run those scans with current advisory data in its authorized CI environment.
