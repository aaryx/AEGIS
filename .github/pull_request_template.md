## Summary

<!-- Briefly describe the purpose of this PR and what problem it solves. -->

## Changes Made

<!-- Bullet points summarizing the code, configuration, or documentation changes. -->
-

## Security & Reliability Checklist

- [ ] **Secret Exposure:** No credentials, API keys, tokens, or environment secrets are committed.
- [ ] **Tenant Scoping:** All database queries and API endpoints enforce strict organization / tenant isolation.
- [ ] **RBAC & Authorization:** Server-side permission dependencies (`require(...)`) protect privileged actions.
- [ ] **Audit Trail:** Critical state mutations are coupled with append-only HMAC-SHA256 audit log entries.
- [ ] **Input Validation:** User inputs, query parameters, and event payloads are strictly validated against schemas.
- [ ] **Deterministic Cleanliness:** No temporary logs, dumps, cache directories, or untracked files are staged.

## Verification Evidence

<!-- Detail local and CI validation results (commands executed, counts passed). -->
- **Backend Tests:** `pytest tests` ->
- **Frontend Tests:** `npm --prefix web test` ->
- **Type Checking:** `python scripts/dev.py typecheck` ->
- **Linting:** `python scripts/dev.py lint` ->
- **Security Audits:** `python scripts/dev.py security` ->

## Related Issue / Work Item

Closes #
