# Contributing

Keep business logic in the Python core; browser/CLI clients must call the API.
Every new tenant-owned table needs organization_id and every query needs a tenant
scope. Preserve source evidence. Never render untrusted logs as HTML or execute
user-supplied rules, AI commands, SQL, or regex.

Before submitting changes:

```sh
python scripts/dev.py format
python scripts/dev.py lint
python scripts/dev.py typecheck
python scripts/dev.py test
python scripts/dev.py security
python scripts/e2e.py
```

New detections require realistic positive/negative fixtures, boundary/window tests
where relevant, MITRE context and evidence explanations. Code-generated contract
samples alone do not establish detection accuracy. New external providers need
timeouts, strict schemas, explicit failure results, idempotency and integration
tests with a real service or deterministic protocol fixture.

Add explicit Alembic migrations for schema changes; do not mutate deployed schema
at startup. Use optimistic versions for analyst updates and unique keys for retry
safety. Dependency changes must update pyproject/requirements.lock or package-lock,
run vulnerability scans, and be tested on Windows and Linux where applicable.
