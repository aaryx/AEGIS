# API

All operational endpoints live under `/api/v1`. `/docs`, `/redoc` and
`/openapi.json` expose the actual route schemas. The API follows the same core
service flow as the CLI and web console.

## Authentication

`POST auth/login` accepts username/password, returns a short-lived bearer token
and sets HttpOnly SameSite=Strict session cookies. Browser mutations must include
`X-CSRF-Token` from the readable CSRF cookie. Origin is checked on login and
cookie-authenticated writes. Use `auth/refresh` to rotate a session and
`auth/logout` to invalidate it. Bearer authentication does not use browser cookies.

API keys are scoped, expiring, hashed at rest, revocable and shown only on creation
through `POST auth/api-keys`. Their effective rights cannot exceed the owner's
current role. Administrator-issued password-reset tokens expire in 15 minutes
and are single-use; the administrator must verify recipient identity out of band.

## Main operations

| Endpoint | Operation |
|---|---|
| POST events/ingest | Validate/normalize and durably accept a batch; 202 |
| POST events/search | Bounded structured filters, sorting, aggregations, cursor |
| GET events/{id} | Original/normalized evidence, hash and processing state |
| GET alerts, incidents, cases, entities, rules, iocs | Tenant-scoped resource lists |
| GET investigations/{id} | Evidence, alerts, entities, relationships, IOC, activity |
| POST incidents | Transactional incident creation and alert attachment |
| POST incidents/{id}/alerts/{alert_id} | Attach existing alert |
| PATCH {alerts,incidents,cases}/{id}/status | Optimistic revision-aware workflow update |
| POST {alerts,incidents,cases}/{id}/notes | Append analyst note |
| POST cases/{id}/evidence | Attach hashed evidence reference |
| PUT rules/{rule_id} | Validated, audited new rule version |
| POST rules/validate, rules/test | Validation and isolated temporal evaluation |
| POST hunts, hunts/parse | Save search / parse bounded query text |
| POST investigations/{id}/ai | Advisory minimized-evidence analysis |
| POST ai/query | Validated query suggestion, never automatically executed |
| POST playbooks/request | Idempotent controlled response request |
| POST playbooks/{id}/approve, execute | Independent approval and execution |
| POST reports/{incident_id} | Evidence-scoped report snapshot |
| GET reports/{id}/html | Escaped printable HTML download |
| GET export/{resource} | JSON or formula-neutralized CSV page |
| GET stream | Authenticated SSE updates |
| GET audit/verify | HMAC chain verification |

Incident creation and response requests require `Idempotency-Key` (8–100 chars).
Reuse with conflicting content returns 409. Resource list cursors order by
opaque IDs; event search cursors order by timestamp and event ID. Limit is
normally 50, maximum 200 for resources and 500 for events/exports.

Example ingestion:

```json
{"events":[{"source":"linux-01","source_type":"json","collector":"https-agent",
 "source_sequence":"log-file-inode:offset","timestamp":"2026-09-28T12:00:00Z",
 "raw_event":{"host":"linux-01","event_category":"authentication","action":"login",
 "outcome":"failure","username":"synthetic-admin","source_ip":"192.0.2.4",
 "message":"Failed authentication"}}]}
```

Errors use `{"error":{"code":"...","message":"...","request_id":"..."}}`.
Validation errors omit submitted values to avoid echoing credentials. 401 means
invalid authentication, 403 insufficient authorization, 409 concurrency/conflict,
422 invalid data, 429 rate limit, and 503 dependency/backpressure failure.
