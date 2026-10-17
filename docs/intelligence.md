# IOC enrichment and threat intelligence

This feature extends the existing IOC API, investigation UI, database-backed worker patterns and SOAR action model. It does not replace curated IOC matching, alter automatic risk scoring, submit samples for scanning, or introduce containment actions.

## Data and migration

Apply `alembic upgrade head` with the existing migration role. Revision **0010**, following **0009**, adds:

- `intel_observables`: tenant-owned normalized artifacts, SHA-256 normalization keys, local observation timestamps and external-lookup eligibility.
- `intel_observable_events`: source-event provenance; alerts, incidents and storylines are resolved through existing evidence relationships. Event deletion cascades these links under existing retention controls.
- `intel_enrichments`: one durable cache/job per tenant, observable and provider; status, attempt count, available time, fenced lease, result, enrichment and expiry timestamps.
- `intel_history`: retained completed lookup attempts and provider evidence.
- `events_metadata.intel_indexed`: resumable post-detection extraction marker.

Unique constraints prevent duplicate artifacts and provider jobs. Tenant-composite foreign keys protect new references; migration triggers enforce event-link tenant ownership. The migration supports both an existing 0009 database and the repository's metadata-based fresh-install bootstrap. No existing local database is automatically migrated by this implementation. Production deployments must rerun the existing initializer/grant procedure for the runtime role to access the new tables; running Alembic alone does not grant new-table access.

The existing `IOC` table remains the curated threat-indicator store. Extracted observations are intentionally separate: automatically inserting them as curated IOCs would make mere presence influence existing `metadata.ioc_match` risk scoring. Curated IOC CRUD and matching remain intact, and an existing IOC can request enrichment without changing its severity/confidence.

## Normalization and extraction

Supported input types: `ip` (IPv4/IPv6), `domain`, `url`, `md5`, `sha1`, `sha256`, and `hash` (algorithm inferred from length).

- IPs use canonical compressed address syntax. Scoped IPv6 and malformed addresses are rejected.
- Domains are lowercased, trailing dots removed, and IDNs converted to ASCII IDNA labels. Labels and total length are validated.
- URLs require HTTP(S), valid hosts/ports, and no userinfo or backslashes. Scheme/host/default ports are normalized. Query strings and fragments are removed **before storage**, because they can contain credentials. Paths remain case-sensitive and local; URLs differing only in stripped components are intentionally grouped. Original event evidence is not rewritten.
- Hashes must be hexadecimal of the declared length and are lowercased.

Extraction reads at most 32 unique observables from allowlisted structured fields: source/destination IPs, `http.domain`, DNS query/question, network domain, `http.url`/`url`, and file hash/algorithm fields. Arbitrary raw messages, process commands and hostnames are not scraped. Existing alerts and incidents are enriched through their linked events; storylines use their existing incident links. Source requests are limited to 200 distinct events and 50 observables and fail without partial writes beyond those limits.

Private, loopback, reserved and multicast IPs are not sent externally. Local/reserved domain suffixes are suppressed. URLs are never submitted to external providers in this release, including their paths. Extracted public hostnames from URLs may be eligible for domain lookups. Internal-looking domains under public suffixes cannot be classified reliably without deployment knowledge: external enrichment is operator opt-in and analysts must follow their organization's disclosure policy.

## Providers and configuration

All providers are disabled by default. Startup never requires credentials, DNS, or provider network access. Configuration is available through Settings/environment and wired into Compose's existing services. See `.env.example`.

| Setting | Default | Purpose |
|---|---:|---|
| `INTEL_AUTO_PROVIDER` | `none` | Optional automatic enrichment of newly indexed events: `none`, `mock`, `virustotal` |
| `INTEL_MOCK_ENABLED` | `false` | Enable explicit deterministic development fixtures |
| `INTEL_VT_ENABLED` | `false` | Permit VirusTotal report lookups |
| `INTEL_VT_API_KEY` | empty | Operator-supplied secret; never returned by health APIs |
| `INTEL_CACHE_SECONDS` | 3600 | Successful/unknown response lifetime |
| `INTEL_FAILURE_CACHE_SECONDS` | 300 | Failed/unavailable response lifetime |
| `INTEL_REFRESH_SECONDS` | 60 | Minimum interval before a manual refresh can bypass cache |
| `INTEL_REQUESTS_PER_MINUTE` | 4 | Shared VirusTotal credential pacing across all tenants/workers |
| `INTEL_QUEUE_CAPACITY` | 500 | Maximum active provider jobs per tenant |
| `INTEL_TIMEOUT_SECONDS` | 5 | Existing bounded HTTPS transport timeout |

**VirusTotal:** Implements read-only report retrieval for public IPs, domains and file hashes at fixed `https://www.virustotal.com/api/v3/` endpoints. It reuses the existing pinned-DNS, TLS-verified integration transport with a fixed host allowlist, no redirects and a 256 KiB response bound. No arbitrary observable URL is fetched. Only the normalized artifact is sent; raw events, incident text and tenant/user identifiers are not sent. API keys use the `x-apikey` header and are never logged. No file uploads or rescan requests occur. Configure quota and usage according to the operator's provider agreement.

Official references: [authentication](https://docs.virustotal.com/reference/authentication), [IP reports](https://docs.virustotal.com/reference/ip-info), [file reports](https://docs.virustotal.com/reference/file-info), [provider object statistics](https://docs.virustotal.com/reference/ip-object).

**Mock:** `malicious.example.test` produces a mock malicious fixture; SHA-256 consisting of 64 `a` characters produces a mock suspicious fixture. Other inputs remain unknown. Fixture confidence 90 is artificial and labelled `assessment_origin: mock`, with `not_real_intelligence: true`. Private/reserved IPs never receive synthetic malicious verdicts. Mock claims are excluded from production detection overlays.

## Verdict semantics and evidence

Transport/job statuses are distinct from verdicts:

- `QUEUED`, `RUNNING`: pending work, no current assessment.
- `COMPLETE`: a usable provider response.
- `UNKNOWN`: no report or no usable intelligence.
- `UNAVAILABLE`: disabled/missing credentials, authorization failure or external-disclosure policy suppression.
- `FAILED`: bounded lookup attempts exhausted or invalid/unavailable provider response.

Verdicts are `unknown`, `malicious`, `suspicious`, `undetected`. There is deliberately no `clean` verdict. VirusTotal statistics are preserved as allowlisted provider-reported counts. AEGIS derives the label using `any malicious > any suspicious > nonempty results undetected > unknown`, explicitly marked `aegis-derived`; it is not claimed to be a provider-issued overall verdict. Confidence remains null because these counts are not a calibrated probability. Provider first/last-seen or analysis timestamps are included only when supplied and valid.

Each result includes its provider, fixed provider report reference, evidence, method, reason, timestamp and expiry. `assessment` is the current view; expired/pending/failed results return unknown there. `result` preserves the latest response for inspection and may be historical; inspect `stale`, status and timestamps before using it. History is paginated. No exception strings, provider response bodies, secrets, or raw events are persisted in lookup errors/audits.

## Workers, recovery and resource bounds

The existing detection worker performs independent post-detection extraction, 50 events per iteration. This runs after detection commits; extraction failure cannot roll back an alert or suppress detection. Previously processed events are indexed after migration. Automatic lookup is off by default; when enabled, queue saturation does not block extraction and skipped automatic lookups must be requested later on demand.

The existing notification worker (`python -m aegis.notification_worker`, already present in Compose) processes up to 10 intelligence jobs per iteration. Notification dispatch failure does not prevent the intelligence pass. No new service, broker or package is required.

Jobs are claimed in short database transactions. Network I/O holds no database transaction or tenant lock. A 180-second lease and ownership token prevent late/stale workers from overwriting a newer result. Expired claims can be recovered after restart. At most three provider calls are attempted per lookup cycle; retries have bounded exponential delay and obey a database-backed global credential rate slot, using existing `window_state` infrastructure. Refreshes reuse the same unique job and cannot race an in-flight lookup. Cached failure/unknown results prevent request storms. Tenant queue writes are serialized using the existing SOAR tenant-lock pattern.

The transport has socket/read limits, not a hard process deadline around system DNS resolution. Provider servers may receive a repeated read-only lookup after a lease expires; stale writes are fenced, but external exactly-once delivery is not claimed. Configuration changes take effect when processes reload settings. Extraction indexing is not automatically replayed when automatic enrichment is enabled later.

## APIs and RBAC

Existing session/bearer authentication and CSRF behavior apply. Read operations use `iocs.read`; mutations use existing `iocs.write`. Source/related-evidence operations additionally require the existing composite evidence read scope. All resource lookups and result/history queries are tenant scoped.

| Method | Path under `/api/v1` | Use |
|---|---|---|
| POST | `/iocs/enrich` | One observable, provider, optional refresh |
| POST | `/iocs/enrich-batch` | 1–50 validated observables, atomic queue submission |
| POST | `/iocs/enrich-source` | Existing event/alert/incident/storyline observables |
| POST | `/iocs/{curated_ioc_id}/enrich?provider=virustotal` | Enrich existing supported curated IOC |
| GET | `/iocs/providers` | Configured/enabled status and last tenant lookup; no live health probe or secrets |
| GET | `/iocs/observables?q=...&offset=0&limit=50` | Observed artifact library |
| GET | `/iocs/observables/{id}` | Provider results and related investigations/evidence IDs |
| GET | `/iocs/enrichments/{id}` | Current job/result state |
| GET | `/iocs/enrichments/{id}/history?offset=0` | Latest 50 attempts per page |
| GET | `/iocs/source-context/{event|alert|incident|storyline}/{id}` | Bounded attributed context for a source |

Example:

```json
{"observable":{"type":"ip","value":"8.8.8.8"},"provider":"virustotal","refresh":false}
```

Batch uses `observables: [{type,value}, ...]`. Source requests use `source_type`, `source_id`, `provider`, `refresh`. Queue responses are not claims that provider work has completed. Analyst requests and completed attempts are recorded through the existing audit chain.

## Detection, investigation and storyline integration

`detection_context(db, organization_id, event)` provides a cache-only, non-mutating interface. During live evaluation, AEGIS overlays:

- `metadata.intel_verdict`: highest-priority fresh non-mock assessment, or `unknown`.
- `metadata.intel_verdicts`: all fresh non-mock verdicts, or `["unknown"]`.
- `metadata.intel_confidence`: maximum explicitly supplied confidence, or null (not an invented zero).
- `metadata.intel_enrichment_ids`: references for reviewing the claims.

A rule can explicitly use `{"field":"metadata.intel_verdict","op":"eq","value":"malicious"}`. This does not change existing rules, `metadata.ioc_match`, risk weights, alert status or severity. A later enrichment does not retroactively rerun detections. The overlay is not written into original event payloads. Existing replay behavior is unchanged and does not fetch live intelligence automatically; replaying live-time intelligence requires an explicit future snapshot design.

Investigation responses include attributed `intelligence` context. The console's existing Intelligence tab adds source enrichment and current provider context alongside curated matches. Storyline detail exposes the same incident-derived context without altering correlation or storyline risk. Observable details link to related events, alerts, incidents and storylines (100 per type). Source context is deliberately bounded to 200 normalized values and 64 provider results; large investigations may have additional context outside that view.

## SOAR

An existing playbook can declare `"input_schema":{"observable_id":"observable"}` and use:

```json
{
  "description": "Enrich and record advisory incident context",
  "trigger": {"source":"incident"},
  "input_schema": {"observable_id":"observable"},
  "timeout_seconds": 300,
  "steps": [
    {"id":"lookup","action":"enrich_observable","provider":"virustotal"},
    {"id":"note","action":"incident_note","when":{"field":"intel_verdict","op":"eq","value":"malicious"}}
  ]
}
```

`enrich_observable` requires `iocs.write`, rechecked against the requester's current role during execution. It queues/reuses the job and waits through persisted worker polls without consuming action retries or holding a transaction. The workflow deadline still applies. Failed/unavailable enrichment fails the step; unknown intelligence remains unknown. Dry runs queue nothing. Completion exposes `intel_verdict`, `intel_confidence`, `intel_status` for later declarative conditions. A subsequent incident note records an advisory verdict/provider/lookup reference, explicitly distinguished from proof of compromise. Existing `enrich` can also include cached context for a supported `ioc_id`.

Simulation containment actions remain subject to the original independent approval requirements. No real response actions are introduced. Cancelling a workflow stops its future steps but does not cancel a shared read-only intelligence lookup already requested. Mock results remain labelled in SOAR; use only for development scenarios.

## CLI and console

```text
aegis iocs enrich ip 8.8.8.8 --provider virustotal
aegis iocs enrich domain malicious.example.test --provider mock
aegis iocs enrich-batch observables.json --provider mock
aegis iocs enrich-source incident INC-existing --provider virustotal
aegis iocs providers
aegis iocs observables
aegis iocs inspect-observable <observable-id>
aegis iocs enrichment-history <lookup-id>
aegis soar execute <playbook-id> incident <incident-id> request-unique --observable-id <observable-id> --no-dry-run
```

Use existing `AEGIS_TOKEN` and API URL options. The Threat Intelligence console retains the curated IOC table/editor and adds observable search, lookups, controlled refresh, provider status, verdict/confidence/origin, timestamps, supporting evidence, history, and related investigation navigation. Loading, empty, error, missing-configuration and stale states are explicit.

## Verification handoff

Tests added in `tests/test_intelligence.py`, a pre-feature upgrade-path check in `tests/test_migrations.py`, and `web/tests/intelligence.test.tsx`. They exercise canonicalization, malformed values, privacy suppression, caching/expiry, retries, lease fencing, concurrency, tenant/RBAC isolation, extraction/provenance, mock exclusion from detection, SOAR wait/branch/dry-run semantics, mocked VirusTotal mapping, CLI, and UI behavior.

Antigravity should independently verify PostgreSQL migration/trigger behavior and runtime grants; real credential quota/error responses and TLS/DNS behavior; sustained queue load and notification-worker latency; source-field coverage for deployment-specific parsers; privacy approval for sending public-looking domains; and browser end-to-end navigation. No live VirusTotal query, real credentials, PostgreSQL/Redis/OpenSearch deployment, or external provider SLA was verified by local mocked tests. Enrichment history/observable retention is not yet automated; event retention removes source links but retains the artifact and lookup history. This implementation is not a production-readiness certification.
