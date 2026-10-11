# Extension boundaries

**Update:** working file collection and webhook/Slack/Teams/IOC-feed integrations
now exist in `aegis/collector.py` and `aegis/integrations.py`. See
[hardening.md](hardening.md) for configuration and guarantees. The original gap
notes below describe the initial implementation and are superseded for these adapters.

Current explicit interfaces:

- `Parser` / `ParserRegistry` in `aegis/parsers.py`: can_parse, parse, validate.
  Pass reviewed parser instances to the registry; first match wins.
- `StateStore` in `aegis/detection.py`: temporal state append; Redis and SQL adapters.
- `StorageProvider` in `aegis/storage.py`: index, bounded search, health.
- `AIProvider` in `aegis/ai.py`: evidence analysis and structured query generation.
- `ResponseProvider` in `aegis/response.py`: fixed action execution with verifiable
  results. The installed local provider never claims remote enforcement.

Collectors should emit `EventInput` batches through HTTPS, preserve stable source
and sequence identifiers, buffer until 202 acceptance and retry idempotently.
Windows Event Log, journald, Docker and cloud integrations currently consume
exported JSON records. Native OS/cloud polling agents require separate source
credentials and lifecycle management.

Detection extensions normally add declarative rules rather than executable
plugins. Add a condition strategy only when a validated rule cannot express the
behavior. Enrichment currently matches the tenant IOC store; external GeoIP,
reputation/ASN and feed refresh need reviewed providers and provenance handling.

Notifications are durable in-application records. Email/webhook/Slack/Teams
dispatch is not installed. Integrators must add configured allowlisted endpoints,
timeouts, delivery status, replay/idempotency controls and tests before claiming
external notifications.

Plugin code is trusted deployment code, not sandboxed user code. No automatic
entry-point discovery or uploaded executable plugin installation occurs. Run
third-party collectors in separate processes with scoped ingestion-only API keys.
