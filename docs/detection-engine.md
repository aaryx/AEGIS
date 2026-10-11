# Detection engine

**Current behavior:** correlation windows now use transactional PostgreSQL state
alongside alerts; search projection uses an independent durable outbox. Rule checks
now use independent positive and near-miss fixtures rather than samples derived
from rule predicates. See [hardening.md](hardening.md). Historical Redis and
sample-generation notes below are superseded.

The worker processes ordered event batches from a PostgreSQL inbox, enriches
against tenant IOCs, indexes a search projection and evaluates enabled rule
versions. Redis sorted sets retain bounded temporal event projections; local
tests use SQL-backed windows. Events carry original evidence throughout.

Detection explanations include selection predicates, group identity, measured
value, configured threshold/window/sequence, contributing event IDs, rule version,
MITRE IDs and recommended investigation actions. Risk combines confidence-scaled
severity, privileged identity, asset criticality, IOC match, multi-stage sequence
and event frequency. The individual contributions are stored with the score.

34 bundled rules cover authentication failures/spraying/failure-to-success,
privilege changes/sudo, suspicious command indicators, persistence, network
fan-out/scans/failures/periodicity, web traversal/errors/rates, file access/archive/
transfer behavior, cloud IAM/storage/audit modifications and a compromise chain.
These are behavioral indicators, not proof of malicious intent. For example,
storage policy modification requires context before claiming public exposure.

The compromise sequence groups by host and matches failed login → successful
login → sudo → process → network within 30 minutes. The resulting critical alert
creates/associates an incident; alerts for the same tenant/host/time bucket are
attached. This is deliberately conservative host-based correlation, not campaign
attribution. Review shared hosts and NAT identity assumptions when tuning.

Fingerprints combine tenant, rule/version, group and cooldown time bucket.
Contributing event links use unique constraints. Cooldown boundaries can produce
adjacent alerts; suppression is bucket-based, not a sliding silence timer.

State windows retain at most 10,000 matching events per key. Production worker
serialization is per tenant, and arrival batches are event-time sorted. Very late
events can be missed after the relevant state expires; source clock corrections,
watermarks and backfill re-evaluation are not implemented. Evidence remains
searchable and can be replayed/tested explicitly. See verification limitations.

Run `aegis rules test --all` for positive/negative contract samples. Independent
tests additionally cover actual log parsers, threshold boundary/window behavior,
benign traffic and the complete synthetic attack chain.
