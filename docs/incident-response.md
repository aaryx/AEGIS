# Incident response

Alert statuses: NEW, ACKNOWLEDGED, INVESTIGATING, ESCALATED, RESOLVED,
FALSE_POSITIVE, CLOSED. Incident stages advance one step at a time:

OPEN → TRIAGED → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY → RESOLVED → CLOSED.

Resolve/close operations require resolution notes. Status updates include the
current revision; stale writes fail with 409. Assignees must belong to the same
organization. Notes are append-only through the API. Cases may attach alerts,
events and entities with content hashes and the attaching actor.

## Controlled response

1. Authorized senior analyst requests a fixed, allowlisted action with an
   idempotency key and tenant-owned target.
2. Evidence collection/notification are low impact.
3. Isolate-host, disable-account and block-IOC policy requests require a different
   SOC manager/admin to approve using a human session, not an API key.
4. Execution rechecks state and authorization, locks the execution row and records
   the result and audit entry transactionally.
5. Repeated execution of VERIFIED requests returns the recorded result.

The installed response provider is local. High-impact actions persist a policy
record on the target entity and return `enforced_externally: false`. It does not
claim an EDR, directory or firewall changed. Real enforcement requires a reviewed
provider implementing execution, idempotency and verification for that system.

Reports snapshot incident details, evidence hashes/IDs, event timeline, entities,
alerts, risk contributions, MITRE/IOC, notes, actions and recommendations. JSON
and escaped HTML are available. HTML can be printed to PDF by an analyst.
Evidence scope is explicitly capped at 500 events per generated report.
