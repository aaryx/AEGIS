# Attack storylines

Storylines correlate **persisted production alerts** and reuse incident assignment,
notes, evidence, optimistic revisions and audited lifecycle transitions. Run
`alembic upgrade head` before deploying this version (migration `0008`).

## Use

In the console, open **Storylines**, choose a window and select **Correlate alerts**.
Open a result for the detection timeline, ATT&CK tags, correlation explanations and
risk factors. **Investigate incident** opens the existing evidence, notes, status,
assignment API and audit workflow. Existing incidents remain intact.

The CLI uses the authenticated API (`AEGIS_URL` and `AEGIS_TOKEN`):

```sh
aegis storylines correlate --window-seconds 1800
aegis storylines list --status OPEN --severity high
aegis storylines show STL-<identifier>
aegis incidents note INC-<identifier> "Reviewed source evidence"
aegis incidents update INC-<identifier> TRIAGED 2 --assignee <user-id>
```

Use the returned incident revision for each update. The existing lifecycle is
OPEN → TRIAGED → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY → RESOLVED →
CLOSED. Containment here is an investigation status; correlation executes no
endpoint actions. Resolution requires notes.

API: `POST /api/v1/storylines/correlate?window_seconds=1800`,
`GET /api/v1/storylines?limit=50&offset=0&status=OPEN&severity=high`, and
`GET /api/v1/storylines/{id}`. Follow `next_offset` for pagination.
Correlation requires incident create/update permissions and evidence-read scope.
Detail requires evidence-read scope; audit activity is withheld without audit-read
permission. All queries use the authenticated tenant.

## Correlation contract

- Process alerts in `(first_seen, id)` order. At least two alerts are required.
- A pair must share a valid, tenant-owned host, user or IP entity. Null, unknown,
  malformed, multicast and unspecified IP identifiers cannot establish a link.
  Time, rule or technique similarity alone never establish a link.
- Compare absolute first-observed timestamp distance to an **inclusive** window
  (1–86400 seconds). A fixed anchor prevents unbounded transitive chains.
- Try existing open storylines in creation order, then unmatched anchors in event
  order. Persist the chosen reasons and window. Each alert has one unique
  storyline membership. Retrying unchanged data produces no new records or audit
  entries. Existing legacy/manual incidents may also reference the same alert.
- Membership is append-only. Late arrivals can attach on either side of an anchor;
  timeline order is event-time order. Existing groups are not merged or reassigned,
  preserving analyst work. Thus grouping is deterministic for a given persisted
  history, **not invariant to different batches arriving over time**. Changing the
  requested window affects new groups only. Resolved/closed cases accept no new
  members.
- Correlation is an explicit analyst operation, not automatically run by ingestion.
  Replay matches intentionally stay isolated: dry-run results never create live
  incidents. To demonstrate the workflow, ingest the existing synthetic attack
  chain, drain the worker and correlate its persisted alerts.

## Scores

Severity is the maximum detection severity. Risk is capped at 100 and consists of
severity points (low 20, medium 40, high 70, critical 90), up to 10 points for
additional shared identifier types (5 each), and up to 10 for additional distinct
rules (2 each). Priority is 1 at risk ≥80, 2 at ≥50, otherwise 3.

Confidence is a separate heuristic evidence-strength score: 35 + 15 per shared
identifier type + up to 15 for additional distinct rules (5 each), capped at 95.
It is **not a calibrated probability**. Shared infrastructure can produce false
correlations; the UI exposes the supporting identifiers for analyst review.
No asset criticality, threat-intelligence confidence or technique causality is
invented. ATT&CK tags describe detections, not proven attack steps.

## Bounds and verification

The synchronous service rejects tenants with more than 5000 retained alerts rather
than silently truncating analysis. Worst-case matching is quadratic; this initial
bounded workflow is not a distributed streaming correlator. PostgreSQL serializes
same-tenant runs with a transaction advisory lock; SQLite remains a single-writer development mode.
Evidence and activity use the existing investigation limits (500 events, 200 notes
and audit entries). Retention policies still apply.

`pytest tests/test_storylines.py tests/test_migrations.py` includes a real synthetic
ingestion → detection → correlation → note/assignment → resolved incident scenario,
tenant/RBAC, time boundaries, late arrival, idempotency, malformed identifiers,
fresh-session persistence, CLI/API consistency and a 1000-alert performance guard.
`npm --prefix web test` exercises console API calls, filters, errors, evidence
escaping and incident navigation. These do not substitute for PostgreSQL
concurrency verification or browser acceptance on a deployed stack.
