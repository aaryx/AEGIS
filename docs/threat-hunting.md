# Threat hunting

The frontend and CLI submit a validated abstraction rather than raw search DSL.

```text
source_ip = "192.0.2.44"
event.category = "authentication" AND outcome = "failure"
username = "synthetic-admin" AND timestamp > now()-24h
```

Plain text searches messages. Supported field clauses use JSON string, numeric
or Boolean values with `=` and uppercase `AND`. Structured API filters expose
the supported operators in the rule schema. Arbitrary scripts, regex, SQL and
unbounded backend query JSON are rejected.

Search defaults to the preceding 24 hours and caps ranges at MAX_SEARCH_DAYS.
OpenSearch uses explicit daily indices, timestamp/event-ID sort and search-after
cursors. It rejects incomplete/time-out results rather than representing them as
complete. Aggregations return up to 50 buckets. Local SQLite search caps an
eligible time window at 50,000 events and asks the user to narrow it if exceeded.

Use event detail field buttons to pivot by IP, host or user. Entity views expose
evidence-backed relationships and related events; investigation links connect
alerts, incidents, IOCs and entities. The GUI exports the current selected page,
not an unbounded dataset. API clients may iterate cursors for larger exports.

Sequence investigation uses a sequence detection rule with isolated rule testing.
The natural-language assistant will not pretend a simple event filter can execute
an ordered multi-event sequence.
