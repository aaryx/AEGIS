# Rule format

Rules are strict declarative JSON/YAML. YAML is loaded with `safe_load`; no code,
raw SQL, OpenSearch scripts, arbitrary regex or subprocess expression is accepted.

```yaml
id: AEGIS-AUTH-CUSTOM
name: Repeated authentication failures
description: Detect ten failed logins from one source within five minutes.
selection:
  - field: event_category
    op: eq
    value: authentication
  - field: outcome
    op: eq
    value: failure
condition:
  type: threshold
  count: 10
  window_seconds: 300
  group_by: [source_ip]
severity: high
confidence: 80
mitre_techniques: [T1110]
cooldown_seconds: 900
exceptions:
  - reason: Authorized security validation from a dedicated lab address
    predicates:
      - field: source_ip
        op: eq
        value: 192.0.2.99
recommended_actions:
  - Validate account ownership and inspect subsequent successful logins.
```

Operators: `eq`, `ne`, `in`, `contains`, `gte`, `lte`, `exists`.
`in` accepts up to 100 values; comparisons are type checked. All selection
predicates must match. Each exception is an AND group; any exception suppresses
the event. Exceptions require a reason and are preserved in audited versions.

Condition types:

- `match`: one selected event.
- `threshold`: `count` events in the window.
- `aggregation`: distinct values of `distinct_field`, or sum of `sum_field`
  reaching `sum_threshold`.
- `sequence`: ordered list of nonempty predicate lists, one event per step.
- `beacon`: at least four events; coefficient of variation of intervals at or
  below `tolerance`, with nonzero intervals.
- `anomaly`: numeric `sum_field`, at least `baseline_count` prior observations,
  current value more than `deviation` population standard deviations above mean.

Group fields must exist; absent identities never share a null correlation bucket.
Windows are limited to one day, sequences to ten steps and selections to thirty
predicates. Supported fields are explicitly enumerated in `aegis/schemas.py`.

Update by rule business ID with the current version. Conflicting updates return
409. Persisted versions preserve author, timestamp, document and change summary.
MITRE identifiers must exist in the curated catalog when saving rules.
