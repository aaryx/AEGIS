# Operational CLI

## Offline detection rule simulator

```sh
aegis --format json rules simulate --dataset AUTH-001
aegis --format json rules simulate --dataset ALL
aegis --format json rules simulate --dataset AUTH-001 --rule candidate.yml
aegis --format json rules simulate --events events.json --tenant lab-a
```

`rules simulate` runs locally using the existing evaluator and a fresh in-memory
replay store. It requires no server or token and creates no ingestion records,
alerts, incidents, replay jobs or response actions. The existing top-level
`simulate` and `replay` commands send events to ingestion; they are separate workflows.

Choose exactly one input: a bundled fixture ID or a JSON array (20 MB and 10,000
events maximum). File entries are normalized `Event` objects or `EventInput`
objects with explicit timezone-aware timestamps, for example:

```json
[{"source":"lab","timestamp":"2026-10-01T12:00:00Z","raw_event":{"host":"LAB","action":"sudo"}}]
```

File input uses all bundled rules unless `--rule` supplies one candidate YAML.
Dataset input defaults to its corresponding bundled rule. Candidates are evaluated
regardless of lifecycle status, without saving or activating them. Events are sorted
by timestamp and ID; duplicate IDs and malformed records are reported and skipped.
An optional top-level `organization_id` must match `--tenant`. Untagged local events
are assigned to that namespace; this is not server authorization or proof of ownership.

Reports contain event totals, evaluator match counts per rule, evidence, elapsed
processing time and errors. Any record/evaluation error gives exit code 2, with
partial results. Bundled fixtures additionally report benign-match candidates and
rules missing the attack scenario. Positive and negative sequences have separate
state. Quality results are withheld on errors and for unlabelled files; they are
not production false-positive rates. Matches precede production cooldown/suppression,
enrichment and response handling, so counts are not predicted production alert counts.
Replay is event-time ordered and does not reproduce production arrival lateness.

## Other commands

New operational commands:
`aegis collectors run <log> --spool <db> --source-type linux`,
`aegis collectors spool <db>`, and `aegis integrations list|save|sync|deliveries`.
`aegis simulate attack-chain --host <unique-host> --source-ip <synthetic-ip>`
supports isolated repeatable acceptance runs. See [hardening.md](hardening.md).

Run `aegis --help` and `<group> --help` for the installed command surface.
Use `--format json` globally, or `--json` on resource list/show commands.
`--format csv` exports tabular results with formula-injection protection.
Noninteractive stdout defaults to JSON. `--quiet` suppresses normal output;
errors remain on stderr. Profiles contain connection URLs, not credentials.

```sh
aegis version
aegis status
aegis health
aegis config
aegis login
aegis alerts list --severity critical --json
aegis alerts show ALT-<UUID>
aegis alerts update ALT-<UUID> INVESTIGATING 1
aegis incidents create "Investigate account compromise" --alert ALT-<UUID>
aegis incidents note INC-<UUID> "Validated source evidence"
aegis investigate ALT-<UUID> --ai
aegis hunt --query 'event.category = "authentication" AND outcome = "failure"'
aegis hunt --ip 192.0.2.44 --hours 24
aegis events search --user synthetic-admin
aegis rules validate rule.yml
aegis rules test rule.yml --events demo-data/auth.json
aegis rules test --all
aegis rules save rule.yml "Tuned threshold for authorized scanner" --version 1
aegis iocs add --type ip --value 203.0.113.10
aegis collectors status
aegis mitre technique T1110
aegis reports generate INC-<UUID>
aegis playbooks request isolate_host <entity-id> <unique-request-key>
aegis playbooks approve <execution-id>
aegis playbooks execute <execution-id>
aegis audit verify
aegis system retry <dead-letter-event-id>
```

Ingestion and synthetic activity:

```sh
aegis ingest file demo-data/auth.json
aegis ingest directory ./logs --source-type generic
aegis ingest syslog --listen 127.0.0.1:5514
aegis replay demo-data/auth.json --deterministic
aegis simulate brute-force
aegis simulate suspicious-login
aegis simulate privilege-escalation
aegis simulate attack-chain
aegis simulate port-scan
aegis simulate web-attack
aegis benchmark ingest --events 1000
```

UDP syslog is explicitly best effort. Binding a remote interface requires
`--allow-remote`; privileged ports are rejected. For reliable collection use
HTTPS batches or replayable files. File input is capped at 20 MB. JSON arrays,
JSON Lines and text files are supported. Preserve source identity and sequence
when retrying. Reusing the same source/sequence with different evidence is rejected.

Exit codes: 0 success; 1 detection self-check failure; 2 input/API error;
3 authentication/authorization; 4 absent resource; 5 unreachable API.
Typer argument validation also uses 2. Local file parsing errors currently use
Python's nonzero exception exit; no successful output is returned on failure.

Benchmark output measures API acceptance only. It is not a claim about worker
throughput or sustained enterprise scale. Rate limits apply to benchmark traffic.
