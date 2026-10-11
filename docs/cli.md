# Operational CLI

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
