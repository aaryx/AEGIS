# Getting started

1. Generate `.env` with `python scripts/configure.py`.
2. Start `docker compose up -d --build`; initialization must exit successfully.
3. Open http://localhost:3000 and use the generated bootstrap credentials.
4. Install the Python CLI, run `aegis login`, and set the resulting `AEGIS_TOKEN`.
5. Run `aegis simulate attack-chain`. Allow worker processing and the five-second
   OpenSearch refresh/SSE interval.
6. Open Alerts, then **Potential account compromise**. Inspect the detection
   conditions, SHA-256 evidence, timeline, entity relationships, IOC and risk.
7. The correlated chain automatically associates an incident. Individual alerts
   can also be attached through the incident API or used to create an incident.
8. Add analyst findings, run the advisory analysis, and generate a report.
9. Run `aegis audit verify` to verify the audit chain.

PowerShell token setup: `$env:AEGIS_TOKEN = 'the-issued-token'`.
POSIX: `export AEGIS_TOKEN='the-issued-token'`.
Do not paste tokens into tickets or commit them. A scoped ingestion API key is
more appropriate than an analyst session for a long-running collector.

The GUI and CLI read the same API state. Empty deployments show useful empty
states rather than fabricated charts. Synthetic sources are labeled explicitly.
