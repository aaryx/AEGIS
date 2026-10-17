import csv
import hashlib
import json
import os
import socket
import sys
import time
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import typer
import yaml
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from aegis import __version__
from aegis.config import get_settings
from aegis.db import Base, Organization, User, database
from aegis.pipeline import seed_rules
from aegis.rules import MITRE
from aegis.schemas import DetectionRule, EventInput, parse_query
from aegis.security import PASSWORDS, audit
from aegis.simulation import simulate

app = typer.Typer(help="AEGIS Security Intelligence & Operations Platform", no_args_is_help=True)
console = Console(stderr=True)


def output(ctx: typer.Context, value, csv_output=False):
    if ctx.obj["quiet"]:
        return
    if csv_output or ctx.obj["format"] == "csv":
        rows = value.get("items", [value]) if isinstance(value, dict) else value
        if rows:
            writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {
                        key: (
                            "'" + item
                            if isinstance(item, str) and item.startswith(("=", "+", "-", "@"))
                            else json.dumps(item)
                            if isinstance(item, (dict, list))
                            else item
                        )
                        for key, item in row.items()
                    }
                )
    elif ctx.obj["format"] == "json" or not sys.stdout.isatty():
        typer.echo(json.dumps(value, indent=2, default=str))
    elif isinstance(value, dict) and "items" in value:
        rows = value["items"]
        if not rows:
            console.print("No results. Widen the time range or clear filters.")
            return
        columns = [
            key
            for key in (
                "id",
                "severity",
                "title",
                "name",
                "rule_id",
                "type",
                "value",
                "status",
                "risk_score",
                "created_at",
            )
            if key in rows[0]
        ][:7]
        table = Table(*columns)
        for row in rows:
            table.add_row(*(str(row.get(key, ""))[:90] for key in columns))
        Console().print(table)
        if value.get("next_cursor"):
            console.print(f"Next cursor: {value['next_cursor']}")
    else:
        Console().print_json(data=value)


def call(ctx, method, path, **kwargs):
    token = os.environ.get("AEGIS_TOKEN", "")
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(
            base_url=ctx.obj["url"].rstrip("/") + "/api/v1/", timeout=30, follow_redirects=False
        ) as client:
            response = client.request(method, path.lstrip("/"), headers=headers, **kwargs)
        if response.is_error:
            try:
                message = response.json().get("error", {}).get("message", response.reason_phrase)
            except ValueError:
                message = response.reason_phrase
            console.print(f"{response.status_code}: {message}", markup=False)
            raise typer.Exit(
                3 if response.status_code in {401, 403} else 4 if response.status_code == 404 else 2
            )
        return response.json() if "json" in response.headers.get("content-type", "") else response.text
    except httpx.HTTPError as exc:
        console.print(
            f"API unavailable ({type(exc).__name__}). Check AEGIS_URL and service health.", markup=False
        )
        raise typer.Exit(5) from exc


@app.callback()
def options(
    ctx: typer.Context,
    url: str = typer.Option("", envvar="AEGIS_URL"),
    profile: str = "default",
    config_file: Path = typer.Option(Path.home() / ".config" / "aegis" / "config.toml"),
    format: str = typer.Option("table", help="table, json or csv"),
    quiet: bool = False,
    verbose: bool = False,
):
    if format not in {"table", "json", "csv"}:
        raise typer.BadParameter("Format must be table, json or csv")
    config = tomllib.loads(config_file.read_text()) if config_file.is_file() else {}
    profile_data = config.get("profiles", {}).get(profile, {})
    ctx.obj = {
        "url": url or profile_data.get("url", "http://localhost:8000"),
        "format": format,
        "quiet": quiet,
        "verbose": verbose,
        "profile": profile,
    }


@app.command()
def version():
    typer.echo(__version__)


@app.command()
def config(ctx: typer.Context):
    output(ctx, {key: ctx.obj[key] for key in ("url", "format", "profile")})


@app.command()
def status(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "system/health"))


@app.command()
def health(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "system/readiness"))


@app.command()
def login(
    ctx: typer.Context,
    username: str = typer.Option(prompt=True),
    password: str = typer.Option(prompt=True, hide_input=True),
):
    result = call(ctx, "POST", "auth/login", json={"username": username, "password": password})
    console.print("Set AEGIS_TOKEN to this bearer token. It expires; it is not saved to disk.")
    typer.echo(result["access_token"])


@app.command()
def bootstrap(
    username: str = typer.Option(prompt=True),
    password: str = typer.Option(prompt=True, hide_input=True, confirmation_prompt=True),
    organization: str = "AEGIS",
):
    """Create the first administrator. Requires direct database access."""
    if len(password) < 14 or len(password) > 256:
        raise typer.BadParameter("Password must contain 14–256 characters")
    settings = get_settings()
    engine, sessions = database(settings.database_url)
    if settings.environment != "production":
        Base.metadata.create_all(engine)
    with sessions.begin() as db:
        if db.scalar(select(User.id).limit(1)):
            raise typer.BadParameter("Already bootstrapped. Use the authenticated users API.")
        org = Organization(name=organization)
        db.add(org)
        db.flush()
        user = User(
            organization_id=org.id,
            username=username,
            password_hash=PASSWORDS.hash(password),
            role="SUPER_ADMIN",
        )
        db.add(user)
        db.flush()
        seed_rules(db, org.id)
        audit(db, settings, org.id, user.id, "system.bootstrap", user.id)
    console.print("Administrator and detection rules created.")


def resource_group(name):
    group = typer.Typer(help=f"Operate on {name}.", no_args_is_help=True)

    @group.command("list")
    def list_items(
        ctx: typer.Context,
        limit: int = 50,
        cursor: str = "",
        severity: str = "",
        status: str = "",
        query: str = "",
        sort: str = "desc",
        json_output: bool = typer.Option(False, "--json"),
    ):
        if json_output:
            ctx.obj["format"] = "json"
        output(
            ctx,
            call(
                ctx,
                "GET",
                name,
                params={
                    "limit": limit,
                    "cursor": cursor,
                    "severity": severity,
                    "status": status,
                    "q": query,
                    "sort": sort,
                },
            ),
        )

    @group.command("show")
    def show(ctx: typer.Context, identifier: str, json_output: bool = typer.Option(False, "--json")):
        if json_output:
            ctx.obj["format"] = "json"
        output(ctx, call(ctx, "GET", f"{name}/{identifier}"))

    if name in {"alerts", "incidents", "cases"}:

        @group.command("update")
        def update(
            ctx: typer.Context,
            identifier: str,
            status: str,
            revision: int,
            assignee: str = "",
            resolution: str = "",
        ):
            output(
                ctx,
                call(
                    ctx,
                    "PATCH",
                    f"{name}/{identifier}/status",
                    json={
                        "status": status,
                        "revision": revision,
                        "assignee": assignee or None,
                        "resolution": resolution,
                    },
                ),
            )

        @group.command("note")
        def note(ctx: typer.Context, identifier: str, text: str):
            output(ctx, call(ctx, "POST", f"{name}/{identifier}/notes", json={"text": text}))

    app.add_typer(group, name=name)
    return group


groups = {
    name: resource_group(name)
    for name in (
        "alerts",
        "incidents",
        "cases",
        "entities",
        "rules",
        "iocs",
        "collectors",
        "reports",
        "playbooks",
        "audit",
        "users",
        "hunts",
    )
}


storylines_app = typer.Typer(help="Correlate and investigate persisted alert storylines.")
app.add_typer(storylines_app, name="storylines")


@storylines_app.command("list")
def storyline_list(ctx: typer.Context, limit: int = 50, offset: int = 0,
                   status: str = "", severity: str = ""):
    output(ctx, call(ctx, "GET", "storylines", params={"limit": limit, "offset": offset,
                                                       "status": status, "severity": severity}))


@storylines_app.command("show")
def storyline_show(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "GET", f"storylines/{identifier}"))


@storylines_app.command("correlate")
def storyline_correlate(ctx: typer.Context, window_seconds: int = 1800):
    output(ctx, call(ctx, "POST", "storylines/correlate", params={"window_seconds": window_seconds}))


@groups["rules"].command("validate")
def validate_rule(path: Path):
    rule = DetectionRule.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    unknown = set(rule.mitre_techniques) - set(MITRE)
    if unknown:
        raise typer.BadParameter("Unknown ATT&CK identifiers: " + ", ".join(unknown))
    typer.echo(f"VALID {rule.id}")


@groups["rules"].command("test")
def test_rule(
    ctx: typer.Context,
    path: Path | None = None,
    events: Path | None = None,
    all_rules: bool = typer.Option(False, "--all"),
):
    if all_rules:
        from aegis.rule_checks import check_all

        result = check_all()
        output(ctx, result)
        if result["failed"]:
            raise typer.Exit(1)
        return
    if not path or not events:
        raise typer.BadParameter("Provide a rule file and --events, or --all")
    rule = DetectionRule.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    records = load_events(events, "json")
    output(
        ctx,
        call(
            ctx,
            "POST",
            "rules/test",
            json={
                "document": rule.model_dump(mode="json"),
                "events": [item.model_dump(mode="json") for item in records],
            },
        ),
    )


@groups["rules"].command("save")
def save_rule(ctx: typer.Context, path: Path, summary: str, version: int = 0, enabled: bool = True):
    rule = DetectionRule.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    output(
        ctx,
        call(
            ctx,
            "PUT",
            f"rules/{rule.id}",
            json={
                "document": rule.model_dump(mode="json"),
                "version": version,
                "summary": summary,
                "enabled": enabled,
            },
        ),
    )


@groups["rules"].command("activate")
def activate_rule_cli(
    ctx: typer.Context,
    rule_id: str,
    version: int = typer.Option(..., "--version", "-v", help="Exact candidate version to activate"),
    summary: str = typer.Option("Authorized rule activation", "--summary", "-s"),
):
    output(
        ctx,
        call(
            ctx,
            "POST",
            f"rules/{rule_id}/activate",
            json={"version": version, "summary": summary},
        ),
    )


@groups["rules"].command("rollback")
def rollback_rule_cli(
    ctx: typer.Context,
    rule_id: str,
    target_version: int = typer.Option(..., "--version", "-v", help="Historical version to restore"),
    summary: str = typer.Option("Authorized version rollback", "--summary", "-s"),
):
    output(
        ctx,
        call(
            ctx,
            "POST",
            f"rules/{rule_id}/rollback",
            json={"target_version": target_version, "summary": summary},
        ),
    )


@groups["rules"].command("replay")
def replay_rule_cli(
    ctx: typer.Context,
    rule_id: str,
    dataset: str = typer.Option("all", "--dataset", "-d", help="Labelled dataset name or rule ID"),
    candidate: Path | None = typer.Option(None, "--candidate", "-c", help="Path to candidate rule YAML"),
    events: Path | None = typer.Option(None, "--events", "-e", help="Path to raw events JSON file"),
    max_events: int = typer.Option(5000, "--max-events", min=1, max=50000),
    dry_run: bool = typer.Option(True, "--dry-run/--live"),
):
    cand_doc = None
    if candidate:
        cand_doc = DetectionRule.model_validate(
            yaml.safe_load(candidate.read_text(encoding="utf-8"))
        ).model_dump(mode="json")
    event_ids = []
    target_type = "DATASET"
    if events:
        target_type = "EVENTS"
        records = load_events(events, "json")
        event_ids = [
            str(r.raw_event.get("event_id", f"evt-{i}"))
            if isinstance(r.raw_event, dict)
            else f"evt-{i}"
            for i, r in enumerate(records)
        ]

    payload = {
        "rule_id": rule_id,
        "candidate_document": cand_doc,
        "target_type": target_type,
        "dataset_name": dataset,
        "event_ids": event_ids,
        "max_events": max_events,
        "dry_run": dry_run,
    }
    output(ctx, call(ctx, "POST", f"rules/{rule_id}/replay", json=payload))


@groups["rules"].command("replays")
def list_replays_cli(ctx: typer.Context, rule_id: str):
    output(ctx, call(ctx, "GET", f"rules/{rule_id}/replays"))


@groups["rules"].command("diff")
def diff_rule_versions_cli(
    ctx: typer.Context,
    rule_id: str,
    v1: int = typer.Option(..., "--v1", help="Base version"),
    v2: int = typer.Option(..., "--v2", help="Target version"),
):
    import difflib

    versions_data = call(ctx, "GET", f"rules/{rule_id}/versions", params={"limit": 200})
    items = versions_data.get("items", []) if isinstance(versions_data, dict) else []
    doc1 = next((item.get("document") for item in items if item.get("version") == v1), None)
    doc2 = next((item.get("document") for item in items if item.get("version") == v2), None)
    if not doc1:
        console.print(f"Version {v1} not found for rule {rule_id}")
        raise typer.Exit(1)
    if not doc2:
        console.print(f"Version {v2} not found for rule {rule_id}")
        raise typer.Exit(1)

    text1 = json.dumps(doc1, indent=2, sort_keys=True).splitlines()
    text2 = json.dumps(doc2, indent=2, sort_keys=True).splitlines()
    diff = list(difflib.unified_diff(text1, text2, fromfile=f"v{v1}", tofile=f"v{v2}", lineterm=""))
    if not diff:
        console.print("No differences found between version documents.")
    else:
        for line in diff:
            if line.startswith("+"):
                console.print(f"[green]{line}[/green]")
            elif line.startswith("-"):
                console.print(f"[red]{line}[/red]")
            elif line.startswith("@"):
                console.print(f"[cyan]{line}[/cyan]")
            else:
                console.print(line)


@groups["rules"].command("import-sigma")
def import_sigma_cli(ctx: typer.Context, path: Path):
    if not path.exists():
        console.print(f"File not found: {path}")
        raise typer.Exit(1)
    raw_content = path.read_text(encoding="utf-8")
    output(ctx, call(ctx, "POST", "rules/import-sigma", json={"yaml_rule": raw_content}))


@groups["rules"].command("coverage")
def coverage_cli(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "coverage/mitre"))


@groups["iocs"].command("add")
def add_ioc(
    ctx: typer.Context, type: str = typer.Option(...), value: str = typer.Option(...), source: str = "analyst"
):
    output(ctx, call(ctx, "POST", "iocs", json={"type": type, "value": value, "source": source}))


@groups["reports"].command("generate")
def report(ctx: typer.Context, incident: str, identifier: str | None = None):
    output(
        ctx,
        call(ctx, "POST", "reports/" + (identifier if incident == "incident" and identifier else incident)),
    )


@groups["collectors"].command("status")
def collectors_status(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "collectors"))


@groups["incidents"].command("create")
def incident_create(
    ctx: typer.Context, title: str, alert: list[str] = typer.Option([]), severity: str = "high"
):
    from uuid import uuid4

    output(
        ctx,
        call(
            ctx,
            "POST",
            "incidents",
            json={"title": title, "alert_ids": alert, "severity": severity},
            headers={"Idempotency-Key": str(uuid4())},
        ),
    )


@groups["playbooks"].command("request")
def response_request(ctx: typer.Context, action: str, target: str, idempotency_key: str):
    output(
        ctx,
        call(
            ctx,
            "POST",
            "playbooks/request",
            json={"action": action, "target": target},
            headers={"Idempotency-Key": idempotency_key},
        ),
    )


@groups["playbooks"].command("approve")
def response_approve(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "POST", f"playbooks/{identifier}/approve"))


@groups["playbooks"].command("execute")
def response_execute(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "POST", f"playbooks/{identifier}/execute"))


@groups["audit"].command("verify")
def audit_verify(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "audit/verify"))


@app.command()
def investigate(ctx: typer.Context, identifier: str, ai: bool = False):
    output(ctx, call(ctx, "POST" if ai else "GET", f"investigations/{identifier}" + ("/ai" if ai else "")))


@app.command()
def hunt(
    ctx: typer.Context,
    query: str = typer.Option(""),
    ip: str = "",
    user: str = "",
    hours: int = 24,
    limit: int = 50,
    cursor: str = "",
):
    search = parse_query(query)
    search.start = datetime.now(UTC) - timedelta(hours=hours)
    search.limit, search.cursor = limit, cursor or None
    from aegis.schemas import Predicate

    if ip:
        search.filters.append(Predicate(field="source_ip", value=ip))
    if user:
        search.filters.append(Predicate(field="username", value=user))
    output(ctx, call(ctx, "POST", "events/search", json=search.model_dump(mode="json")))


app.command("search")(hunt)
events_app = typer.Typer(no_args_is_help=True)
events_app.command("search")(hunt)
app.add_typer(events_app, name="events")


ingest_app = typer.Typer(no_args_is_help=True)
app.add_typer(ingest_app, name="ingest")


def load_events(path: Path, source_type: str) -> list[EventInput]:
    if path.stat().st_size > 20_000_000:
        raise typer.BadParameter("Input exceeds 20 MB; split it into smaller files")
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        values = json.loads(content)
        values = values if isinstance(values, list) else [values]
    else:
        values = [
            json.loads(line) if source_type == "json" and line.lstrip().startswith("{") else line
            for line in content.splitlines()
            if line.strip()
        ]
    return [
        EventInput.model_validate(value)
        if isinstance(value, dict) and "raw_event" in value
        else EventInput(
            source="file:" + hashlib.sha256(str(path.resolve()).encode()).hexdigest(),
            source_type=source_type,
            collector="cli-file",
            source_sequence=hashlib.sha256(content.encode()).hexdigest() + ":" + str(index),
            raw_event=value,
        )
        for index, value in enumerate(values)
    ]


def send_events(ctx, events):
    accepted, duplicates = 0, 0
    for offset in range(0, len(events), 100):
        result = call(
            ctx,
            "POST",
            "events/ingest",
            json={"events": [event.model_dump(mode="json") for event in events[offset : offset + 100]]},
        )
        accepted += len(result["accepted"])
        duplicates += len(result["duplicates"])
    output(ctx, {"accepted": accepted, "duplicates": duplicates})


@ingest_app.command("file")
def ingest_file(ctx: typer.Context, path: Path, source_type: str = "json"):
    send_events(ctx, load_events(path, source_type))


@groups["collectors"].command("run")
def run_collector(
    ctx: typer.Context,
    path: Path,
    spool: Path = typer.Option(...),
    name: str = "file-agent",
    source_type: str = "generic",
    once: bool = False,
    interval: float = typer.Option(2, min=0.1, max=60),
):
    """Tail a newline-delimited file with persistent checkpoints and durable retry spooling."""
    from urllib.parse import urlsplit

    from aegis.collector import FileCollector

    url = ctx.obj["url"].rstrip("/") + "/api/v1/"
    parsed = urlsplit(url)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise typer.BadParameter("Remote collectors require HTTPS")
    collector = FileCollector(spool, name)
    try:
        with httpx.Client(base_url=url, timeout=15, follow_redirects=False) as client:
            while True:
                collector.collect(path, source_type)
                delivered = collector.flush(client, os.environ.get("AEGIS_TOKEN", ""))
                if once:
                    output(ctx, {"delivered": delivered, "spool": collector.status()})
                    break
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print("Collector stopped; unacknowledged records remain in the spool.")
    finally:
        collector.close()


@groups["collectors"].command("spool")
def spool_status(ctx: typer.Context, path: Path, retry_quarantined: bool = False):
    from aegis.collector import FileCollector

    collector = FileCollector(path, "inspection")
    try:
        if retry_quarantined:
            collector.retry_quarantined()
        output(ctx, collector.status())
    finally:
        collector.close()


integration_app = typer.Typer(no_args_is_help=True)
app.add_typer(integration_app, name="integrations")


@integration_app.command("list")
def integration_list(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "integrations"))


@integration_app.command("save")
def integration_save(ctx: typer.Context, path: Path, identifier: str = "new"):
    output(
        ctx, call(ctx, "PUT", "integrations/" + identifier, json=json.loads(path.read_text(encoding="utf-8")))
    )


@integration_app.command("sync")
def integration_sync(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "POST", f"integrations/{identifier}/sync"))


@integration_app.command("deliveries")
def integration_deliveries(ctx: typer.Context, cursor: str = ""):
    output(ctx, call(ctx, "GET", "deliveries", params={"cursor": cursor}))


ingest_app.command("json")(ingest_file)


@ingest_app.command("directory")
def ingest_directory(ctx: typer.Context, path: Path, source_type: str = "generic"):
    for file in sorted(path.iterdir()):
        if file.is_file() and not file.is_symlink() and file.suffix in {".log", ".json", ".jsonl"}:
            send_events(ctx, load_events(file, source_type))


@ingest_app.command("syslog")
def ingest_syslog(ctx: typer.Context, listen: str = "127.0.0.1:5514", allow_remote: bool = False):
    """Receive UDP syslog. UDP is best effort; use files/HTTPS for durable delivery."""
    host, port_text = listen.rsplit(":", 1)
    port = int(port_text)
    if port < 1024 or port > 65535:
        raise typer.BadParameter("Use an unprivileged port between 1024 and 65535")
    if host not in {"127.0.0.1", "localhost"} and not allow_remote:
        raise typer.BadParameter("Remote binding requires --allow-remote and network ACLs")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))
        console.print(f"Receiving best-effort UDP syslog on {listen}; Ctrl+C to stop")
        while True:
            payload, address = server.recvfrom(65536)
            send_events(
                ctx,
                [
                    EventInput(
                        source=address[0],
                        source_type="syslog",
                        collector="syslog-udp",
                        timestamp=datetime.now(UTC),
                        raw_event=payload.decode("utf-8", errors="replace"),
                    )
                ],
            )


@app.command("simulate")
def simulation(ctx: typer.Context, scenario: str, host: str = "LAB-WEB-01", source_ip: str = "192.0.2.44"):
    import ipaddress
    source_ip = str(ipaddress.ip_address(source_ip))
    if not 1 <= len(host) <= 200:
        raise typer.BadParameter("Host must contain 1–200 characters")
    if scenario == "attack-chain":
        call(
            ctx,
            "POST",
            "iocs",
            json={
                "type": "ip",
                "value": "203.0.113.10",
                "source": "synthetic-dataset",
                "description": "Documentation-only address used by the safe attack-chain dataset",
            },
        )
    events = simulate(scenario)
    for event in events:
        if isinstance(event.raw_event, dict):
            event.raw_event = event.raw_event | {"host": host, "source_ip": source_ip}
    send_events(ctx, events)


@app.command()
def replay(ctx: typer.Context, path: Path, speed: float = 0, deterministic: bool = False):
    events = load_events(path, "json")
    if speed < 0:
        raise typer.BadParameter("Speed must be nonnegative; zero sends without delays")
    if deterministic or speed == 0:
        send_events(ctx, events)
    else:
        previous = None
        for event in events:
            if previous and event.timestamp:
                time.sleep(min(60, max(0, (event.timestamp - previous).total_seconds() / speed)))
            send_events(ctx, [event])
            previous = event.timestamp


mitre_app = typer.Typer()
app.add_typer(mitre_app, name="mitre")


@mitre_app.command("technique")
def technique(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "GET", f"mitre/{identifier}"))


system_app = typer.Typer()
app.add_typer(system_app, name="system")
system_app.command("health")(status)


@system_app.command("config")
def system_config(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "system/config"))


@system_app.command("retry")
def retry(ctx: typer.Context, event_id: str):
    output(ctx, call(ctx, "POST", f"system/dead-letter/{event_id}/retry"))


@app.command("detections")
def detections(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "rules"))


@app.command("threat-intel")
def threat_intel(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "iocs"))


benchmark_app = typer.Typer()
app.add_typer(benchmark_app, name="benchmark")


@benchmark_app.command("ingest")
def benchmark(ctx: typer.Context, events: int = typer.Option(1000, min=1, max=1000000)):
    started = time.monotonic()
    stamp = datetime.now(UTC)
    for offset in range(0, events, 100):
        batch = [
            EventInput(
                source="benchmark",
                collector="synthetic-benchmark",
                timestamp=stamp,
                source_sequence=f"{stamp.isoformat()}:{index}",
                raw_event={
                    "message": "Synthetic load event",
                    "host": "BENCH-01",
                    "event_category": "application",
                },
            )
            for index in range(offset, min(events, offset + 100))
        ]
        call(
            ctx, "POST", "events/ingest", json={"events": [event.model_dump(mode="json") for event in batch]}
        )
    elapsed = time.monotonic() - started
    output(
        ctx,
        {
            "events_accepted": events,
            "elapsed_seconds": elapsed,
            "accepted_per_second": events / elapsed,
            "scope": "API acceptance, not processing throughput",
        },
    )


agent_app = typer.Typer(help="AEGIS Endpoint Agent containment daemon and management")
app.add_typer(agent_app, name="agent")


@agent_app.command("run")
def run_agent(
    ctx: typer.Context,
    name: str | None = typer.Option(None, "--name", help="Hostname or agent identifier"),
    server: str | None = typer.Option(None, "--server", help="AEGIS server URL (defaults to context URL)"),
    token: str | None = typer.Option(None, "--token", help="Bearer token (defaults to AEGIS_TOKEN env)"),
    interval: float = typer.Option(5.0, "--interval", help="Polling interval in seconds"),
    once: bool = typer.Option(False, "--once", help="Run single heartbeat/execution cycle and exit"),
    live: bool = typer.Option(False, "--live", help="Enable live OS firewall/process modifications instead of safe simulation"),
    controller_ip: str = typer.Option("127.0.0.1", "--controller-ip", help="AEGIS controller IP allowed through firewall"),
):
    from aegis.agent import EndpointAgent

    target_server = server or ctx.obj.get("url", "http://127.0.0.1:8000")
    target_token = token or os.environ.get("AEGIS_TOKEN", "")
    agent = EndpointAgent(
        name=name,
        server_url=target_server,
        token=target_token,
        controller_ip=controller_ip,
        simulation_mode=not live,
    )
    try:
        if once:
            summary = agent.run_cycle()
            output(ctx, summary)
        else:
            console.print(f"[bold cyan]AEGIS Endpoint Agent[/bold cyan] starting on host [bold]{agent.name}[/bold]")
            console.print(f"Controller: {target_server} | Mode: {'LIVE' if live else 'SIMULATED'}")
            agent.run_forever(interval=interval)
    except Exception as exc:
        console.print(f"[bold red]Agent execution error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@agent_app.command("list")
def list_agents(ctx: typer.Context):
    """List registered endpoint agents and isolation statuses."""
    output(ctx, call(ctx, "GET", "agents"))


@agent_app.command("status")
def agent_status(ctx: typer.Context):
    """Display host posture and system telemetry of local agent."""
    from aegis.agent import EndpointAgent

    agent = EndpointAgent()
    output(ctx, agent.get_system_info())


maintenance_app = typer.Typer(no_args_is_help=True, help="Data lifecycle and maintenance operations")
app.add_typer(maintenance_app, name="maintenance")


@maintenance_app.command("retention")
def run_retention_cli(
    ctx: typer.Context,
    dry_run: bool = typer.Option(False, "--dry-run", help="Report eligible records without deleting"),
):
    """Run data lifecycle retention cleanup across security events and transient state."""
    output(ctx, call(ctx, "POST", "system/retention", params={"dry_run": dry_run}))


soar_app = typer.Typer(help="Versioned SOAR workflows (separate from single-action responses).")
app.add_typer(soar_app, name="soar")


@soar_app.command("list")
def soar_list(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "soar/playbooks"))


@soar_app.command("validate")
def soar_validate(ctx: typer.Context, file: Path):
    output(ctx, call(ctx, "POST", "soar/validate", json=json.loads(file.read_text())))


@soar_app.command("save")
def soar_save(ctx: typer.Context, file: Path):
    output(ctx, call(ctx, "POST", "soar/playbooks", json=json.loads(file.read_text())))


@soar_app.command("execute")
def soar_execute(ctx: typer.Context, identifier: str, source_type: str, source_id: str,
                 idempotency_key: str, target_id: str = "", ioc_id: str = "", observable_id: str = "", dry_run: bool = True):
    inputs = {k: v for k, v in {"target_id": target_id, "ioc_id": ioc_id, "observable_id": observable_id}.items() if v}
    output(ctx, call(ctx, "POST", f"soar/playbooks/{identifier}/execute", json={
        "source_type": source_type, "source_id": source_id, "inputs": inputs,
        "idempotency_key": idempotency_key, "dry_run": dry_run}))


@soar_app.command("inspect")
def soar_inspect(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "GET", f"soar/executions/{identifier}"))


@soar_app.command("approve")
def soar_approve(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "POST", f"soar/executions/{identifier}/decision", json={"decision": "approve"}))


@soar_app.command("decision")
def soar_decision(ctx: typer.Context, identifier: str, decision: str):
    output(ctx, call(ctx, "POST", f"soar/executions/{identifier}/decision", json={"decision": decision}))



@groups["iocs"].command("enrich")
def intel_enrich(ctx: typer.Context, kind: str, value: str, provider: str = "virustotal", refresh: bool = False):
    output(ctx, call(ctx, "POST", "iocs/enrich", json={"observable": {"type": kind, "value": value},
        "provider": provider, "refresh": refresh}))


@groups["iocs"].command("enrich-batch")
def intel_batch(ctx: typer.Context, file: Path, provider: str = "virustotal"):
    output(ctx, call(ctx, "POST", "iocs/enrich-batch", json={"observables": json.loads(file.read_text(encoding="utf-8")), "provider": provider}))


@groups["iocs"].command("enrich-source")
def intel_source(ctx: typer.Context, source_type: str, source_id: str, provider: str = "virustotal"):
    output(ctx, call(ctx, "POST", "iocs/enrich-source", json={"source_type": source_type, "source_id": source_id, "provider": provider}))


@groups["iocs"].command("providers")
def intel_providers(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "iocs/providers"))


@groups["iocs"].command("observables")
def intel_observables(ctx: typer.Context, offset: int = 0):
    output(ctx, call(ctx, "GET", "iocs/observables", params={"offset": offset}))


@groups["iocs"].command("inspect-observable")
def intel_detail(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "GET", f"iocs/observables/{identifier}"))


@groups["iocs"].command("enrichment-history")
def intel_history(ctx: typer.Context, identifier: str, offset: int = 0):
    output(ctx, call(ctx, "GET", f"iocs/enrichments/{identifier}/history", params={"offset": offset}))


ueba_app = typer.Typer(help="Bounded behavioral analysis and evidence")
app.add_typer(ueba_app, name="ueba")


@ueba_app.command("profiles")
def ueba_profiles(ctx: typer.Context, entity: str = "", offset: int = 0):
    output(ctx, call(ctx, "GET", "ueba/profiles", params={"entity": entity, "offset": offset}))


@ueba_app.command("profile")
def ueba_profile(ctx: typer.Context, identifier: str):
    output(ctx, call(ctx, "GET", f"ueba/profiles/{identifier}"))


@ueba_app.command("findings")
def ueba_findings(ctx: typer.Context, entity: str = "", detector: str = "", offset: int = 0):
    output(ctx, call(ctx, "GET", "ueba/findings", params={"entity": entity, "detector": detector, "offset": offset}))


@ueba_app.command("evidence")
def ueba_evidence(ctx: typer.Context, identifier: str, offset: int = 0):
    output(ctx, call(ctx, "GET", f"ueba/findings/{identifier}", params={"offset": offset}))


@ueba_app.command("analyze")
def ueba_analyze(ctx: typer.Context, window_end: str, refresh_only: bool = False):
    output(ctx, call(ctx, "POST", "ueba/analyze", json={"window_end": window_end, "refresh_only": refresh_only}))


@ueba_app.command("jobs")
def ueba_jobs(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "ueba/jobs"))


@ueba_app.command("detectors")
def ueba_detectors(ctx: typer.Context):
    output(ctx, call(ctx, "GET", "ueba/detectors"))


if __name__ == "__main__":
    app()
