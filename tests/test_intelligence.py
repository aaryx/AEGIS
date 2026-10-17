"""Focused intelligence behavior and regression checks, with no live provider calls."""

import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from aegis.db import IOC, Enrichment, EnrichmentHistory, EventRecord, Observable, ObservableEvent
from aegis.intel_providers import PROVIDERS, ProviderResult, VirusTotalProvider
from aegis.intelligence import detection_context, index_once, lookup_once, observe, queue
from aegis.observables import ObservableInput, extract, normalize
from aegis.soar import lock_tenant


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("ip", "2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888"),
        ("domain", "Sub.Example.COM.", "sub.example.com"),
        ("domain", "b\u00fccher.de", "xn--bcher-kva.de"),
        ("hash", "A" * 64, "a" * 64),
        ("url", "HTTPS://Example.com:443/path?token=private#secret", "https://example.com/path"),
    ],
)
def test_normalization(kind, value, expected):
    assert normalize(kind, value)[1] == expected


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip", "999.1.1.1"),
        ("ip", "fe80::1%eth0"),
        ("domain", "-bad.test"),
        ("domain", "x..com"),
        ("url", "file:///etc/passwd"),
        ("url", "http://user:secret@example.com"),
        ("md5", "a" * 64),
        ("hash", "nope"),
    ],
)
def test_invalid(kind, value):
    with pytest.raises(ValueError):
        ObservableInput(type=kind, value=value)


def submit(system, value="malicious.example.test", kind="domain", provider="mock", **kwargs):
    return system["client"].post(
        "/api/v1/iocs/enrich",
        json={"observable": {"type": kind, "value": value}, "provider": provider, **kwargs},
    )


def tick(system):
    lookup_once(system["settings"], system["app"].state.sessions)


def test_mock_cache_history_and_unknown(system):
    system["settings"].intel_mock_enabled = True
    result = submit(system).json()
    tick(system)
    response = submit(system).json()
    assert response["lookup"]["id"] == result["lookup"]["id"]
    assert response["lookup"]["assessment"]["assessment_origin"] == "mock"
    assert response["lookup"]["assessment"]["verdict"] == "malicious"
    history = system["client"].get(f"/api/v1/iocs/enrichments/{result['lookup']['id']}/history").json()
    assert len(history["items"]) == 1
    assert submit(system, refresh=True).json()["lookup"]["status"] == "COMPLETE"  # Refresh cooldown.
    private = submit(system, "127.0.0.1", "ip").json()
    tick(system)
    item = system["client"].get(f"/api/v1/iocs/observables/{private['observable']['id']}").json()
    assert item["lookups"][0]["assessment"]["verdict"] == "unknown"
    assert item["external_allowed"] is False
    with system["app"].state.sessions() as db:
        assert not list(db.scalars(select(IOC)))


def test_unavailable_config_and_tenant_rbac(system):
    result = submit(system, "8.8.8.8", "ip", "virustotal").json()
    tick(system)
    detail = system["client"].get(f"/api/v1/iocs/observables/{result['observable']['id']}").json()
    assert detail["lookups"][0]["status"] == "UNAVAILABLE"
    assert detail["lookups"][0]["assessment"]["verdict"] == "unknown"
    health = system["client"].get("/api/v1/iocs/providers").json()
    assert not any(p["configured"] for p in health["items"])
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert system["client"].get(f"/api/v1/iocs/observables/{result['observable']['id']}").status_code == 404
    assert (
        system["client"].get(f"/api/v1/iocs/enrichments/{result['lookup']['id']}/history").status_code == 404
    )
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["VIEWER"]
    assert submit(system).status_code == 403


def test_batch_bounds_and_atomicity(system):
    client = system["client"]
    assert (
        client.post(
            "/api/v1/iocs/enrich-batch", json={"observables": [{"type": "ip", "value": "8.8.8.8"}] * 51}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/iocs/enrich-batch",
            json={"observables": [{"type": "ip", "value": "8.8.8.8"}, {"type": "ip", "value": "invalid"}]},
        ).status_code
        == 422
    )
    assert client.get("/api/v1/iocs/observables").json()["items"] == []


def test_extraction_links_and_detection_separation(system):
    payload = {
        "source_ip": "192.168.1.1",
        "http": {"url": "https://example.com/path?token=secret"},
        "raw_event": "malicious.example.test",
    }
    assert len(extract(payload)) == 3
    with system["app"].state.sessions.begin() as db:
        from aegis.db import now

        record = EventRecord(
            organization_id=system["org"],
            timestamp=now(),
            source="test",
            evidence_hash="a" * 64,
            payload=payload,
            state="PROCESSED",
        )
        db.add(record)
        db.flush()
        identifier = record.id
    index_once(system["settings"], system["app"].state.sessions)
    with system["app"].state.sessions() as db:
        assert db.get(EventRecord, identifier).payload == payload
        assert len(list(db.scalars(select(Observable)))) == 3
        assert len(list(db.scalars(select(ObservableEvent)))) == 3
        assert not list(db.scalars(select(Enrichment)))
        assert detection_context(db, system["org"], payload)["intel_verdicts"] == ["unknown"]
    result = system["client"].post(
        "/api/v1/iocs/enrich-source",
        json={"source_type": "event", "source_id": identifier, "provider": "mock"},
    )
    assert result.status_code == 200, result.text
    assert len(result.json()["items"]) == 3
    obs = result.json()["items"][0]["observable"]["id"]
    assert system["client"].get(f"/api/v1/iocs/observables/{obs}").json()["related"]["events"] == [identifier]


def test_failure_retry_and_crash_recovery(system, monkeypatch):
    class Failing:
        def lookup(self, settings, obs):
            raise RuntimeError("private-api-key-do-not-log")

    monkeypatch.setitem(PROVIDERS, "mock", Failing())
    item = submit(system).json()["lookup"]
    for attempt in range(3):
        tick(system)
        with system["app"].state.sessions.begin() as db:
            row = db.get(Enrichment, item["id"])
            assert row.attempts == attempt + 1
            assert "private-api-key" not in str(row.result)
            row.available_at = 0
    with system["app"].state.sessions() as db:
        assert db.get(Enrichment, item["id"]).status == "FAILED"
        assert len(list(db.scalars(select(EnrichmentHistory)))) == 3
    other = submit(system, "other.example.test").json()["lookup"]
    with system["app"].state.sessions.begin() as db:
        row = db.get(Enrichment, other["id"])
        row.status, row.lease_until, row.lease_token = "RUNNING", time.time() - 1, "dead-worker"
    tick(system)
    with system["app"].state.sessions() as db:
        assert db.get(Enrichment, other["id"]).status == "QUEUED"


def test_concurrent_queue_and_lookup(system):
    system["settings"].intel_mock_enabled = True

    def add(_):
        with system["app"].state.sessions.begin() as db:
            lock_tenant(db, system["org"])
            obs = observe(db, system["org"], "domain", "malicious.example.test")
            return queue(db, system["settings"], obs, "mock").id

    with ThreadPoolExecutor(max_workers=3) as pool:
        identifiers = list(pool.map(add, range(3)))
    assert len(set(identifiers)) == 1
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: tick(system), range(3)))
    with system["app"].state.sessions() as db:
        assert len(list(db.scalars(select(EnrichmentHistory)))) == 1


def test_vt_mapping_fixed_endpoint_and_privacy(system, monkeypatch):
    from pydantic import SecretStr

    from aegis import intel_providers

    calls = []
    system["settings"].intel_vt_enabled = True
    system["settings"].intel_vt_api_key = SecretStr("test-provider-key")

    def request(settings, endpoint, **kwargs):
        calls.append(endpoint)
        return b'{"data":{"attributes":{"last_analysis_stats":{"malicious":2,"harmless":5},"last_analysis_date":100}}}'

    monkeypatch.setattr(intel_providers, "request_bytes", request)
    provider = VirusTotalProvider()
    result = provider.lookup(
        system["settings"], SimpleNamespace(type="ip", value="8.8.8.8", external_allowed=True)
    )
    assert result.verdict == "malicious"
    assert result.assessment_origin == "aegis-derived" and result.confidence is None
    assert calls == ["https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"]
    assert "test-provider-key" not in str(result)
    private = provider.lookup(
        system["settings"],
        SimpleNamespace(type="url", value="http://169.254.169.254/metadata", external_allowed=False),
    )
    assert private.status == "UNAVAILABLE" and len(calls) == 1


def test_soar_enrichment_wait_and_branch(system):
    from aegis.soar import process_workflows

    system["settings"].intel_mock_enabled = True
    item = submit(system).json()
    from tests.test_soar import setup
    from tests.test_soar import submit as start

    definition = {
        "description": "Enrich before investigation",
        "trigger": {"source": "incident"},
        "input_schema": {"observable_id": "observable"},
        "steps": [
            {"id": "intel", "action": "enrich_observable", "provider": "mock"},
            {
                "id": "note",
                "action": "incident_note",
                "when": {"field": "intel_verdict", "value": "malicious"},
            },
        ],
    }
    book, source, _ = setup(system, definition)
    run = start(
        system, book, source, dry_run=False, inputs={"observable_id": item["observable"]["id"]}
    ).json()
    process_workflows(system["settings"], system["app"].state.sessions)
    tick(system)
    with system["app"].state.sessions.begin() as db:
        from aegis.db import WorkflowRun

        db.get(WorkflowRun, run["id"]).available_at = 0
    process_workflows(system["settings"], system["app"].state.sessions)
    process_workflows(system["settings"], system["app"].state.sessions)
    detail = system["client"].get(f"/api/v1/soar/executions/{run['id']}").json()
    assert detail["status"] == "SUCCEEDED", detail
    assert detail["history"][0]["output"]["data"]["assessment_origin"] == "mock"


def test_cli(monkeypatch):
    from aegis import cli

    calls = []
    monkeypatch.setattr(
        cli, "call", lambda ctx, method, path, **kwargs: calls.append((method, path, kwargs)) or {}
    )
    result = CliRunner().invoke(cli.app, ["iocs", "enrich", "domain", "example.com", "--provider", "mock"])
    assert result.exit_code == 0, result.output
    assert calls[0][1] == "iocs/enrich"


def test_expiry_is_unknown_and_refresh_is_controlled(system):
    system["settings"].intel_mock_enabled = True
    item = submit(system).json()
    tick(system)
    with system["app"].state.sessions.begin() as db:
        row = db.get(Enrichment, item["lookup"]["id"])
        row.expires_at = time.time() - 1
        row.enriched_at = time.time() - 120
    detail = system["client"].get(f"/api/v1/iocs/enrichments/{item['lookup']['id']}").json()
    assert detail["assessment"]["verdict"] == "unknown" and detail["stale"]
    assert "lease_token" not in detail
    assert submit(system).json()["lookup"]["status"] == "QUEUED"


def test_provider_rate_and_stale_lease_fencing(system, monkeypatch):
    from aegis.intelligence import reserve_provider

    with system["app"].state.sessions.begin() as db:
        assert reserve_provider(db, system["settings"], "virustotal")
        assert not reserve_provider(db, system["settings"], "virustotal")
    item = submit(system).json()

    class StaleWorker:
        def lookup(self, settings, observable):
            with system["app"].state.sessions.begin() as db:
                row = db.get(Enrichment, item["lookup"]["id"])
                row.lease_token = "replacement-worker"
            return ProviderResult(status="COMPLETE", verdict="malicious", reason="stale-result")

    monkeypatch.setitem(PROVIDERS, "mock", StaleWorker())
    tick(system)
    with system["app"].state.sessions() as db:
        assert db.get(Enrichment, item["lookup"]["id"]).result == {}
        assert not list(db.scalars(select(EnrichmentHistory)))


def test_source_tenant_and_mock_cannot_influence_detection(system):
    system["settings"].intel_mock_enabled = True
    submit(system)
    tick(system)
    with system["app"].state.sessions() as db:
        context = detection_context(db, system["org"], {"http": {"domain": "malicious.example.test"}})
        assert context["intel_verdict"] == "unknown" and context["intel_confidence"] is None
    from tests.test_soar import setup

    _, source, _ = setup(system)
    system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert (
        system["client"]
        .post("/api/v1/iocs/enrich-source", json={"source_type": "incident", "source_id": source})
        .status_code
        == 404
    )


def test_soar_dry_run_never_queues_provider(system):
    from aegis.soar import process_workflows
    from tests.test_soar import setup
    from tests.test_soar import submit as start

    with system["app"].state.sessions.begin() as db:
        lock_tenant(db, system["org"])
        obs = observe(db, system["org"], "ip", "8.8.8.8")
        identifier = obs.id
    definition = {
        "description": "Dry enrichment",
        "trigger": {"source": "incident"},
        "input_schema": {"observable_id": "observable"},
        "steps": [{"id": "intel", "action": "enrich_observable"}],
    }
    book, source, _ = setup(system, definition)
    run = start(system, book, source, inputs={"observable_id": identifier}).json()
    process_workflows(system["settings"], system["app"].state.sessions)
    assert system["client"].get(f"/api/v1/soar/executions/{run['id']}").json()["status"] == "SUCCEEDED"
    with system["app"].state.sessions() as db:
        assert not list(db.scalars(select(Enrichment)))


def test_related_observables_tenant_isolation(system):
    """Verify that related() strictly isolates alerts, incidents, and storylines by organization."""
    from datetime import UTC, datetime

    from aegis.db import Alert, AlertEvent, EventRecord, Incident, IncidentAlert
    from aegis.intelligence import related

    org_a = system["org"]
    org_b = system["other"]
    test_ip = "198.51.100.77"

    # Seed in Tenant A
    with system["app"].state.sessions.begin() as db:
        obs_a = observe(db, org_a, "ip", test_ip)
        obs_a_id = obs_a.id

    # Seed in Tenant B with an event, alert, and incident linking to that IP
    with system["app"].state.sessions.begin() as db:
        obs_b = observe(db, org_b, "ip", test_ip)
        ev_b = EventRecord(
            id="ev-tenant-b-001",
            organization_id=org_b,
            timestamp=datetime.now(UTC),
            evidence_hash="ev-hash-b",
            source="syslog",
            state="PROCESSED",
            payload={"source_ip": test_ip},
        )
        alert_b = Alert(
            id="ALT-tenant-b-001",
            organization_id=org_b,
            title="Tenant B Alert",
            severity="high",
            rule_id="rule-b",
            rule_version=1,
            fingerprint="fp-b-001",
            correlation_key="ck-b-001",
            confidence=90,
            risk_score=80,
            risk_factors={},
            explanation={},
            mitre_techniques=[],
            entity_ids=[],
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        inc_b = Incident(
            id="INC-tenant-b-001",
            organization_id=org_b,
            title="Tenant B Incident",
            severity="high",
        )
        db.add_all([ev_b, alert_b, inc_b])
        db.flush()
        db.add(ObservableEvent(organization_id=org_b, observable_id=obs_b.id, event_id=ev_b.id))
        db.add(AlertEvent(alert_id=alert_b.id, event_id=ev_b.id))
        db.add(IncidentAlert(incident_id=inc_b.id, alert_id=alert_b.id))

    # Tenant A queries related for obs_a
    with system["app"].state.sessions() as db:
        rel_a = related(db, org_a, obs_a_id)
        # Must NOT leak Tenant B's alert, incident, or event
        assert "ALT-tenant-b-001" not in rel_a["alerts"]
        assert "INC-tenant-b-001" not in rel_a["incidents"]
        assert "ev-tenant-b-001" not in rel_a["events"]

    # Also test via API endpoint: Tenant A client cannot access Tenant B's observable
    api_resp = system["client"].get(f"/api/v1/iocs/observables/{obs_b.id}/related")
    assert api_resp.status_code == 404

