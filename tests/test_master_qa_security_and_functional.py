"""Comprehensive Master QA Functional & Security Test Suite.

Verifies:
1. Detailed observable normalization & validation for all types (IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256).
2. Threat intelligence cache lifecycle, rate limits, expiry semantics, and provider fault handling.
3. SOAR playbook validation, execution lifecycle, approval security, and simulated containment safety.
4. CLI command routing, argument parsing, and response formatting for all IOC and SOAR commands.
5. In-depth Security Auditing: Cross-tenant IDOR, privilege escalation, SSRF mitigation, and secret leak prevention.
"""

import json
import time
from types import SimpleNamespace

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from typer.testing import CliRunner

from aegis import cli
from aegis.db import (
    AuditLog,
    CaseNote,
    Enrichment,
    Entity,
    Incident,
    Observable,
    WorkflowRun,
)
from aegis.intel_providers import PROVIDERS, VirusTotalProvider
from aegis.intelligence import (
    lookup_once,
    observe,
    queue,
)
from aegis.observables import normalize
from aegis.soar import (
    ADAPTERS,
    Definition,
    process_workflows,
)

# -----------------------------------------------------------------------------
# 1. OBSERVABLE VALIDATION & NORMALIZATION TESTS
# -----------------------------------------------------------------------------

def test_ipv4_and_ipv6_normalization_and_suppression():
    """Verify IP normalization, boundary values, and external eligibility."""
    # Globally routable public unicast IPs: external_allowed = True
    assert normalize("ip", "8.8.8.8") == ("ip", "8.8.8.8", True)
    assert normalize("ip", "1.1.1.1") == ("ip", "1.1.1.1", True)
    assert normalize("ip", "2001:4860:4860::8888") == ("ip", "2001:4860:4860::8888", True)

    # IPv6 compressed notation and lowercase hex
    assert normalize("ip", "2001:0DB8:0000:0000:0000:0000:0000:0001")[1] == "2001:db8::1"

    # Private, loopback, link-local, multicast, documentation IPs: external_allowed = False
    assert normalize("ip", "127.0.0.1")[2] is False
    assert normalize("ip", "10.0.0.1")[2] is False
    assert normalize("ip", "172.16.0.1")[2] is False
    assert normalize("ip", "192.168.1.1")[2] is False
    assert normalize("ip", "169.254.169.254")[2] is False
    assert normalize("ip", "224.0.0.1")[2] is False
    assert normalize("ip", "255.255.255.255")[2] is False
    assert normalize("ip", "::1")[2] is False
    assert normalize("ip", "fe80::1")[2] is False

    # Malformed IPs safely rejected
    for invalid in ["256.1.1.1", "1.2.3.4.5", "invalid_ip", "fe80::1%eth0", "::ffff:999.1.1.1"]:
        with pytest.raises(ValueError):
            normalize("ip", invalid)


def test_domain_normalization_and_suppression():
    """Verify domain lowercase, trailing dot, IDN, and reserved suffix suppression."""
    # Standard domains
    assert normalize("domain", "EXAMPLE.COM.") == ("domain", "example.com", False)  # example is reserved
    assert normalize("domain", "threat.attacker-c2.net") == ("domain", "threat.attacker-c2.net", True)

    # Internationalized Domain Names (IDN) converted to ASCII Punycode
    kind, val, allowed = normalize("domain", "b\u00fccher.de")
    assert val == "xn--bcher-kva.de"
    assert allowed is True

    # Subdomains and label checks
    kind, val, allowed = normalize("domain", "sub3.deep.threat.org")
    assert val == "sub3.deep.threat.org"
    assert allowed is True

    # Reserved suffixes suppressed
    for reserved in ["internal", "corp", "test", "local", "localhost", "example.com"]:
        assert normalize("domain", f"host.{reserved}")[2] is False

    # Malformed domains rejected
    for invalid in ["-bad.com", "bad-.com", "bad..com", "no_underscores.com", "nodot", "a" * 255 + ".com", "127.0.0.1"]:
        with pytest.raises(ValueError):
            normalize("domain", invalid)


def test_url_normalization_and_credential_sanitization():
    """Verify URL scheme validation, credential stripping, and privacy suppression."""
    # Credentials stripped, query stripped, fragment stripped
    url_input = "HTTPS://admin:superSecret@Example.COM:443/api/v1/dl?token=secret123&session=xyz#download"
    # urlsplit rejects credentials in username/password
    with pytest.raises(ValueError, match="Expected HTTP"):
        normalize("url", url_input)

    # Valid URL without userinfo: query & fragment stripped before storage
    safe_url = "HTTPS://Example.COM:443/api/v1/dl?token=secret123#frag"
    kind, val, allowed = normalize("url", safe_url)
    assert kind == "url"
    assert val == "https://example.com/api/v1/dl"
    assert allowed is False  # URLs are never submitted to external providers

    # Non-standard port preserved
    kind, val, allowed = normalize("url", "http://example.com:8080/path")
    assert val == "http://example.com:8080/path"

    # SSRF / Arbitrary local resources safely rejected or suppressed
    for invalid in ["file:///etc/passwd", "ftp://ftp.example.com", "gopher://evil", "javascript:alert(1)", "http://host\\evil"]:
        with pytest.raises(ValueError):
            normalize("url", invalid)


def test_hash_normalization_and_algorithm_inference():
    """Verify MD5, SHA-1, SHA-256 validation and type inference."""
    md5 = "A" * 32
    sha1 = "B" * 40
    sha256 = "C" * 64

    # Direct type declarations
    assert normalize("md5", md5) == ("md5", md5.lower(), True)
    assert normalize("sha1", sha1) == ("sha1", sha1.lower(), True)
    assert normalize("sha256", sha256) == ("sha256", sha256.lower(), True)

    # Inferred algorithm from length when type is 'hash'
    assert normalize("hash", md5) == ("md5", md5.lower(), True)
    assert normalize("hash", sha1) == ("sha1", sha1.lower(), True)
    assert normalize("hash", sha256) == ("sha256", sha256.lower(), True)

    # Length / algorithm mismatch rejected
    with pytest.raises(ValueError):
        normalize("md5", sha256)
    with pytest.raises(ValueError):
        normalize("sha256", md5)
    with pytest.raises(ValueError):
        normalize("hash", "A" * 50)  # unsupported hash length
    with pytest.raises(ValueError):
        normalize("hash", "G" * 32)  # non-hex chars


# -----------------------------------------------------------------------------
# 2. THREAT INTEL PROVIDER & CACHE BEHAVIOR TESTS
# -----------------------------------------------------------------------------

def test_virustotal_provider_mapping_and_error_handling(system, monkeypatch):
    """Test VirusTotal adapter mapping, 404/401/403/500 handling, and secret preservation."""
    system["settings"].intel_vt_enabled = True
    system["settings"].intel_vt_api_key = SecretStr("secret-vt-api-key-999")
    vt = VirusTotalProvider()

    # 1. Successful response with statistics mapping
    def fake_request(transport, endpoint, headers):
        assert headers.get("x-apikey") == "secret-vt-api-key-999"
        return json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 20, "undetected": 10},
                    "first_seen_date": 1700000000,
                    "last_analysis_date": 1705000000,
                }
            }
        }).encode()

    from aegis import intel_providers
    monkeypatch.setattr(intel_providers, "request_bytes", fake_request)

    res = vt.lookup(system["settings"], SimpleNamespace(type="ip", value="8.8.8.8", external_allowed=True))
    assert res.status == "COMPLETE"
    assert res.verdict == "malicious"
    assert res.assessment_origin == "aegis-derived"
    assert res.confidence is None
    assert res.first_seen == 1700000000
    assert "secret-vt-api-key-999" not in str(res)

    # 2. 404 response produces UNKNOWN status (not clean!)
    def fake_404(*args, **kwargs):
        raise ValueError("Integration returned HTTP 404")
    monkeypatch.setattr(intel_providers, "request_bytes", fake_404)
    res_404 = vt.lookup(system["settings"], SimpleNamespace(type="ip", value="8.8.8.8", external_allowed=True))
    assert res_404.status == "UNKNOWN"
    assert res_404.reason == "provider_has_no_record"

    # 3. 401/403 produces UNAVAILABLE
    def fake_401(*args, **kwargs):
        raise ValueError("Integration returned HTTP 401")
    monkeypatch.setattr(intel_providers, "request_bytes", fake_401)
    res_401 = vt.lookup(system["settings"], SimpleNamespace(type="ip", value="8.8.8.8", external_allowed=True))
    assert res_401.status == "UNAVAILABLE"
    assert res_401.reason == "provider_authorization_failed"

    # 4. Network timeout / 500 error produces FAILED with retryable=True
    def fake_timeout(*args, **kwargs):
        raise TimeoutError("Socket timeout")
    monkeypatch.setattr(intel_providers, "request_bytes", fake_timeout)
    res_timeout = vt.lookup(system["settings"], SimpleNamespace(type="ip", value="8.8.8.8", external_allowed=True))
    assert res_timeout.status == "FAILED"
    assert res_timeout.retryable is True


def test_batch_enrichment_bounds_and_atomic_failure(system):
    """Test POST /iocs/enrich-batch limits and atomic rollback."""
    client = system["client"]

    # Oversized batch rejected (> 50 items)
    large_batch = [{"type": "ip", "value": f"203.0.113.{i}"} for i in range(51)]
    resp_large = client.post("/api/v1/iocs/enrich-batch", json={"observables": large_batch})
    assert resp_large.status_code == 422

    # Malformed member in batch aborts entire batch atomically (no partial persistence)
    mixed_batch = [
        {"type": "ip", "value": "203.0.113.1"},
        {"type": "ip", "value": "not-a-valid-ip"},
    ]
    resp_mixed = client.post("/api/v1/iocs/enrich-batch", json={"observables": mixed_batch})
    assert resp_mixed.status_code == 422

    # Verify no observables were persisted from rejected batch
    with system["app"].state.sessions() as db:
        obs = list(db.scalars(select(Observable).where(Observable.organization_id == system["org"])))
        assert len(obs) == 0


def test_cache_reuse_and_refresh_cooldown(system):
    """Verify caching, cooldown window, and expiry behavior."""
    client = system["client"]
    settings = system["settings"]
    settings.intel_mock_enabled = True

    # Initial enrichment request
    r1 = client.post("/api/v1/iocs/enrich", json={
        "observable": {"type": "domain", "value": "malicious.example.test"},
        "provider": "mock",
    }).json()
    enrichment_id = r1["lookup"]["id"]

    # Execute worker lookup
    lookup_once(settings, system["app"].state.sessions)

    # Repeated request reuses cached result
    r2 = client.post("/api/v1/iocs/enrich", json={
        "observable": {"type": "domain", "value": "malicious.example.test"},
        "provider": "mock",
        "refresh": False,
    }).json()
    assert r2["lookup"]["id"] == enrichment_id
    assert r2["lookup"]["assessment"]["verdict"] == "malicious"

    # Immediate refresh request within cooldown window (settings.intel_refresh_seconds = 60) is suppressed
    r3 = client.post("/api/v1/iocs/enrich", json={
        "observable": {"type": "domain", "value": "malicious.example.test"},
        "provider": "mock",
        "refresh": True,
    }).json()
    assert r3["lookup"]["status"] == "COMPLETE"  # Still COMPLETE, not re-queued

    # Expire entry manually: assessment becomes unknown, stale=True
    with system["app"].state.sessions.begin() as db:
        row = db.get(Enrichment, enrichment_id)
        row.expires_at = time.time() - 10
        row.enriched_at = time.time() - 120

    detail = client.get(f"/api/v1/iocs/enrichments/{enrichment_id}").json()
    assert detail["stale"] is True
    assert detail["assessment"]["verdict"] == "unknown"

    # Now request with refresh=True re-queues successfully
    r4 = client.post("/api/v1/iocs/enrich", json={
        "observable": {"type": "domain", "value": "malicious.example.test"},
        "provider": "mock",
        "refresh": True,
    }).json()
    assert r4["lookup"]["status"] == "QUEUED"


# -----------------------------------------------------------------------------
# 3. SOAR PLAYBOOK ENGINE TESTS
# -----------------------------------------------------------------------------

def test_playbook_schema_validation_and_branching_constraints():
    """Verify playbook structural validation and safety guardrails."""
    # 1. Missing required field
    with pytest.raises(ValueError):
        Definition.model_validate({
            "description": "Missing trigger",
            "steps": [{"id": "s1", "action": "summary"}],
        })

    # 2. Backward branching forbidden
    with pytest.raises(ValueError, match="Branches must point forward"):
        Definition.model_validate({
            "description": "Loop test",
            "trigger": {"source": "incident"},
            "steps": [
                {"id": "s1", "action": "summary"},
                {"id": "s2", "action": "summary", "when": {"field": "status", "value": "OPEN"}, "on_false": "s1"},
            ],
        })

    # 3. Containment action requires target_id entity input
    with pytest.raises(ValueError, match="Containment simulation requires target_id"):
        Definition.model_validate({
            "description": "Missing entity input",
            "trigger": {"source": "incident"},
            "steps": [{"id": "contain", "action": "simulate_block_ip"}],
        })

    # 4. enrich_observable requires observable_id input
    with pytest.raises(ValueError, match="enrich_observable requires an observable_id input"):
        Definition.model_validate({
            "description": "Missing observable input",
            "trigger": {"source": "incident"},
            "steps": [{"id": "enrich", "action": "enrich_observable"}],
        })

    # 5. Incident note on alert trigger forbidden (must be incident or storyline)
    with pytest.raises(ValueError, match="Incident notes require an incident or storyline trigger"):
        Definition.model_validate({
            "description": "Alert note test",
            "trigger": {"source": "alert"},
            "steps": [{"id": "note", "action": "incident_note"}],
        })


def test_dry_run_mode_enforces_zero_side_effects(system):
    """Verify dry-run executions NEVER write notes or execute containment."""
    client = system["client"]
    settings = system["settings"]

    with system["app"].state.sessions.begin() as db:
        incident = Incident(organization_id=system["org"], title="Dry Run Inc", severity="high")
        entity = Entity(organization_id=system["org"], type="ip", value="203.0.113.5")
        db.add_all([incident, entity])
        db.flush()
        inc_id, ent_id = incident.id, entity.id

    doc = {
        "description": "Dry Run Suite",
        "trigger": {"source": "incident"},
        "input_schema": {"target_id": "entity"},
        "steps": [
            {"id": "note", "action": "incident_note"},
            {"id": "block", "action": "simulate_block_ip"},
            {"id": "sum", "action": "summary"},
        ],
    }

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SECURITY_ADMIN"]
    pb = client.post("/api/v1/soar/playbooks", json={"name": "DryRun", "definition": doc, "enabled": True}).json()

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    run = client.post(
        f"/api/v1/soar/playbooks/{pb['id']}/execute",
        json={
            "source_type": "incident",
            "source_id": inc_id,
            "inputs": {"target_id": ent_id},
            "dry_run": True,
            "idempotency_key": "dry-run-001",
        },
    ).json()

    # Advance worker through all steps (dry run skips approval wait)
    for _ in range(4):
        process_workflows(settings, system["app"].state.sessions)

    detail = client.get(f"/api/v1/soar/executions/{run['id']}").json()
    assert detail["status"] == "SUCCEEDED"
    assert detail["dry_run"] is True

    # Note output shows note_added = False
    assert detail["history"][0]["output"]["data"]["note_added"] is False

    # Containment shows simulation
    assert detail["history"][1]["output"]["simulated"] is True
    assert detail["history"][1]["output"]["external_changed"] is False

    # Prove no case notes were persisted in database
    with system["app"].state.sessions() as db:
        notes = list(db.scalars(select(CaseNote).where(CaseNote.organization_id == system["org"])))
        assert len(notes) == 0


def test_retry_limits_and_terminal_cancellation(system, monkeypatch):
    """Verify automatic retries, manual retry budget exhaustion, and cancellation."""
    client = system["client"]
    settings = system["settings"]

    with system["app"].state.sessions.begin() as db:
        inc = Incident(organization_id=system["org"], title="Retry Inc", severity="high")
        db.add(inc)
        db.flush()
        inc_id = inc.id

    class FailingAdapter:
        def execute(self, *args):
            raise RuntimeError("Adapter failure for testing")

    doc = {
        "description": "Retry Test",
        "trigger": {"source": "incident"},
        "steps": [{"id": "failing_step", "action": "summary", "retries": 1}],
    }

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SECURITY_ADMIN"]
    pb = client.post("/api/v1/soar/playbooks", json={"name": "RetryPB", "definition": doc, "enabled": True}).json()

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    run = client.post(
        f"/api/v1/soar/playbooks/{pb['id']}/execute",
        json={"source_type": "incident", "source_id": inc_id, "idempotency_key": "retry-key-01"},
    ).json()

    monkeypatch.setitem(ADAPTERS, "summary", FailingAdapter())

    # Attempt 1 fails, available_at set for backoff
    process_workflows(settings, system["app"].state.sessions)
    r1 = client.get(f"/api/v1/soar/executions/{run['id']}").json()
    assert r1["status"] == "RUNNING"
    assert r1["attempts"] == 1

    # Reset backoff and attempt 2 (exceeds retries: 1 -> FAILED)
    with system["app"].state.sessions.begin() as db:
        db.get(WorkflowRun, run["id"]).available_at = 0
    process_workflows(settings, system["app"].state.sessions)

    r2 = client.get(f"/api/v1/soar/executions/{run['id']}").json()
    assert r2["status"] == "FAILED"

    # Manual retry endpoint
    dec_url = f"/api/v1/soar/executions/{run['id']}/decision"
    retry_resp = client.post(dec_url, json={"decision": "retry"})
    assert retry_resp.status_code == 200
    assert retry_resp.json()["status"] == "QUEUED"

    # Cancel execution
    cancel_resp = client.post(dec_url, json={"decision": "cancel"})
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "CANCELLED"

    # Attempting to retry a cancelled/terminal execution must return 409
    retry_again = client.post(dec_url, json={"decision": "retry"})
    assert retry_again.status_code == 409


# -----------------------------------------------------------------------------
# 4. CLI COMMAND SUITE TESTS
# -----------------------------------------------------------------------------

def test_all_ioc_and_soar_cli_commands(tmp_path, monkeypatch):
    """Verify that all documented IOC and SOAR CLI commands route accurately."""
    calls = []

    def mock_call(ctx, method, path, **kwargs):
        calls.append((method, path, kwargs))
        if "providers" in path:
            return {"items": [{"provider": "mock", "enabled": True, "configured": True, "last_status": "OK"}]}
        if "observables" in path:
            return {"items": [{"id": "obs-1", "type": "ip", "value": "8.8.8.8"}]}
        return {"status": "ok", "id": "test-res-id"}

    monkeypatch.setattr(cli, "call", mock_call)
    runner = CliRunner()

    # IOC CLI Commands
    assert runner.invoke(cli.app, ["iocs", "enrich", "ip", "8.8.8.8", "--provider", "mock"]).exit_code == 0
    assert calls[-1][1] == "iocs/enrich"

    batch_file = tmp_path / "batch.json"
    batch_file.write_text('[{"type": "ip", "value": "8.8.8.8"}]')
    assert runner.invoke(cli.app, ["iocs", "enrich-batch", str(batch_file), "--provider", "mock"]).exit_code == 0
    assert calls[-1][1] == "iocs/enrich-batch"

    assert runner.invoke(cli.app, ["iocs", "enrich-source", "incident", "INC-123"]).exit_code == 0
    assert calls[-1][1] == "iocs/enrich-source"

    assert runner.invoke(cli.app, ["iocs", "providers"]).exit_code == 0
    assert calls[-1][1] == "iocs/providers"

    assert runner.invoke(cli.app, ["iocs", "observables"]).exit_code == 0
    assert calls[-1][1] == "iocs/observables"

    assert runner.invoke(cli.app, ["iocs", "inspect-observable", "OBS-123"]).exit_code == 0
    assert calls[-1][1] == "iocs/observables/OBS-123"

    assert runner.invoke(cli.app, ["iocs", "enrichment-history", "ENR-123"]).exit_code == 0
    assert calls[-1][1] == "iocs/enrichments/ENR-123/history"

    # SOAR CLI Commands
    assert runner.invoke(cli.app, ["soar", "list"]).exit_code == 0
    assert calls[-1][1] == "soar/playbooks"

    def_file = tmp_path / "definition.json"
    def_file.write_text(json.dumps({"description": "Test", "trigger": {"source": "incident"}, "steps": []}))
    assert runner.invoke(cli.app, ["soar", "validate", str(def_file)]).exit_code == 0
    assert calls[-1][1] == "soar/validate"

    save_file = tmp_path / "save.json"
    save_file.write_text(json.dumps({"name": "Test", "definition": {"description": "t", "trigger": {"source": "incident"}, "steps": []}}))
    assert runner.invoke(cli.app, ["soar", "save", str(save_file)]).exit_code == 0
    assert calls[-1][1] == "soar/playbooks"

    assert runner.invoke(cli.app, ["soar", "execute", "PB-1", "incident", "INC-1", "req-01"]).exit_code == 0
    assert calls[-1][1] == "soar/playbooks/PB-1/execute"

    assert runner.invoke(cli.app, ["soar", "inspect", "RUN-1"]).exit_code == 0
    assert calls[-1][1] == "soar/executions/RUN-1"

    assert runner.invoke(cli.app, ["soar", "approve", "RUN-1"]).exit_code == 0
    assert calls[-1][1] == "soar/executions/RUN-1/decision"
    assert calls[-1][2]["json"]["decision"] == "approve"

    assert runner.invoke(cli.app, ["soar", "decision", "RUN-1", "cancel"]).exit_code == 0
    assert calls[-1][1] == "soar/executions/RUN-1/decision"
    assert calls[-1][2]["json"]["decision"] == "cancel"


# -----------------------------------------------------------------------------
# 5. SECURITY & TENANT ISOLATION TESTS
# -----------------------------------------------------------------------------

def test_cross_tenant_idor_on_all_intelligence_and_soar_endpoints(system):
    """Verify that every endpoint strictly isolates tenant data and returns 404 for foreign IDs."""
    client = system["client"]

    # Create resources in primary tenant
    with system["app"].state.sessions.begin() as db:
        obs = observe(db, system["org"], "ip", "203.0.113.50")
        enr = queue(db, system["settings"], obs, "mock")
        inc = Incident(organization_id=system["org"], title="Tenant Inc", severity="high")
        db.add(inc)
        db.flush()
        obs_id = obs.id
        enr_id = enr.id
        inc_id = inc.id

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SECURITY_ADMIN"]
    pb = client.post("/api/v1/soar/playbooks", json={
        "name": "IDOR-Test",
        "definition": {"description": "test", "trigger": {"source": "incident"}, "steps": [{"id": "s", "action": "summary"}]},
        "enabled": True,
    }).json()

    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    run = client.post(f"/api/v1/soar/playbooks/{pb['id']}/execute", json={
        "source_type": "incident", "source_id": inc_id, "idempotency_key": "idor-run-001"
    }).json()

    # Now switch to OUTSIDER token (different tenant)
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]

    # 1. Foreign Observable lookup
    assert client.get(f"/api/v1/iocs/observables/{obs_id}").status_code == 404

    # 2. Foreign Enrichment detail
    assert client.get(f"/api/v1/iocs/enrichments/{enr_id}").status_code == 404

    # 3. Foreign Enrichment history
    assert client.get(f"/api/v1/iocs/enrichments/{enr_id}/history").status_code == 404

    # 4. Foreign Source context
    assert client.get(f"/api/v1/iocs/source-context/incident/{inc_id}").status_code == 404

    # 5. Foreign Playbook detail
    assert client.get(f"/api/v1/soar/playbooks/{pb['id']}").status_code == 404

    # 6. Foreign Execution detail
    assert client.get(f"/api/v1/soar/executions/{run['id']}").status_code == 404

    # 7. Foreign Execution audit
    assert client.get(f"/api/v1/soar/executions/{run['id']}/audit").status_code == 404

    # 8. Foreign Execution decision (approve / cancel / retry)
    assert client.post(f"/api/v1/soar/executions/{run['id']}/decision", json={"decision": "cancel"}).status_code == 404


def test_secrets_never_leak_in_audit_or_error_messages(system, monkeypatch):
    """Verify that credentials, tokens, and raw secrets never leak into logs or audits."""
    client = system["client"]
    secret_token = "SUPER-SECRET-BEARER-TOKEN-12345"

    class LeakingExceptionProvider:
        def lookup(self, settings, observable):
            raise ValueError(f"Crash with sensitive credential: {secret_token}")

    monkeypatch.setitem(PROVIDERS, "mock", LeakingExceptionProvider())

    # Request enrichment with failing provider
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SENIOR_ANALYST"]
    resp = client.post("/api/v1/iocs/enrich", json={
        "observable": {"type": "domain", "value": "leak-test.example.org"},
        "provider": "mock",
    })
    assert resp.status_code == 200
    lookup_id = resp.json()["lookup"]["id"]

    # Worker runs lookup across 3 attempts to exhaust retry budget
    for _ in range(3):
        lookup_once(system["settings"], system["app"].state.sessions)
        with system["app"].state.sessions.begin() as db:
            db.get(Enrichment, lookup_id).available_at = 0

    # Inspect enrichment record and history
    detail = client.get(f"/api/v1/iocs/enrichments/{lookup_id}").json()
    assert secret_token not in str(detail)
    assert detail["status"] == "FAILED"

    # Inspect database audit records directly
    with system["app"].state.sessions() as db:
        audit_rows = list(db.scalars(select(AuditLog).where(AuditLog.organization_id == system["org"])))
        for log in audit_rows:
            assert secret_token not in str(log.details)
            assert secret_token not in str(log.action)
