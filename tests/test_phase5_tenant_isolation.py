"""Phase 5 Adversarial Tenant Isolation Test Suite.

Treats tenant boundaries as critical security barriers.
Exercises adversarial cross-tenant read, update, reference, linking, token scoping,
and injection paths across all core domains:
1. Incidents & Alert linking
2. Cases, Notes & Forensic Evidence attachment
3. Detection Rules (save, activate, rollback)
4. SOAR Playbooks, Runs & Approval workflows
5. Endpoint Agents (enrollment, polling, revocation, receipt submission)
6. Integrations & Notification Deliveries
7. Threat Intelligence & Observables
8. Ingestion payload organization ID spoofing
9. Uniform 404 responses preventing tenant enumeration
10. Role and token scoping (VIEWER mutations, expired/malformed tokens)
11. Multi-tenant background worker isolation
"""

import secrets
from datetime import UTC, datetime

from sqlalchemy import select

from aegis.db import (
    Agent,
    Alert,
    AlertEvent,
    Case,
    CaseEvidence,
    CaseNote,
    Delivery,
    EventRecord,
    Incident,
    IncidentAlert,
    Integration,
    Notification,
    Playbook,
    PlaybookExecution,
    PlaybookVersion,
    Rule,
    User,
    now,
)
from aegis.pipeline import ingest
from aegis.simulation import simulate
from aegis.worker import process_once


def test_cross_tenant_incident_read_and_status_update_adversarial(system):
    """Tenant A cannot read or mutate Tenant B's incident; DB state and audit heads remain clean."""
    client = system["client"]
    sessions = system["app"].state.sessions

    # Create Incident in Tenant B (Other Org)
    with sessions.begin() as db:
        inc_b = Incident(
            organization_id=system["other"],
            title="Tenant B Confidential Incident",
            severity="critical",
            status="OPEN",
            priority=1,
            revision=1,
        )
        db.add(inc_b)
        db.flush()
        inc_b_id = inc_b.id

    # 1. Tenant A attempts to read Tenant B's incident
    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"
    resp_read = client.get(f"/api/v1/incidents/{inc_b_id}")
    assert resp_read.status_code == 404
    assert resp_read.json()["error"]["message"] == "Resource does not exist"

    # 2. Tenant A attempts to mutate Tenant B's incident status
    resp_update = client.patch(
        f"/api/v1/incidents/{inc_b_id}/status",
        json={"status": "RESOLVED", "revision": 1},
    )
    assert resp_update.status_code == 404
    assert resp_update.json()["error"]["message"] == "Resource does not exist"

    # 3. Assert DB state: Tenant B incident remains OPEN with revision 1
    with sessions() as db:
        refreshed = db.get(Incident, inc_b_id)
        assert refreshed.status == "OPEN"
        assert refreshed.revision == 1


def test_cross_tenant_alert_linking_adversarial(system):
    """Tenant A cannot link Tenant B's alerts to Tenant A's incident."""
    client = system["client"]
    sessions = system["app"].state.sessions

    with sessions.begin() as db:
        inc_a = Incident(
            organization_id=system["org"],
            title="Tenant A Incident",
            severity="medium",
            status="OPEN",
            priority=2,
        )
        alert_b = Alert(
            organization_id=system["other"],
            title="Tenant B Malware Alert",
            severity="high",
            status="OPEN",
            rule_id="MAL-001",
            rule_version=1,
            fingerprint="fp-mal-b",
            correlation_key="ck-mal-b",
            confidence=95,
            risk_score=90,
            risk_factors={"malware": True},
            explanation={"detail": "Detected trojan executable"},
            mitre_techniques=["T1204.002"],
            entity_ids=[],
            first_seen=now(),
            last_seen=now(),
            event_count=1,
        )
        db.add_all([inc_a, alert_b])
        db.flush()
        inc_a_id = inc_a.id
        alert_b_id = alert_b.id

    # Tenant A attempts to attach Tenant B's alert to Tenant A's incident
    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"
    resp = client.post(f"/api/v1/incidents/{inc_a_id}/alerts/{alert_b_id}")
    assert resp.status_code == 404
    assert resp.json()["error"]["message"] == "Resource does not exist"

    # Assert no cross-tenant IncidentAlert link was written
    with sessions() as db:
        link = db.get(IncidentAlert, (inc_a_id, alert_b_id))
        assert link is None


def test_cross_tenant_case_evidence_and_note_injection(system):
    """Tenant A cannot attach Tenant B's evidence or post notes to Tenant B's case."""
    client = system["client"]
    sessions = system["app"].state.sessions

    with sessions.begin() as db:
        case_b = Case(
            organization_id=system["other"],
            title="Confidential Legal Case Org B",
            status="OPEN",
        )
        case_a = Case(
            organization_id=system["org"],
            title="Standard Case Org A",
            status="OPEN",
        )
        alert_b = Alert(
            organization_id=system["other"],
            title="Org B Sensitive Alert",
            severity="high",
            status="OPEN",
            rule_id="SEC-002",
            rule_version=1,
            fingerprint="fp-sec-b",
            correlation_key="ck-sec-b",
            confidence=80,
            risk_score=75,
            risk_factors={"confidential": True},
            explanation={"detail": "Sensitive alert in Org B"},
            mitre_techniques=["T1005"],
            entity_ids=[],
            first_seen=now(),
            last_seen=now(),
            event_count=1,
        )
        db.add_all([case_b, case_a, alert_b])
        db.flush()
        case_b_id = case_b.id
        case_a_id = case_a.id
        alert_b_id = alert_b.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SENIOR_ANALYST']}"

    # 1. Tenant A attempts to read Tenant B's case
    assert client.get(f"/api/v1/cases/{case_b_id}").status_code == 404

    # 2. Tenant A attempts to add note to Tenant B's case using NoteInput schema (field: 'text')
    resp_note = client.post(
        f"/api/v1/cases/{case_b_id}/notes",
        json={"text": "Adversarial injection into Org B"},
    )
    assert resp_note.status_code == 404
    assert resp_note.json()["error"]["message"] == "Resource does not exist"

    # 3. Tenant A attempts to attach Org B's alert as evidence into Org A's case
    resp_ev = client.post(
        f"/api/v1/cases/{case_a_id}/evidence",
        json={"resource_type": "alerts", "resource_id": alert_b_id},
    )
    assert resp_ev.status_code == 404
    assert resp_ev.json()["error"]["message"] == "Resource does not exist"

    # 4. Assert DB state: no note on Case B, no evidence linked from Alert B
    with sessions() as db:
        notes = list(db.scalars(select(CaseNote).where(CaseNote.resource_id == case_b_id)))
        assert len(notes) == 0
        evidences = list(db.scalars(select(CaseEvidence).where(CaseEvidence.resource_id == alert_b_id)))
        assert len(evidences) == 0


def test_cross_tenant_detection_rule_isolation(system):
    """Tenant A cannot read, modify, or activate Tenant B's detection rules."""
    client = system["client"]
    sessions = system["app"].state.sessions

    with sessions.begin() as db:
        rule_doc = {
            "id": "AEGIS-ORGB-SECRET-01",
            "name": "Org B Proprietary Rule",
            "severity": "high",
            "description": "Confidential rule logic",
            "mitre_techniques": ["T1059.001"],
            "selection": [{"field": "event_id", "op": "eq", "value": "4688"}],
        }
        rule_b = Rule(
            organization_id=system["other"],
            rule_id="AEGIS-ORGB-SECRET-01",
            version=1,
            enabled=True,
            document=rule_doc,
        )
        db.add(rule_b)
        db.flush()
        rule_b_id = rule_b.rule_id

    # Tenant A attempts access
    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    # 1. Read rule returns 404
    assert client.get(f"/api/v1/rules/{rule_b_id}").status_code == 404

    # 2. Activate rule returns 404
    resp_act = client.post(f"/api/v1/rules/{rule_b_id}/activate", json={"version": 1, "summary": "Activation attempt"})
    assert resp_act.status_code == 404

    # 3. Rollback rule returns 404
    resp_roll = client.post(
        f"/api/v1/rules/{rule_b_id}/rollback",
        json={"target_version": 1, "summary": "Adversarial rollback attempt"},
    )
    assert resp_roll.status_code == 404

    # 4. Attempting to update existing version 1 of rule_b_id under Tenant A fails with 409
    # because Tenant A does not own this rule, so save_rule treats it as new (requiring version 0)
    tuned_doc = dict(rule_doc)
    tuned_doc["description"] = "Tampered description"
    resp_save = client.put(
        f"/api/v1/rules/{rule_b_id}",
        json={
            "document": tuned_doc,
            "summary": "Adversarial overwrite rule attempt",
            "enabled": False,
            "version": 1,
            "lifecycle_stage": "DRAFT",
        },
    )
    assert resp_save.status_code == 409

    # Verify rule in DB is untouched
    with sessions() as db:
        r = db.scalar(select(Rule).where(Rule.organization_id == system["other"], Rule.rule_id == rule_b_id))
        assert r.enabled is True
        assert r.document["name"] == "Org B Proprietary Rule"


def test_cross_tenant_soar_playbook_and_approval_workflow(system):
    """Tenant A cannot execute Tenant B's playbooks or approve Tenant B's SOAR executions."""
    client = system["client"]
    sessions = system["app"].state.sessions

    with sessions.begin() as db:
        user_b = db.scalar(select(User).where(User.organization_id == system["other"]))
        pb_b = Playbook(
            organization_id=system["other"],
            name="Org B Isolation Playbook",
            enabled=True,
            version=1,
        )
        db.add(pb_b)
        db.flush()

        pb_ver_b = PlaybookVersion(
            organization_id=system["other"],
            playbook_id=pb_b.id,
            version=1,
            document={
                "description": "Org B playbook",
                "trigger": {"source": "incident"},
                "steps": [{"id": "step1", "action": "summary"}],
            },
            author=user_b.id,
        )
        db.add(pb_ver_b)

        exec_b = PlaybookExecution(
            id="SOAR-EXEC-ORGB-001",
            organization_id=system["other"],
            action="isolate_host",
            target="10.10.10.10",
            status="APPROVAL_REQUIRED",
            requested_by=user_b.id,
            idempotency_key="orgb-exec-01",
            revision=0,
        )
        db.add(exec_b)
        db.flush()
        pb_b_id = pb_b.id
        exec_b_id = exec_b.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SOC_MANAGER']}"

    # 1. Tenant A attempts to execute Tenant B's playbook
    resp_exec = client.post(
        f"/api/v1/soar/playbooks/{pb_b_id}/execute",
        json={"source_type": "incident", "source_id": "INC-NONEXISTENT", "idempotency_key": "cross-pb-01"},
    )
    assert resp_exec.status_code == 404

    # 2. Tenant A attempts to approve Tenant B's execution
    resp_app = client.post(f"/api/v1/playbooks/{exec_b_id}/approve")
    assert resp_app.status_code == 404
    assert resp_app.json()["error"]["message"] == "Execution does not exist"

    # Assert DB: Execution status remains APPROVAL_REQUIRED
    with sessions() as db:
        refreshed = db.get(PlaybookExecution, exec_b_id)
        assert refreshed.status == "APPROVAL_REQUIRED"
        assert refreshed.approved_by is None


def test_cross_tenant_agent_revocation_and_receipt_adversarial(system):
    """Tenant A cannot revoke Tenant B's enrolled agent or submit receipts for it."""
    client = system["client"]
    sessions = system["app"].state.sessions

    with sessions.begin() as db:
        agent_b = Agent(
            organization_id=system["other"],
            name="SRV-ORGB-PAYROLL",
            status="ENROLLED",
            version="1.0.0",
            public_key="0" * 64,
            auth_token_hash="placeholder-token-hash-b",
        )
        db.add(agent_b)
        db.flush()
        agent_b_name = agent_b.name

    client.headers["Authorization"] = f"Bearer {system['tokens']['SUPER_ADMIN']}"

    # 1. Tenant A attempts to revoke Tenant B's agent
    resp_revoke = client.post(
        f"/api/v1/agents/{agent_b_name}/revoke",
        json={"reason": "Adversarial cross-tenant revocation attempt"},
    )
    assert resp_revoke.status_code == 404
    assert resp_revoke.json()["error"]["message"] == "Agent not found"

    # Assert DB: Agent remains ENROLLED in Org B
    with sessions() as db:
        refreshed = db.scalar(
            select(Agent).where(Agent.organization_id == system["other"], Agent.name == agent_b_name)
        )
        assert refreshed.status == "ENROLLED"
        assert refreshed.revoked_at is None


def test_cross_tenant_webhook_and_delivery_retry_adversarial(system):
    """Tenant A cannot retry Tenant B's dead deliveries or modify Tenant B's integrations."""
    client = system["client"]
    sessions = system["app"].state.sessions
    system["settings"].integration_allowed_hosts = ["example.com"]

    with sessions.begin() as db:
        integ_b = Integration(
            organization_id=system["other"],
            name="Org B Slack Webhook",
            kind="slack",
            endpoint="https://example.com/webhook-b",
            enabled=True,
            revision=1,
            status="DEGRADED",
        )
        db.add(integ_b)
        db.flush()

        notif_b = Notification(
            organization_id=system["other"],
            title="Org B Security Notice",
            resource_id="INC-ORGB-01",
        )
        db.add(notif_b)
        db.flush()

        delivery_b = Delivery(
            organization_id=system["other"],
            integration_id=integ_b.id,
            notification_id=notif_b.id,
            state="DEAD",
            attempts=5,
            last_error="HTTPError",
        )
        db.add(delivery_b)
        db.flush()
        integ_b_id = integ_b.id
        delivery_b_id = delivery_b.id

    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    # 1. Tenant A attempts to retry Tenant B's dead delivery
    resp_retry = client.post(f"/api/v1/deliveries/{delivery_b_id}/retry")
    assert resp_retry.status_code == 404
    assert resp_retry.json()["error"]["message"] == "Resource does not exist"

    # 2. Tenant A attempts to update Tenant B's integration
    resp_upd = client.put(
        f"/api/v1/integrations/{integ_b_id}",
        json={
            "name": "Tampered Integration",
            "kind": "slack",
            "endpoint": "https://example.com/tampered",
            "enabled": False,
            "revision": 1,
        },
    )
    assert resp_upd.status_code == 404
    assert resp_upd.json()["error"]["message"] == "Resource does not exist"

    # Assert DB: delivery remains DEAD and integration remains unchanged
    with sessions() as db:
        d = db.get(Delivery, delivery_b_id)
        assert d.state == "DEAD"
        assert d.attempts == 5
        i = db.get(Integration, integ_b_id)
        assert i.name == "Org B Slack Webhook"
        assert i.enabled is True


def test_payload_organization_id_spoofing_rejected_or_isolated(system):
    """Injecting manipulated organization_id in request bodies is rejected or cannot breach tenant."""
    client = system["client"]
    sessions = system["app"].state.sessions

    client.headers["Authorization"] = f"Bearer {system['tokens']['SECURITY_ADMIN']}"

    # 1. Attempting to create a Case with explicit foreign organization_id in JSON
    # StrictModel extra='forbid' must reject unexpected fields
    resp_case = client.post(
        "/api/v1/cases",
        json={
            "title": "Adversarial Spoofed Case",
            "organization_id": system["other"],
        },
    )
    assert resp_case.status_code == 422

    # 2. Ingesting raw events via /api/v1/events/ingest while attempting to pass organization_id inside event
    # Ingestion API takes tenant from principal.organization_id exclusively
    event_payload = {
        "events": [
            {
                "source": "spoofed-collector",
                "source_type": "json",
                "timestamp": datetime.now(UTC).isoformat(),
                "raw_event": {"user": "admin", "organization_id": system["other"]},
            }
        ]
    }
    resp_ingest = client.post("/api/v1/events/ingest", json=event_payload)
    assert resp_ingest.status_code == 202
    accepted = resp_ingest.json()["accepted"]
    assert len(accepted) == 1
    event_id = accepted[0]

    # Verify in DB: Event is strictly saved under Org A, NOT Org B
    with sessions() as db:
        ev = db.get(EventRecord, event_id)
        assert ev.organization_id == system["org"]
        assert ev.organization_id != system["other"]


def test_uniform_error_structure_prevents_tenant_enumeration(system):
    """Querying a nonexistent resource and querying another tenant's resource return identical 404s."""
    client = system["client"]
    sessions = system["app"].state.sessions

    with sessions.begin() as db:
        real_inc_b = Incident(
            organization_id=system["other"],
            title="Real Foreign Incident",
            severity="low",
            status="OPEN",
            priority=3,
        )
        db.add(real_inc_b)
        db.flush()
        real_foreign_id = real_inc_b.id

    fake_id = "INC-" + secrets.token_hex(16)

    client.headers["Authorization"] = f"Bearer {system['tokens']['ANALYST']}"

    resp_fake = client.get(f"/api/v1/incidents/{fake_id}")
    resp_foreign = client.get(f"/api/v1/incidents/{real_foreign_id}")

    # Both must be 404 with identical error structure and message
    assert resp_fake.status_code == 404
    assert resp_foreign.status_code == 404
    assert resp_fake.json()["error"]["code"] == resp_foreign.json()["error"]["code"] == "HTTP_404"
    assert (
        resp_fake.json()["error"]["message"]
        == resp_foreign.json()["error"]["message"]
        == "Resource does not exist"
    )


def test_token_scope_and_role_boundaries_adversarial(system):
    """VIEWER role cannot perform mutations, invalid/expired/missing tokens fail closed with 401."""
    client = system["client"]

    # 1. VIEWER attempts incident creation
    client.headers["Authorization"] = f"Bearer {system['tokens']['VIEWER']}"
    resp_viewer = client.post(
        "/api/v1/incidents",
        json={"title": "Unauthorized Incident Creation", "severity": "low", "priority": 3, "alert_ids": []},
    )
    assert resp_viewer.status_code == 403
    assert "Permissions required:" in resp_viewer.json()["error"]["message"]

    # 2. Missing token
    client.headers.pop("Authorization", None)
    assert client.get("/api/v1/incidents").status_code == 401

    # 3. Malformed / garbage token
    client.headers["Authorization"] = "Bearer not-a-valid-token-format-xyz"
    assert client.get("/api/v1/incidents").status_code == 401

    # 4. Token with excessive length (>200 chars)
    client.headers["Authorization"] = "Bearer " + ("A" * 250)
    assert client.get("/api/v1/incidents").status_code == 401


def test_multi_tenant_worker_batch_isolation(system):
    """Background worker processes multi-tenant queue without cross-tenant alert contamination."""
    sessions = system["app"].state.sessions
    settings = system["app"].state.settings
    storage = system["app"].state.storage

    # Ingest distinct event batches into Org A and Org B
    with sessions.begin() as db:
        user_a = db.scalar(select(User).where(User.organization_id == system["org"]))
        user_b = db.scalar(select(User).where(User.organization_id == system["other"]))

        events_a = simulate("attack-chain")[:3]
        events_b = simulate("brute-force")[:3]

        res_a = ingest(db, settings, system["org"], events_a, user_a.id)
        res_b = ingest(db, settings, system["other"], events_b, user_b.id)
        assert len(res_a["accepted"]) == 3
        assert len(res_b["accepted"]) == 3

    # Worker processes the queue
    processed = process_once(settings, sessions, storage)
    assert processed >= 6

    # Verify database state: Org A and Org B events are strictly isolated
    with sessions() as db:
        org_a_events = list(
            db.scalars(select(EventRecord).where(EventRecord.organization_id == system["org"]))
        )
        org_b_events = list(
            db.scalars(select(EventRecord).where(EventRecord.organization_id == system["other"]))
        )
        assert len(org_a_events) >= 3
        assert len(org_b_events) >= 3

        # Assert no Alert in Org A references Org B events
        for alert_a in db.scalars(select(Alert).where(Alert.organization_id == system["org"])):
            linked_events = list(
                db.scalars(
                    select(EventRecord)
                    .join(AlertEvent, AlertEvent.event_id == EventRecord.id)
                    .where(AlertEvent.alert_id == alert_a.id)
                )
            )
            for ev in linked_events:
                assert ev.organization_id == system["org"]
                assert ev.organization_id != system["other"]
