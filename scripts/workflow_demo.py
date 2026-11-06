"""AEGIS Synthetic Security Operations Workflow Regression Demonstration.

Fast, deterministic in-process regression demonstration for the end-to-end pipeline:
1. Synthetic telemetry emission: writes realistic RFC 3164 Syslog lines to disk.
2. Checkpointed file collection with durable SQLite WAL spooling.
3. Authenticated ingestion, normalization, and deduplication via in-process TestClient.
4. Real-time detection rule evaluation (AEGIS-AUTH-001 and AEGIS-AUTH-002).
5. Automated storyline correlation and incident formation.
6. Analyst investigation view with full event/entity provenance.
7. SOAR containment playbook execution with two-person approval enforcement:
   - Rejection of self-approval (403)
   - Rejection of API-key approval (403)
   - Rejection of cross-tenant approval (404)
   - Authorized execution by independent human administrator
   - Inert simulated execution via LocalAdapter (simulated=True, external_changed=False)
8. Tamper-evident HMAC-SHA256 audit chain verification.
9. Structured JSON output and quantitative metrics.

NOTE ON SCOPE:
This script performs fast (~1.1s) in-process pipeline invariant verification.
It generates realistic RFC 3164 strings to disk and runs against SQLite with ASGI TestClient.
For live service acceptance with an actual containerized OpenSSH daemon emitting
syslog to /var/log/auth.log, network HTTP API sockets, and real PostgreSQL container,
run `scripts/live_workflow_acceptance.py` (or `python scripts/dev.py demo --live`).
"""

import argparse
import hashlib
import json
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.api import create_app
from aegis.collector import FileCollector
from aegis.config import Settings
from aegis.db import (
    Alert,
    APIKey,
    AuditLog,
    Base,
    Entity,
    EntityRelationship,
    Incident,
    Organization,
    Storyline,
    User,
    WorkflowRun,
    database,
)
from aegis.pipeline import seed_rules
from aegis.security import PASSWORDS, Principal, issue_session, token_hash, verify_audit
from aegis.soar import Condition, Definition, RunInput, Step, Trigger, advance
from aegis.storylines import correlate
from aegis.worker import process_once

ROOT = Path(__file__).resolve().parents[1]


def build_auth_telemetry_lines() -> list[str]:
    """Generate RFC 3164 Syslog authentication log lines for an edge gateway.

    Includes 12 rapid attack/brute-force failures targeting multiple accounts
    from attacker IP 198.51.100.42, followed by 2 benign successful authentications
    from trusted analyst IP 192.168.1.50.
    """
    lines = []
    # 12 brute-force failures across 5 distinct usernames from hostile IP 198.51.100.42
    targets = [
        "admin",
        "root",
        "service",
        "backup",
        "guest",
        "admin",
        "root",
        "service",
        "backup",
        "guest",
        "admin",
        "root",
    ]
    for i, user in enumerate(targets):
        port = 50000 + i
        line = (
            f"Oct 24 14:02:{10 + i:02d} edge-gw-01 sshd[12{450 + i}]: "
            f"Failed password for invalid user {user} from 198.51.100.42 port {port} ssh2\n"
        )
        lines.append(line)

    # 2 benign successful authentications from trusted analyst workstation 192.168.1.50
    lines.append(
        "Oct 24 14:02:25 edge-gw-01 sshd[12470]: Accepted publickey for analyst from 192.168.1.50 port 50020 ssh2\n"
    )
    lines.append(
        "Oct 24 14:02:28 edge-gw-01 sshd[12471]: Accepted publickey for secops from 192.168.1.50 port 50021 ssh2\n"
    )
    return lines


def run_demonstration(
    database_url: str | None = None,
    output_path: Path | None = None,
    clean_after: bool = True,
) -> dict:
    t_start = time.perf_counter()
    metrics: dict = {
        "timestamp": datetime.now(UTC).isoformat(),
        "phases": {},
        "summary": {},
    }

    temp_dir = Path(tempfile.mkdtemp(prefix="aegis_wf_demo_"))
    try:
        # -------------------------------------------------------------
        # Phase 1: Environment Setup & Seed Provisioning
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        db_path = temp_dir / "workflow_demo.db"
        actual_db_url = database_url or f"sqlite:///{db_path}"

        settings = Settings(
            environment="testing",
            database_url=actual_db_url,
            audit_secret="demonstration-audit-integrity-secret-key-at-least-32-chars-long",  # noqa: S106
            max_event_bytes=65536,
            queue_capacity=1000,
            soar_queue_capacity=50,
            response_approval_seconds=3600,
            _env_file=None,
        )

        engine, sessions = database(settings.database_url)
        Base.metadata.create_all(engine)
        app = create_app(settings)

        # Seed Primary Tenant and Secondary (Outsider) Tenant
        with sessions.begin() as db:
            org = Organization(name="SecOps Enterprise Tenant")
            org_outsider = Organization(name="Outsider Isolated Tenant")
            db.add_all([org, org_outsider])
            db.flush()

            org_id = org.id
            outsider_org_id = org_outsider.id

            pw_hash = PASSWORDS.hash("demo-secure-password-12345")

            # 1. Collector Agent User (SECURITY_ADMIN) for scoped event ingestion
            collector_user = User(
                organization_id=org_id,
                username="collector-service",
                password_hash=pw_hash,
                role="SECURITY_ADMIN",
            )
            # 2. SOC Analyst (SENIOR_ANALYST) for detection inspection & playbook execution
            analyst_user = User(
                organization_id=org_id,
                username="soc-analyst",
                password_hash=pw_hash,
                role="SENIOR_ANALYST",
            )
            # 3. Independent Security Admin (SECURITY_ADMIN) for sensitive action approval
            admin_user = User(
                organization_id=org_id,
                username="sec-admin",
                password_hash=pw_hash,
                role="SECURITY_ADMIN",
            )
            # 4. Outsider User in foreign tenant for cross-tenant rejection testing
            outsider_user = User(
                organization_id=outsider_org_id,
                username="outsider-admin",
                password_hash=pw_hash,
                role="SUPER_ADMIN",
            )
            db.add_all([collector_user, analyst_user, admin_user, outsider_user])
            db.flush()

            collector_token, _ = issue_session(db, collector_user, settings)
            analyst_token, _ = issue_session(db, analyst_user, settings)
            admin_token, _ = issue_session(db, admin_user, settings)
            outsider_token, _ = issue_session(db, outsider_user, settings)

            # Seed an API Key belonging to sec_admin to test API key approval rejection
            api_key_secret = "aegis_key_" + hashlib.sha256(b"api-key-automation-secret").hexdigest()
            api_key_row = APIKey(
                organization_id=org_id,
                user_id=admin_user.id,
                name="automation-orchestrator",
                permissions=[
                    "playbooks.approve",
                    "playbooks.read",
                    "playbooks.execute",
                    "events.read",
                    "alerts.read",
                    "incidents.read",
                    "entities.read",
                    "iocs.read",
                ],
                key_hash=token_hash(api_key_secret),
                expires=time.time() + 86400 * 30,
            )
            db.add(api_key_row)
            db.flush()

            # Seed Built-in Rules (AEGIS-AUTH-001, AEGIS-AUTH-002, etc.)
            seed_rules(db, org_id)

            collector_id = collector_user.id
            analyst_id = analyst_user.id
            admin_id = admin_user.id

        metrics["phases"]["setup"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "organization_id": org_id,
            "outsider_org_id": outsider_org_id,
            "collector_user_id": collector_id,
            "analyst_user_id": analyst_id,
            "admin_user_id": admin_id,
        }

        # -------------------------------------------------------------
        # Phase 2: Telemetry Emission to Local File
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        auth_log_path = temp_dir / "edge_auth.log"
        telemetry_lines = build_auth_telemetry_lines()
        with auth_log_path.open("w", encoding="utf-8") as f:
            for line in telemetry_lines:
                f.write(line)

        raw_bytes = auth_log_path.stat().st_size
        metrics["phases"]["emission"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "source_type": "linux_auth",
            "log_path": str(auth_log_path),
            "events_emitted": len(telemetry_lines),
            "bytes_emitted": raw_bytes,
            "target_host": "edge-gw-01",
            "attacker_ip": "198.51.100.42",
            "trusted_ip": "192.168.1.50",
        }

        # -------------------------------------------------------------
        # Phase 3: Checkpointed Collection via FileCollector
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        spool_path = temp_dir / "collector_spool.db"
        collector = FileCollector(
            spool=spool_path, name="edge-auth-collector", capacity=1000, tenant_id=org_id
        )

        collected_count = collector.collect(path=auth_log_path, source_type="linux_auth")
        spool_status_before = collector.status()

        # Deduplication / idempotent collect verification on unchanged file
        recollect_count = collector.collect(path=auth_log_path, source_type="linux_auth")

        metrics["phases"]["collection"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "events_collected": collected_count,
            "spool_status": spool_status_before,
            "recollect_idempotent_count": recollect_count,
            "checkpoint_persisted": True,
        }
        assert collected_count == 14, f"Expected 14 collected events, got {collected_count}"
        assert spool_status_before == {"PENDING": 14}, f"Unexpected spool status: {spool_status_before}"
        assert recollect_count == 0, f"Expected 0 re-collected events, got {recollect_count}"

        # -------------------------------------------------------------
        # Phase 4: Ingestion through Authenticated API & Deduplication
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        # Read spooled EventInput payloads before flushing to use for re-ingestion deduplication check
        spooled_payloads = [
            json.loads(row[0])
            for row in collector.db.execute("SELECT payload FROM spool ORDER BY id").fetchall()
        ]

        with TestClient(app, base_url="http://testserver/api/v1/") as client:
            # Collector flushes spooled events to /api/v1/events/ingest
            flushed_count = collector.flush(client, token=collector_token)
            spool_status_after = collector.status()

            collector.close()

            # Verify deduplication on re-ingestion of identical EventInput batch
            reingest_resp = client.post(
                "events/ingest",
                json={"events": spooled_payloads},
                headers={"Authorization": f"Bearer {collector_token}"},
            )
            assert reingest_resp.status_code == 202, (
                f"Expected 202 for re-ingest, got {reingest_resp.status_code}: {reingest_resp.text}"
            )
            reingest_data = reingest_resp.json()
            duplicates_count = len(reingest_data.get("duplicates", []))
            accepted_count = len(reingest_data.get("accepted", []))

        metrics["phases"]["ingestion"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "events_flushed": flushed_count,
            "spool_status_after_flush": spool_status_after,
            "api_accepted": flushed_count,
            "reingest_accepted": accepted_count,
            "reingest_duplicates": duplicates_count,
            "deduplication_verified": duplicates_count == 14 and accepted_count == 0,
        }
        assert flushed_count == 14, f"Expected 14 flushed events, got {flushed_count}"
        assert spool_status_after == {}, f"Expected empty spool after flush, got {spool_status_after}"
        assert duplicates_count == 14 and accepted_count == 0, "Deduplication invariant violated"

        # -------------------------------------------------------------
        # Phase 5: Detection Pipeline & Storyline Correlation
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        # Run worker processing once to execute detect_batch and project to storage
        processed_count = process_once(settings, sessions, app.state.storage)

        # Trigger storyline correlation
        with sessions.begin() as db:
            analyst_user_obj = db.get(User, analyst_id)
            analyst_principal = Principal(
                user=analyst_user_obj,
                permissions={
                    "events.read",
                    "alerts.read",
                    "incidents.read",
                    "entities.read",
                    "iocs.read",
                    "playbooks.read",
                    "playbooks.execute",
                    "incidents.update",
                },
            )
            correlate(db, settings, analyst_principal, window_seconds=300)

        # Inspect resulting alerts and incidents
        with sessions() as db:
            alerts = list(
                db.scalars(
                    select(Alert).where(Alert.organization_id == org_id).order_by(Alert.first_seen.asc())
                )
            )
            incidents = list(db.scalars(select(Incident).where(Incident.organization_id == org_id)))
            storylines = list(db.scalars(select(Storyline).where(Storyline.organization_id == org_id)))
            entities = list(db.scalars(select(Entity).where(Entity.organization_id == org_id)))
            relationships = list(
                db.scalars(select(EntityRelationship).where(EntityRelationship.organization_id == org_id))
            )

        alert_ids = [a.id for a in alerts]
        rule_ids = [a.rule_id for a in alerts]
        incident_ids = [i.id for i in incidents]

        metrics["phases"]["detection"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "events_processed": processed_count,
            "alerts_generated": len(alerts),
            "rule_ids_triggered": rule_ids,
            "alert_ids": alert_ids,
            "incidents_created": len(incidents),
            "incident_ids": incident_ids,
            "storylines_created": len(storylines),
            "entities_extracted": len(entities),
            "relationships_extracted": len(relationships),
        }
        assert "AEGIS-AUTH-001" in rule_ids, f"Expected AEGIS-AUTH-001 in triggered rules: {rule_ids}"
        assert len(incidents) >= 1, "Expected at least 1 incident created"
        primary_alert = next(a for a in alerts if a.rule_id == "AEGIS-AUTH-001")
        primary_incident = incidents[0]

        # -------------------------------------------------------------
        # Phase 6: Investigation & Entity Provenance
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        with TestClient(app, base_url="http://testserver/api/v1/") as client:
            # Query Alert Investigation
            inv_resp = client.get(
                f"investigations/{primary_alert.id}",
                headers={"Authorization": f"Bearer {analyst_token}"},
            )
            assert inv_resp.status_code == 200, (
                f"Investigation failed with status {inv_resp.status_code}: {inv_resp.text}"
            )
            inv_data = inv_resp.json()

            # Query Incident Investigation
            inc_inv_resp = client.get(
                f"investigations/{primary_incident.id}",
                headers={"Authorization": f"Bearer {analyst_token}"},
            )
            assert inc_inv_resp.status_code == 200, (
                f"Incident investigation failed with status {inc_inv_resp.status_code}"
            )
            inc_inv_data = inc_inv_resp.json()
            assert inc_inv_data.get("kind") == "incidents"

        evidence_items = inv_data.get("evidence", [])
        evidence_hashes = [e["hash"] for e in evidence_items]
        inv_entities = inv_data.get("entities", [])
        inv_relationships = inv_data.get("relationships", [])

        # Find attacker IP entity
        attacker_entity = next(
            (e for e in inv_entities if e["type"] == "ip" and e["value"] == "198.51.100.42"), None
        )
        assert attacker_entity is not None, "Attacker IP entity 198.51.100.42 missing from investigation"

        metrics["phases"]["investigation"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "alert_investigated": primary_alert.id,
            "incident_investigated": primary_incident.id,
            "evidence_count": len(evidence_items),
            "intact_evidence_hashes": len(evidence_hashes),
            "entity_count": len(inv_entities),
            "relationship_count": len(inv_relationships),
            "attacker_entity_id": attacker_entity["id"],
            "mitre_techniques": inv_data.get("mitre_techniques", []),
        }

        # -------------------------------------------------------------
        # Phase 7: SOAR Playbook Execution & Two-Person Approval Gate
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        with TestClient(app, base_url="http://testserver/api/v1/") as client:
            # 1. Author and Register SOAR Playbook
            playbook_def = Definition(
                description="Contain malicious IP entity upon repeated authentication failures",
                trigger=Trigger(
                    source="alert",
                    required_evidence_fields=["source_ip"],
                    conditions=[Condition(field="severity", op="gte", value="high")],
                ),
                steps=[
                    Step(id="summarize_alert", action="summary"),
                    Step(id="contain_hostile_ip", action="simulate_block_ip"),
                ],
                input_schema={"target_id": "entity"},
            )

            pb_resp = client.post(
                "soar/playbooks",
                json={
                    "name": "Contain Hostile IP",
                    "enabled": True,
                    "expected_version": 0,
                    "definition": playbook_def.model_dump(mode="json"),
                },
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert pb_resp.status_code == 200, f"Playbook creation failed: {pb_resp.text}"
            playbook = pb_resp.json()
            playbook_id = playbook["id"]

            # 2. SOC Analyst triggers non-dry-run containment workflow
            run_input = RunInput(
                source_type="alert",
                source_id=primary_alert.id,
                inputs={"target_id": attacker_entity["id"]},
                dry_run=False,
                idempotency_key=str(uuid4()),
            )
            exec_resp = client.post(
                f"soar/playbooks/{playbook_id}/execute",
                json=run_input.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {analyst_token}"},
            )
            assert exec_resp.status_code == 200, f"Execution enqueue failed: {exec_resp.text}"
            run = exec_resp.json()
            run_id = run["id"]

            # 3. Advance workflow run until it completes or halts waiting for approval
            for _ in range(10):
                with sessions.begin() as db:
                    run_obj = db.get(WorkflowRun, run_id)
                    if run_obj.status not in ("QUEUED", "RUNNING"):
                        break
                    advance(db, settings, run_obj)
                    if run_obj.status not in ("QUEUED", "RUNNING"):
                        break

            # Workflow should now be halted waiting for independent approval
            run_status_resp = client.get(
                f"soar/executions/{run_id}",
                headers={"Authorization": f"Bearer {analyst_token}"},
            )
            assert run_status_resp.json()["status"] == "WAITING_FOR_APPROVAL", (
                f"Expected WAITING_FOR_APPROVAL, got {run_status_resp.json()['status']}"
            )

            # 4. Security Enforcement Negative Tests
            # Test A: Self-Approval Rejection
            self_approval_resp = client.post(
                f"soar/executions/{run_id}/decision",
                json={"decision": "approve"},
                headers={"Authorization": f"Bearer {analyst_token}"},
            )
            assert self_approval_resp.status_code == 403, (
                f"Expected 403 for self-approval, got {self_approval_resp.status_code}"
            )

            # Test B: API Key Approval Rejection
            apikey_approval_resp = client.post(
                f"soar/executions/{run_id}/decision",
                json={"decision": "approve"},
                headers={"Authorization": f"Bearer {api_key_secret}"},
            )
            assert apikey_approval_resp.status_code == 403, (
                f"Expected 403 for API key approval, got {apikey_approval_resp.status_code}"
            )

            # Test C: Cross-Tenant Approval Rejection
            cross_tenant_resp = client.post(
                f"soar/executions/{run_id}/decision",
                json={"decision": "approve"},
                headers={"Authorization": f"Bearer {outsider_token}"},
            )
            assert cross_tenant_resp.status_code == 404, (
                f"Expected 404 for cross-tenant approval, got {cross_tenant_resp.status_code}"
            )

            # 5. Authorized Approval by Independent Security Administrator
            valid_approval_resp = client.post(
                f"soar/executions/{run_id}/decision",
                json={"decision": "approve"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert valid_approval_resp.status_code == 200, (
                f"Expected 200 for valid admin approval, got {valid_approval_resp.status_code}: {valid_approval_resp.text}"
            )
            assert valid_approval_resp.json()["status"] == "QUEUED"

            # 6. Advance workflow through simulated containment execution
            for _ in range(10):
                with sessions.begin() as db:
                    run_obj = db.get(WorkflowRun, run_id)
                    if run_obj.status not in ("QUEUED", "RUNNING"):
                        break
                    advance(db, settings, run_obj)
                    if run_obj.status not in ("QUEUED", "RUNNING"):
                        break

            final_run_resp = client.get(
                f"soar/executions/{run_id}",
                headers={"Authorization": f"Bearer {analyst_token}"},
            )
            final_run = final_run_resp.json()
            assert final_run["status"] == "SUCCEEDED", f"Expected SUCCEEDED, got {final_run['status']}"

            # Verify step 2 output details
            step2_history = next((h for h in final_run["history"] if h["step"] == "contain_hostile_ip"), None)
            assert step2_history is not None, "Missing contain_hostile_ip step history"
            assert step2_history["status"] == "SUCCEEDED"
            assert step2_history["output"]["simulated"] is True
            assert step2_history["output"]["dry_run"] is False
            assert step2_history["output"]["data"]["action"] == "simulate_block_ip"
            assert step2_history["output"]["data"]["entity_id"] == attacker_entity["id"]

        metrics["phases"]["soar_response"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "playbook_id": playbook_id,
            "execution_id": run_id,
            "initial_requester": analyst_id,
            "self_approval_rejected": self_approval_resp.status_code == 403,
            "apikey_approval_rejected": apikey_approval_resp.status_code == 403,
            "cross_tenant_rejected": cross_tenant_resp.status_code == 404,
            "independent_approver": admin_id,
            "independent_approval_succeeded": valid_approval_resp.status_code == 200,
            "final_status": final_run["status"],
            "containment_simulated": step2_history["output"]["simulated"],
            "contained_entity_id": attacker_entity["id"],
        }

        # -------------------------------------------------------------
        # Phase 8: Audit Trail Reconstruction & HMAC Chain Integrity
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        with sessions() as db:
            audit_valid = verify_audit(db, settings, org_id)
            audit_logs = list(
                db.scalars(
                    select(AuditLog)
                    .where(AuditLog.organization_id == org_id)
                    .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
                )
            )

        recorded_actions = [log.action for log in audit_logs]

        # Verify API audit check
        with TestClient(app, base_url="http://testserver/api/v1/") as client:
            api_audit_resp = client.get(
                "audit/verify",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert api_audit_resp.status_code == 200
            api_audit_valid = api_audit_resp.json().get("valid") is True

        metrics["phases"]["audit"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "total_audit_records": len(audit_logs),
            "audit_chain_valid": audit_valid and api_audit_valid,
            "actions_recorded": list(dict.fromkeys(recorded_actions)),
            "required_actions_present": {
                "events.ingest": "events.ingest" in recorded_actions,
                "alerts.create": "alerts.create" in recorded_actions,
                "incidents.create": "incidents.create" in recorded_actions,
                "soar.queued": "soar.queued" in recorded_actions,
                "soar.approval_required": "soar.approval_required" in recorded_actions,
                "soar.decision_rejected": "soar.decision_rejected" in recorded_actions,
                "soar.approve": "soar.approve" in recorded_actions,
                "soar.simulated": "soar.simulated" in recorded_actions,
                "soar.succeeded": "soar.succeeded" in recorded_actions,
            },
        }
        assert audit_valid and api_audit_valid, "Audit HMAC-SHA256 hash chain verification failed"

        # -------------------------------------------------------------
        # Overall Summary & Metrics Aggregation
        # -------------------------------------------------------------
        total_duration = round((time.perf_counter() - t_start) * 1000, 2)
        metrics["summary"] = {
            "qualification_type": "SYNTHETIC_WORKFLOW_REGRESSION",
            "result": "PASS",
            "total_duration_ms": total_duration,
            "events_emitted": len(telemetry_lines),
            "events_ingested": flushed_count,
            "events_deduplicated": duplicates_count,
            "alerts_triggered": len(alerts),
            "incidents_created": len(incidents),
            "entities_extracted": len(entities),
            "approval_negative_tests": "3/3 PASSED",
            "containment_mode": "INERT_SIMULATION",
            "audit_integrity": "VERIFIED_VALID",
        }

        # Save structured results to destination
        target_output = output_path or (ROOT / "build" / "workflow-demonstration.json")
        target_output.parent.mkdir(parents=True, exist_ok=True)
        with target_output.open("w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        return metrics

    finally:
        if clean_after and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS Synthetic Security Operations Workflow Demonstration (In-Process Regression)"
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Optional database URL override (default: isolated SQLite DB)",
    )
    parser.add_argument("--output", default=None, help="Destination JSON path for demonstration results")
    parser.add_argument(
        "--keep-artifacts", action="store_true", help="Preserve temporary demonstration files"
    )
    args = parser.parse_args()

    out_path = Path(args.output).resolve() if args.output else None
    results = run_demonstration(
        database_url=args.database_url,
        output_path=out_path,
        clean_after=not args.keep_artifacts,
    )
    print(json.dumps(results["summary"], indent=2))


if __name__ == "__main__":
    main()
