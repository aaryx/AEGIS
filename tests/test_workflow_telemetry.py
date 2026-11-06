"""Automated regression test for the synthetic security operations workflow.

Validates end-to-end pipeline invariants in-process:
- Synthetic RFC 3164 Syslog emission & checkpointed FileCollector spooling.
- Ingestion API normalization, quota gating, and deduplication.
- Rule evaluation: AEGIS-AUTH-001 (brute force) and AEGIS-AUTH-002 (spray).
- Storyline correlation and incident formation.
- Investigation graph retrieval and evidence provenance.
- SOAR containment execution:
  * Self-approval rejection (403)
  * API-key approval rejection (403)
  * Cross-tenant approval rejection (404)
  * Authorized independent human approval (200)
  * Inert simulation verification (simulated=True, external_changed=False)
- HMAC-SHA256 audit log integrity.

For live service qualification against containerized OpenSSH daemon over TCP
network sockets and PostgreSQL, see `scripts/live_workflow_acceptance.py`.
"""

from pathlib import Path

from scripts.workflow_demo import run_demonstration


def test_real_telemetry_workflow_qualification(tmp_path: Path):
    """Run full in-process security operations workflow regression demonstration."""
    db_file = tmp_path / "test_workflow_qual.db"
    out_file = tmp_path / "results.json"
    db_url = f"sqlite:///{db_file}"

    results = run_demonstration(
        database_url=db_url,
        output_path=out_file,
        clean_after=True,
    )

    summary = results["summary"]
    assert summary["qualification_type"] == "SYNTHETIC_WORKFLOW_REGRESSION"
    assert summary["result"] == "PASS"
    assert summary["events_emitted"] == 14
    assert summary["events_ingested"] == 14
    assert summary["events_deduplicated"] == 14
    assert summary["alerts_triggered"] == 2
    assert summary["incidents_created"] >= 1
    assert summary["approval_negative_tests"] == "3/3 PASSED"
    assert summary["containment_mode"] == "INERT_SIMULATION"
    assert summary["audit_integrity"] == "VERIFIED_VALID"

    phases = results["phases"]
    assert phases["collection"]["spool_status"] == {"PENDING": 14}
    assert phases["collection"]["recollect_idempotent_count"] == 0
    assert phases["ingestion"]["deduplication_verified"] is True
    assert "AEGIS-AUTH-001" in phases["detection"]["rule_ids_triggered"]
    assert phases["soar_response"]["self_approval_rejected"] is True
    assert phases["soar_response"]["apikey_approval_rejected"] is True
    assert phases["soar_response"]["cross_tenant_rejected"] is True
    assert phases["soar_response"]["independent_approval_succeeded"] is True
    assert phases["soar_response"]["final_status"] == "SUCCEEDED"
    assert phases["soar_response"]["containment_simulated"] is True
    assert phases["audit"]["audit_chain_valid"] is True
