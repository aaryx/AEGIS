"""AEGIS TITAN Phase 6: Soak Test Multi-Process Harness Regression.

Validates that the multi-worker soak harness initializes multiple tenants,
spawns 4 independent worker processes, admits synthetic events, processes
queue depth to zero, and validates post-run HMAC audit-chain integrity.
"""

from scripts.soak_test import run_soak_test


def test_soak_test_harness_smoke_run(tmp_path):
    """Executes a fast smoke run of the multi-process soak test harness."""
    db_file = tmp_path / "soak_smoke.db"
    out_file = tmp_path / "soak_smoke_out.json"

    report = run_soak_test(
        workers=4,
        duration=5.0,
        rate=30.0,
        tenant_count=2,
        seed=123,
        db_url=f"sqlite:///{db_file}",
        output_path=out_file,
        checkpoint_interval=2.0,
    )

    assert report["status"] == "PASSED"
    assert report["integrity"]["reconciliation_passed"] is True
    assert report["integrity"]["cross_tenant_violations"] == 0
    assert report["integrity"]["audit_chains_valid"] is True
    assert report["metrics"]["final_processed"] > 0
    assert report["metrics"]["final_pending"] == 0
    assert out_file.exists()
