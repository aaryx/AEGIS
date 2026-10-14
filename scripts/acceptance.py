"""Validate the running Compose stack through its real API and CLI, without printing credentials."""

import json
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]


def main():
    config = dotenv_values(ROOT / ".env")
    with httpx.Client(base_url="http://localhost:8000/api/v1/", timeout=30) as client:
        # 1. Smoke Check: Unauthenticated access and invalid credentials must be strictly rejected
        unauth_response = client.get("rules")
        if unauth_response.status_code != 401:
            raise RuntimeError(f"Expected 401 for unauthenticated request, got {unauth_response.status_code}")

        invalid_token_res = client.get("incidents", headers={"Authorization": "Bearer invalid_tampered_token_xyz"})
        if invalid_token_res.status_code != 401:
            raise RuntimeError(f"Expected 401 for invalid token, got {invalid_token_res.status_code}")

        # 2. Smoke Check: System Liveness and Readiness
        liveness = client.get("system/liveness")
        liveness.raise_for_status()
        if liveness.json().get("status") != "HEALTHY":
            raise RuntimeError(f"Liveness check failed: {liveness.text}")

        readiness = client.get("system/readiness")
        readiness.raise_for_status()
        if readiness.json().get("status") != "READY":
            raise RuntimeError(f"Readiness check failed: {readiness.text}")

        # 3. Authenticate with bootstrap credentials
        response = client.post(
            "auth/login",
            json={"username": config["BOOTSTRAP_USERNAME"], "password": config["BOOTSTRAP_PASSWORD"]},
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        client.headers["Authorization"] = "Bearer " + token
        env = os.environ | {"AEGIS_TOKEN": token, "AEGIS_URL": "http://localhost:8000"}

        # Smoke Check: Cross-Tenant Isolation
        foreign_id = str(uuid4())
        cross_tenant_res = client.get(f"investigations/{foreign_id}")
        if cross_tenant_res.status_code != 404:
            raise RuntimeError(
                f"Expected 404 for cross-tenant/unauthorized investigation, got {cross_tenant_res.status_code}"
            )

        # 4. Smoke Check: Detection Rules and MITRE Coverage
        rules_response = client.get("rules")
        rules_response.raise_for_status()
        rules_list = rules_response.json()
        if not any(r.get("rule_id") in ("AUTH-001", "AEGIS-AUTH-001") for r in rules_list):
            raise RuntimeError("Baseline detection rule AUTH-001 missing from rules list")

        coverage_response = client.get("coverage/mitre")
        coverage_response.raise_for_status()
        cov_data = coverage_response.json()
        if cov_data.get("covered_techniques", 0) <= 0:
            raise RuntimeError("MITRE coverage calculation returned 0 covered techniques")

        # 5. Smoke Check: Replay Execution, Persistence, and Sandbox Isolation
        alerts_before = len(client.get("alerts").json().get("items", []))
        replay_response = client.post(
            "rules/AUTH-001/replay",
            json={"target_type": "DATASET", "dataset_name": "AUTH-001", "max_events": 100, "dry_run": True},
        )
        replay_response.raise_for_status()
        replay_data = replay_response.json()
        job_id = replay_data["job_id"]
        if replay_data["status"] not in ("COMPLETED", "COMPLETED_WITH_WARNINGS"):
            raise RuntimeError(f"Replay job failed to complete: {replay_data['status']}")
        if replay_data["events_evaluated"] <= 0:
            raise RuntimeError("Replay job evaluated 0 events")

        job_get = client.get(f"replays/{job_id}")
        job_get.raise_for_status()
        if job_get.json()["id"] != job_id:
            raise RuntimeError("Replay persistence retrieval returned mismatched job ID")

        alerts_after = len(client.get("alerts").json().get("items", []))
        if alerts_after != alerts_before:
            raise RuntimeError(
                f"Replay violated sandbox isolation: alerts count changed from {alerts_before} to {alerts_after}"
            )

        # 6. Attack Chain Simulation and Investigation
        host = "ACCEPTANCE-" + uuid4().hex
        source_ip = "198.18." + str(int(uuid4().hex[:2], 16)) + "." + str(int(uuid4().hex[:2], 16))
        for args in (["status"], ["simulate", "attack-chain", "--host", host, "--source-ip", source_ip]):
            subprocess.run([sys.executable, "-m", "aegis.cli", *args], cwd=ROOT, env=env, check=True)  # noqa: S603  # nosec B603
        evidence = None
        incident = None
        for _ in range(60):
            incidents = client.get("incidents").json()["items"]
            for candidate in incidents:
                result = client.get(f"investigations/{candidate['id']}")
                result.raise_for_status()
                if any(item["event"].get("host") == host for item in result.json()["evidence"]):
                    evidence, incident = result.json(), candidate
                    break
            if evidence:
                break
            time.sleep(2)
        else:
            raise RuntimeError("Attack-chain incident was not generated")
        assert incident is not None
        if not evidence or len(evidence["evidence"]) != 16 or not evidence["iocs"] or not evidence["entities"]:
            raise RuntimeError("Investigation evidence is incomplete")
        for _ in range(10):
            search = client.post(
                "events/search",
                json={"filters": [{"field": "host", "value": host}, {"field": "outcome", "value": "failure"}], "aggregate": "source_ip"},
            )
            search.raise_for_status()
            if search.json()["total"] >= 12:
                break
            time.sleep(2)
        else:
            raise RuntimeError("OpenSearch projection is incomplete")
        report = client.post(f"reports/{incident['id']}")
        report.raise_for_status()
        if not client.get("audit/verify").json()["valid"]:
            raise RuntimeError("Audit chain verification failed")
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "smoke_checks": {
                        "unauth_rejection": "PASS",
                        "invalid_token_rejection": "PASS",
                        "tenant_isolation": "PASS",
                        "system_readiness": "PASS",
                        "detection_rules": len(rules_list),
                        "mitre_covered_techniques": cov_data.get("covered_techniques"),
                        "replay_persistence": "PASS",
                        "replay_sandbox_isolation": "PASS",
                    },
                    "evidence_events": len(evidence["evidence"]),
                    "search_matches": search.json()["total"],
                    "incident_id": incident["id"],
                    "report_id": report.json()["id"],
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
