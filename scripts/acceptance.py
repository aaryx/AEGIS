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
        response = client.post(
            "auth/login",
            json={"username": config["BOOTSTRAP_USERNAME"], "password": config["BOOTSTRAP_PASSWORD"]},
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        client.headers["Authorization"] = "Bearer " + token
        env = os.environ | {"AEGIS_TOKEN": token, "AEGIS_URL": "http://localhost:8000"}
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
