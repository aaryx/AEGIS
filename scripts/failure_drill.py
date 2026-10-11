"""Temporarily stop local search, prove detection continues, then verify outbox recovery."""

import shutil
import subprocess  # nosec B404
import time
from pathlib import Path
from uuid import uuid4

import httpx
from dotenv import dotenv_values


def docker(*args):
    subprocess.run([shutil.which("docker"), "compose", *args], check=True)  # noqa: S603  # nosec B603


def main():
    config = dotenv_values(Path(__file__).resolve().parents[1] / ".env")
    source = "outage-drill-" + uuid4().hex
    with httpx.Client(base_url="http://localhost:8000/api/v1/", timeout=30) as client:
        login = client.post(
            "auth/login",
            json={"username": config["BOOTSTRAP_USERNAME"], "password": config["BOOTSTRAP_PASSWORD"]},
        )
        login.raise_for_status()
        client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
        docker("stop", "opensearch")
        try:
            result = client.post(
                "events/ingest",
                json={
                    "events": [
                        {
                            "source": source,
                            "raw_event": {
                                "host": source,
                                "event_category": "privilege",
                                "action": "sudo",
                                "message": "Synthetic offline-search detection drill",
                            },
                        }
                    ]
                },
            )
            result.raise_for_status()
            event_id = result.json()["accepted"][0]
            for _ in range(30):
                event = client.get("events/" + event_id).json()
                if event["state"] == "PROCESSED":
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Detection stalled while search was down")
            from aegis.parsers import digest

            expected = digest(event["event"]["raw_event"])
            if event["evidence_hash"] != expected:
                raise RuntimeError("Evidence changed during search outage")
        finally:
            docker("start", "opensearch")
        for _ in range(60):
            response = client.post("events/search", json={"filters": [{"field": "source", "value": source}]})
            if response.status_code == 200 and response.json()["total"] == 1:
                print("PASS: detection committed during search outage; durable outbox recovered the event")
                return
            time.sleep(3)
        raise RuntimeError("Search projection did not recover within 180 seconds")


if __name__ == "__main__":
    main()
