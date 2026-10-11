from datetime import UTC, datetime, timedelta

from aegis.schemas import EventInput


def simulate(scenario="attack-chain", start=None):
    start = start or datetime.now(UTC) - timedelta(minutes=4)
    common = {"host": "LAB-WEB-01", "source_ip": "192.0.2.44", "username": "synthetic-admin"}
    events: list[dict] = []
    if scenario in {"attack-chain", "brute-force", "suspicious-login"}:
        events += [
            common
            | {
                "event_category": "authentication",
                "action": "login",
                "outcome": "failure",
                "message": "Failed authentication for synthetic-admin",
            }
            for _ in range(12)
        ]
    if scenario in {"attack-chain", "suspicious-login"}:
        events.append(
            common
            | {
                "event_category": "authentication",
                "action": "login",
                "outcome": "success",
                "authentication": {"privileged": True},
                "message": "Successful authentication after failed logins",
            }
        )
    if scenario in {"attack-chain", "privilege-escalation"}:
        events.append(
            common
            | {
                "event_category": "privilege",
                "action": "sudo",
                "outcome": "success",
                "command_line": "sudo id",
                "message": "Synthetic sudo execution",
            }
        )
    if scenario == "attack-chain":
        events.extend(
            [
                common
                | {
                    "event_category": "process",
                    "action": "execute",
                    "command_line": "powershell -enc U3ludGhldGlj",
                    "process": {"name": "powershell.exe"},
                    "message": "Synthetic encoded PowerShell process telemetry",
                },
                common
                | {
                    "event_category": "network",
                    "action": "connect",
                    "destination_ip": "203.0.113.10",
                    "destination_port": 443,
                    "message": "Synthetic outbound connection to documentation IP",
                },
            ]
        )
    if scenario == "port-scan":
        events.extend(
            common
            | {
                "event_category": "network",
                "action": "connect",
                "destination_ip": "198.51.100.9",
                "destination_port": port,
                "message": "Synthetic connection telemetry",
            }
            for port in range(8000, 8020)
        )
    if scenario == "web-attack":
        events.append(
            common
            | {
                "event_category": "web",
                "action": "request",
                "http": {"path": "/../../etc/passwd", "status": 403},
                "message": "Synthetic path traversal request",
            }
        )
    if scenario == "data-exfiltration":
        events.extend(
            [
                common
                | {
                    "event_category": "file",
                    "action": "read",
                    "file": {"path": "/etc/shadow", "hash": "synthetic-hash-exfil"},
                    "message": "Sensitive security configuration archive read",
                },
                common
                | {
                    "event_category": "network",
                    "action": "connect",
                    "destination_ip": "198.51.100.99",
                    "destination_port": 443,
                    "network": {"bytes": 45000000},
                    "message": "High-volume outbound data transmission (45MB)",
                },
            ]
        )
    if scenario == "cloud-iam-tampering":
        events.append(
            common
            | {
                "event_category": "cloud",
                "action": "AttachUserPolicy",
                "cloud": {
                    "resource": "arn:aws:iam::123456789012:user/compromised-analyst",
                    "action": "AttachUserPolicy",
                },
                "message": "Synthetic cloud administrative privilege assignment: AdministratorAccess",
            }
        )
    if scenario == "ransomware-canary":
        events.extend(
            common
            | {
                "event_category": "file",
                "action": "modify",
                "file": {"path": f"C:\\Shares\\Finance\\document_{i}.xlsx.locked"},
                "message": "High-velocity file modification with known canary ransomware extension",
            }
            for i in range(15)
        )
    if scenario == "benign":
        events.extend(
            common
            | {
                "event_category": "authentication",
                "action": "login",
                "outcome": "success",
                "message": "Routine authorized login",
            }
            for _ in range(3)
        )
    if not events:
        raise ValueError("Unknown synthetic scenario")
    return [
        EventInput(
            source="aegis-simulator",
            source_type="json",
            collector="synthetic",
            timestamp=start + timedelta(seconds=index * 5),
            source_sequence=f"{start.isoformat()}:{scenario}:{index}",
            raw_event=event,
        )
        for index, event in enumerate(events)
    ]
