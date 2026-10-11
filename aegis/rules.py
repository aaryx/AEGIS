"""Curated behavioral rules. Samples are built independently in tests/detection_samples.py."""

from aegis.schemas import Condition, DetectionRule, Predicate

MITRE = {
    "T1110": ("Brute Force", "credential-access"),
    "T1078": ("Valid Accounts", "defense-evasion"),
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1053": ("Scheduled Task/Job", "persistence"),
    "T1543": ("Create or Modify System Process", "persistence"),
    "T1547": ("Boot or Logon Autostart Execution", "persistence"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1005": ("Data from Local System", "collection"),
    "T1560": ("Archive Collected Data", "collection"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1530": ("Data from Cloud Storage", "collection"),
    "T1562": ("Impair Defenses", "defense-evasion"),
    "T1136": ("Create Account", "persistence"),
}


def p(field, value, op="eq") -> Predicate:
    return Predicate(field=field, op=op, value=value)


def builtin_rules() -> list[DetectionRule]:
    auth_failure = [p("event_category", "authentication"), p("outcome", "failure")]
    specs = [
        (
            "AUTH-001",
            "Repeated authentication failures",
            auth_failure,
            "T1110",
            Condition(type="threshold", count=10),
        ),
        (
            "AUTH-002",
            "Password spraying across accounts",
            auth_failure,
            "T1110",
            Condition(type="aggregation", count=5, distinct_field="username"),
        ),
        (
            "AUTH-003",
            "Successful login after repeated failures",
            [p("event_category", "authentication")],
            "T1078",
            Condition(type="sequence", sequence=[auth_failure] * 3 + [[p("outcome", "success")]]),
        ),
        (
            "AUTH-004",
            "Account lockout burst",
            [p("action", "lockout")],
            "T1110",
            Condition(type="threshold", count=5, group_by=["host"]),
        ),
        (
            "AUTH-005",
            "Privileged authentication from multiple sources",
            [p("event_category", "authentication"), p("authentication.privileged", True)],
            "T1078",
            Condition(type="aggregation", count=3, distinct_field="source_ip", group_by=["username"]),
        ),
        (
            "PRIV-001",
            "Privileged command execution",
            [p("action", "sudo")],
            "T1548",
            Condition(group_by=["host"]),
        ),
        (
            "PRIV-002",
            "Privileged group membership changed",
            [p("action", ["group_change", "special_privileges"], "in")],
            "T1098",
            Condition(group_by=["host"]),
        ),
        (
            "PRIV-003",
            "Repeated sudo activity",
            [p("action", "sudo")],
            "T1548",
            Condition(type="threshold", count=10, group_by=["host", "username"]),
        ),
        (
            "PROC-001",
            "Encoded PowerShell execution",
            [p("command_line", "powershell", "contains"), p("command_line", "-enc", "contains")],
            "T1059.001",
            Condition(group_by=["host"]),
        ),
        (
            "PROC-002",
            "Shell downloads remote content",
            [p("command_line", "curl", "contains"), p("command_line", "|", "contains")],
            "T1059",
            Condition(group_by=["host"]),
        ),
        (
            "PROC-003",
            "Office application spawning a shell",
            [
                p("parent_process", ["winword.exe", "excel.exe"], "in"),
                p("process.name", ["cmd.exe", "powershell.exe"], "in"),
            ],
            "T1059",
            Condition(group_by=["host"]),
        ),
        (
            "PERSIST-001",
            "Scheduled task created",
            [p("action", "scheduled_task")],
            "T1053",
            Condition(group_by=["host"]),
        ),
        (
            "PERSIST-002",
            "New service installed",
            [p("action", "service_create")],
            "T1543",
            Condition(group_by=["host"]),
        ),
        (
            "PERSIST-003",
            "Account created",
            [p("action", "create_user")],
            "T1136",
            Condition(group_by=["host"]),
        ),
        (
            "PERSIST-004",
            "Startup location modified",
            [p("file.path", "/etc/cron", "contains")],
            "T1547",
            Condition(group_by=["host"]),
        ),
        (
            "NET-001",
            "Port scanning pattern",
            [p("event_category", "network")],
            "T1046",
            Condition(type="aggregation", count=15, distinct_field="destination_port"),
        ),
        (
            "NET-002",
            "Repeated connection failures",
            [p("event_category", "network"), p("outcome", "failure")],
            "T1046",
            Condition(type="threshold", count=20),
        ),
        (
            "NET-003",
            "Connection to threat intelligence indicator",
            [p("metadata.ioc_match", True)],
            "T1071",
            Condition(group_by=["host"]),
        ),
        (
            "NET-004",
            "Unusual destination fan-out",
            [p("event_category", "network")],
            "T1046",
            Condition(type="aggregation", count=20, distinct_field="destination_ip", group_by=["host"]),
        ),
        (
            "NET-005",
            "Periodic outbound connections",
            [p("event_category", "network")],
            "T1071",
            Condition(type="beacon", count=6, group_by=["host", "destination_ip"]),
        ),
        ("WEB-001", "Path traversal request", [p("http.path", "../", "contains")], "T1190", Condition()),
        (
            "WEB-002",
            "Encoded path traversal request",
            [p("http.path", "%2e%2e", "contains")],
            "T1190",
            Condition(),
        ),
        (
            "WEB-003",
            "Web error burst",
            [p("http.status", 400, "gte")],
            "T1190",
            Condition(type="threshold", count=20),
        ),
        (
            "WEB-004",
            "Web request rate threshold",
            [p("event_category", "web")],
            "T1190",
            Condition(type="threshold", count=100, window_seconds=60),
        ),
        (
            "WEB-005",
            "Security scanning user agent",
            [p("http.user_agent", "sqlmap", "contains")],
            "T1190",
            Condition(),
        ),
        (
            "DATA-001",
            "Bulk file access",
            [p("action", "file_read")],
            "T1005",
            Condition(type="aggregation", count=30, distinct_field="file.path", group_by=["username"]),
        ),
        (
            "DATA-002",
            "Sensitive file access",
            [p("file.path", "/etc/shadow", "contains")],
            "T1005",
            Condition(group_by=["host"]),
        ),
        (
            "DATA-003",
            "Archive creation command",
            [p("command_line", "tar -", "contains")],
            "T1560",
            Condition(group_by=["host"]),
        ),
        (
            "DATA-004",
            "Large outbound transfer",
            [p("event_category", "network")],
            "T1041",
            Condition(
                type="aggregation", sum_field="network.bytes", sum_threshold=100000000, group_by=["host"]
            ),
        ),
        (
            "DATA-005",
            "Outbound transfer statistical deviation",
            [p("event_category", "network")],
            "T1041",
            Condition(type="anomaly", sum_field="network.bytes", group_by=["host"]),
        ),
        (
            "CLOUD-001",
            "Cloud IAM privilege modification",
            [
                p(
                    "action",
                    [
                        "AttachUserPolicy",
                        "PutRolePolicy",
                        "SetIamPolicy",
                        "setIamPolicy",
                        "Microsoft.Authorization/roleAssignments/write",
                    ],
                    "in",
                )
            ],
            "T1098",
            Condition(group_by=["username"]),
        ),
        (
            "CLOUD-002",
            "Public storage policy modification",
            [p("action", ["PutBucketPolicy", "PutBucketAcl", "storage.buckets.setIamPolicy"], "in")],
            "T1530",
            Condition(group_by=["username"]),
        ),
        (
            "CLOUD-003",
            "Cloud audit logging disabled",
            [
                p(
                    "action",
                    ["StopLogging", "DeleteTrail", "Microsoft.Insights/diagnosticSettings/delete"],
                    "in",
                )
            ],
            "T1562",
            Condition(group_by=["username"]),
        ),
        (
            "CORR-001",
            "Potential account compromise",
            [p("event_category", ["authentication", "privilege", "process", "network"], "in")],
            "T1078",
            Condition(
                type="sequence",
                group_by=["host"],
                window_seconds=1800,
                sequence=[
                    auth_failure,
                    [p("event_category", "authentication"), p("outcome", "success")],
                    [p("action", "sudo")],
                    [p("event_category", "process")],
                    [p("event_category", "network")],
                ],
            ),
        ),
    ]
    return [
        DetectionRule(
            id=f"AEGIS-{id_}",
            name=name,
            description=f"Behavioral evidence: {name.lower()}. Validate business context before containment.",
            selection=selection,
            condition=condition,
            mitre_techniques=[technique],
            severity="critical" if id_.startswith("CORR") else "high",
        )
        for id_, name, selection, technique, condition in specs
    ]
