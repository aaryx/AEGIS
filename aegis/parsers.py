import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from aegis.schemas import Event, EventInput


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Parser(Protocol):
    def can_parse(self, event: EventInput) -> bool: ...
    def parse(self, event: EventInput) -> dict: ...
    def validate(self, event: dict) -> bool: ...


class GenericParser:
    def can_parse(self, event):
        return True

    def parse(self, event):
        return {
            "message": event.raw_event if isinstance(event.raw_event, str) else canonical(event.raw_event)
        }

    def validate(self, event):
        return isinstance(event.get("message", ""), str)


class JSONParser(GenericParser):
    def can_parse(self, event):
        return isinstance(event.raw_event, dict) or str(event.raw_event).lstrip().startswith("{")

    def parse(self, event):
        raw = json.loads(event.raw_event) if isinstance(event.raw_event, str) else event.raw_event
        if not isinstance(raw, dict):
            raise ValueError("Structured event must be an object")
        reserved = {
            "event_id",
            "ingest_timestamp",
            "source",
            "source_type",
            "collector",
            "raw_event",
            "metadata",
        }
        data = {key: value for key, value in raw.items() if key in Event.model_fields and key not in reserved}
        if isinstance(data.get("process"), str):
            data["process"] = {"name": data["process"]}
        data["normalized_fields"] = {
            key: value for key, value in raw.items() if key not in Event.model_fields
        }
        data.setdefault("message", canonical(raw))
        return data


class LinuxAuthParser(GenericParser):
    def can_parse(self, event):
        return isinstance(event.raw_event, str) and any(
            word in event.raw_event for word in ("sshd[", "sudo:", "useradd[")
        )

    def parse(self, event):
        text = event.raw_event
        data = {
            "message": text,
            "event_category": "authentication",
            "action": "login",
            "event_type": "linux_auth",
        }
        auth = re.search(
            r"(Failed|Accepted) (?:password|publickey) for (?:invalid user )?(\S+) from ([\da-fA-F.:]+) port (\d+)",
            text,
        )
        if auth:
            data.update(
                username=auth[2],
                source_ip=auth[3],
                source_port=int(auth[4]),
                outcome="failure" if auth[1] == "Failed" else "success",
            )
        host = re.search(r"\s([\w.-]+)\s+(?:sshd|sudo|useradd)(?:\[|:)", text)
        if host:
            data["host"] = host[1]
        if "sudo:" in text:
            data.update(event_category="privilege", action="sudo", outcome="success")
            command = re.search(r"COMMAND=(.{1,8192})", text)
            if command:
                data["command_line"] = command[1]
        if "useradd[" in text:
            data.update(event_category="identity", action="create_user", outcome="success")
        return data


class SyslogParser(GenericParser):
    def can_parse(self, event):
        return event.source_type in {"syslog", "firewall", "journald"}

    def parse(self, event):
        if isinstance(event.raw_event, dict):
            raw = event.raw_event
            return {
                "message": str(raw.get("MESSAGE", "")),
                "host": raw.get("_HOSTNAME"),
                "process": {"name": raw.get("SYSLOG_IDENTIFIER")},
            }
        data = {"message": event.raw_event, "event_type": "syslog"}
        pairs = dict(re.findall(r"\b([A-Za-z_]+)=([^\s]{1,500})", event.raw_event))
        for source, target in {
            "SRC": "source_ip",
            "DST": "destination_ip",
            "SPT": "source_port",
            "DPT": "destination_port",
            "PROTO": "protocol",
        }.items():
            if source in pairs:
                data[target] = int(pairs[source]) if source in {"SPT", "DPT"} else pairs[source]
        if "SRC" in pairs:
            data.update(
                event_category="network",
                action="connect",
                outcome="failure" if "DROP" in event.raw_event else "unknown",
            )
        return data


class WebParser(GenericParser):
    pattern = re.compile(
        r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^" ]{1,8192}) [^"]+" (\d{3}) (\d+|-)(?: "[^"]*" "([^"]*)")?'
    )

    def can_parse(self, event):
        return event.source_type in {"nginx", "apache"}

    def parse(self, event):
        match = self.pattern.match(str(event.raw_event))
        if not match:
            raise ValueError("Malformed web access log")
        return {
            "message": event.raw_event,
            "source_ip": match[1],
            "timestamp": datetime.strptime(match[2], "%d/%b/%Y:%H:%M:%S %z"),
            "event_category": "web",
            "action": "request",
            "outcome": "failure" if int(match[5]) >= 400 else "success",
            "http": {
                "method": match[3],
                "path": match[4],
                "status": int(match[5]),
                "user_agent": match[7] or "",
            },
            "network": {"bytes": int(match[6]) if match[6] != "-" else 0},
        }


class WindowsEventParser(JSONParser):
    mapping = {
        4624: ("authentication", "login", "success"),
        4625: ("authentication", "login", "failure"),
        4740: ("authentication", "lockout", "failure"),
        4672: ("privilege", "special_privileges", "success"),
        4720: ("identity", "create_user", "success"),
        4732: ("privilege", "group_change", "success"),
        4688: ("process", "execute", "success"),
        4698: ("persistence", "scheduled_task", "success"),
        7045: ("persistence", "service_create", "success"),
    }

    def can_parse(self, event):
        return event.source_type == "windows"

    def parse(self, event):
        raw = json.loads(event.raw_event) if isinstance(event.raw_event, str) else event.raw_event
        event_id = int(raw.get("EventID", 0))
        category, action, outcome = self.mapping.get(event_id, ("other", "observe", "unknown"))
        fields = raw.get("EventData", {})
        return {
            "event_type": f"windows_{event_id}",
            "event_category": category,
            "action": action,
            "outcome": outcome,
            "host": raw.get("Computer"),
            "username": fields.get("TargetUserName"),
            "source_ip": fields.get("IpAddress") if fields.get("IpAddress") not in {"-", "", None} else None,
            "command_line": fields.get("CommandLine"),
            "process": {"name": fields.get("NewProcessName")},
            "parent_process": fields.get("ParentProcessName"),
            "message": canonical(raw),
            **({"timestamp": raw["TimeCreated"]} if raw.get("TimeCreated") else {}),
        }


class DockerParser(JSONParser):
    def can_parse(self, event):
        return event.source_type == "docker"

    def parse(self, event):
        raw = json.loads(event.raw_event) if isinstance(event.raw_event, str) else event.raw_event
        return {
            "message": raw.get("log", ""),
            "event_type": "container",
            "normalized_fields": {"stream": raw.get("stream")},
            **({"timestamp": raw["time"]} if raw.get("time") else {}),
        }


class CloudParser(JSONParser):
    def can_parse(self, event):
        return event.source_type in {"aws", "azure", "gcp"}

    def parse(self, event):
        raw = json.loads(event.raw_event) if isinstance(event.raw_event, str) else event.raw_event
        if event.source_type == "aws":
            action = raw.get("eventName", "unknown")
            return {
                "event_category": "cloud",
                "action": action,
                "username": raw.get("userIdentity", {}).get("arn"),
                "cloud": {"provider": "aws", "action": action, "resource": raw.get("eventSource")},
                "outcome": "failure" if raw.get("errorCode") else "success",
                "message": canonical(raw),
                **({"timestamp": raw["eventTime"]} if raw.get("eventTime") else {}),
            }
        if event.source_type == "azure":
            action = raw.get("operationName", "unknown")
            action = action.get("value", "unknown") if isinstance(action, dict) else action
            return {
                "event_category": "cloud",
                "action": action,
                "username": raw.get("caller"),
                "message": canonical(raw),
                "cloud": {"provider": "azure", "action": action, "resource": raw.get("resourceId")},
            }
        proto = raw.get("protoPayload", {})
        return {
            "event_category": "cloud",
            "action": proto.get("methodName", "unknown"),
            "message": canonical(raw),
            "username": proto.get("authenticationInfo", {}).get("principalEmail"),
            "cloud": {
                "provider": "gcp",
                "action": proto.get("methodName"),
                "resource": proto.get("resourceName"),
            },
        }


class ParserRegistry:
    def __init__(self, plugins: list[Parser] | None = None):
        self.parsers = [
            *(plugins or []),
            WindowsEventParser(),
            DockerParser(),
            CloudParser(),
            LinuxAuthParser(),
            WebParser(),
            SyslogParser(),
            JSONParser(),
            GenericParser(),
        ]

    def normalize(
        self, incoming: EventInput, organization_id: str, accepted_at: datetime | None = None
    ) -> Event:
        accepted_at = accepted_at or datetime.now(UTC)
        identity: dict = {
            "tenant": organization_id,
            "source": incoming.source,
            "sequence": incoming.source_sequence,
        }
        if incoming.source_sequence is None:
            identity.update(
                raw=incoming.raw_event,
                timestamp=incoming.timestamp.isoformat() if incoming.timestamp else None,
            )
        event_id = str(uuid5(NAMESPACE_URL, canonical(identity)))
        parser = next(parser for parser in self.parsers if parser.can_parse(incoming))
        try:
            parsed = parser.parse(incoming)
        except (AttributeError, KeyError, TypeError, OverflowError) as exc:
            raise ValueError("Malformed source log structure") from exc
        if not parser.validate(parsed):
            raise ValueError("Parser validation failed")
        parsed.setdefault("timestamp", incoming.timestamp or accepted_at)
        data = incoming.model_dump(exclude={"timestamp"}) | parsed
        data.update(
            event_id=event_id,
            ingest_timestamp=accepted_at,
            metadata={"parser": type(parser).__name__, "classification": "SENSITIVE"},
        )
        result = Event.model_validate(data)
        if result.timestamp.tzinfo is None:
            raise ValueError("Parsed timestamp must include timezone")
        result.timestamp = result.timestamp.astimezone(UTC)
        if result.timestamp > accepted_at + timedelta(minutes=5):
            raise ValueError("Event timestamp exceeds allowed future clock skew")
        return result
