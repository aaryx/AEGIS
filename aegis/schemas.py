import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["informational", "low", "medium", "high", "critical"]
RoleName = Literal["SUPER_ADMIN", "SECURITY_ADMIN", "SOC_MANAGER", "SENIOR_ANALYST", "ANALYST", "VIEWER"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=65536, allow_inf_nan=False)


class EventInput(StrictModel):
    source: str = Field(min_length=1, max_length=200)
    source_type: str = Field(default="json", max_length=80)
    collector: str = Field(default="api", min_length=1, max_length=200)
    source_sequence: str | None = Field(default=None, max_length=200)
    timestamp: datetime | None = None
    raw_event: str | dict

    @field_validator("timestamp")
    @classmethod
    def aware(cls, value):
        if value and value.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
        return value

    @field_validator("raw_event")
    @classmethod
    def bounded_json(cls, value):
        if len(json.dumps(value, allow_nan=False).encode()) > 262144:
            raise ValueError("Event is too large")
        stack = [(value, 0)]
        while stack:
            item, depth = stack.pop()
            if depth > 20:
                raise ValueError("Event nesting exceeds 20 levels")
            if isinstance(item, dict):
                stack.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                stack.extend((child, depth + 1) for child in item)
        return value


class Event(StrictModel):
    event_id: str
    timestamp: datetime
    ingest_timestamp: datetime
    source: str
    source_type: str
    collector: str
    source_sequence: str | None = None
    host: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(None, ge=0, le=65535)
    destination_port: int | None = Field(None, ge=0, le=65535)
    protocol: str | None = None
    username: str | None = None
    user_id: str | None = None
    process_id: int | None = None
    parent_process: str | None = None
    command_line: str | None = None
    event_type: str = "generic"
    event_category: str = "other"
    action: str = "observe"
    outcome: str = "unknown"
    severity: Severity = "informational"
    message: str = ""
    raw_event: str | dict
    normalized_fields: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=100)
    geo: dict = Field(default_factory=dict)
    authentication: dict = Field(default_factory=dict)
    network: dict = Field(default_factory=dict)
    file: dict = Field(default_factory=dict)
    process: dict = Field(default_factory=dict)
    http: dict = Field(default_factory=dict)
    cloud: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def ip(cls, value):
        return str(ipaddress.ip_address(value)) if value else None


FIELDS = {
    "event_id",
    "timestamp",
    "source",
    "source_type",
    "host",
    "hostname",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "username",
    "user_id",
    "process_id",
    "parent_process",
    "command_line",
    "event_type",
    "event_category",
    "action",
    "outcome",
    "severity",
    "message",
    "tags",
    "http.status",
    "http.path",
    "http.user_agent",
    "network.bytes",
    "file.path",
    "file.hash",
    "process.name",
    "cloud.action",
    "cloud.resource",
    "authentication.privileged",
    "metadata.ioc_match",
    "metadata.asset_criticality",
}
ALIASES = {"event.category": "event_category", "event.type": "event_type", "user.name": "username"}


def get_field(event: dict, field: str) -> Any:
    value: Any = event
    for part in ALIASES.get(field, field).split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


class Predicate(StrictModel):
    field: str
    op: Literal["eq", "ne", "in", "contains", "gte", "lte", "exists"] = "eq"
    value: str | int | float | bool | list[str | int] | None = None

    @field_validator("field")
    @classmethod
    def known_field(cls, value):
        value = ALIASES.get(value, value)
        if value not in FIELDS:
            raise ValueError("Unsupported field")
        return value

    @model_validator(mode="after")
    def valid_operator(self):
        if self.op == "in" and (not isinstance(self.value, list) or len(self.value) > 100):
            raise ValueError("in requires a list of up to 100 values")
        if self.op in {"gte", "lte"} and (
            not isinstance(self.value, (int, float)) or isinstance(self.value, bool)
        ):
            raise ValueError("Numeric comparison requires a number")
        if self.op == "contains" and not isinstance(self.value, str):
            raise ValueError("contains requires text")
        return self

    def matches(self, event: dict) -> bool:
        actual = get_field(event, self.field)
        match self.op:
            case "eq":
                return actual == self.value
            case "ne":
                return actual is not None and actual != self.value
            case "in":
                return actual in self.value if isinstance(self.value, list) else False
            case "contains":
                return isinstance(actual, str) and str(self.value).casefold() in actual.casefold()
            case "gte":
                return (
                    isinstance(actual, (int, float))
                    and not isinstance(actual, bool)
                    and isinstance(self.value, (int, float))
                    and not isinstance(self.value, bool)
                    and actual >= self.value
                )
            case "lte":
                return (
                    isinstance(actual, (int, float))
                    and not isinstance(actual, bool)
                    and isinstance(self.value, (int, float))
                    and not isinstance(self.value, bool)
                    and actual <= self.value
                )
            case "exists":
                return (actual is not None) == (self.value is not False)
        return False


class Condition(StrictModel):
    type: Literal["match", "threshold", "sequence", "aggregation", "anomaly", "beacon"] = "match"
    count: int = Field(1, ge=1, le=10000)
    window_seconds: int = Field(300, ge=1, le=86400)
    group_by: list[str] = Field(default_factory=lambda: ["source_ip"], min_length=1, max_length=4)
    distinct_field: str | None = None
    sum_field: str | None = None
    sum_threshold: float = Field(0, ge=0)
    sequence: list[list[Predicate]] = Field(default_factory=list, max_length=10)
    baseline_count: int = Field(20, ge=5, le=1000)
    deviation: float = Field(3.0, ge=1, le=10)
    tolerance: float = Field(0.15, ge=0.01, le=0.5)

    @model_validator(mode="after")
    def supported(self):
        for name in self.group_by + [f for f in (self.distinct_field, self.sum_field) if f]:
            if name not in FIELDS:
                raise ValueError(f"Unsupported field: {name}")
        if self.type == "sequence" and (len(self.sequence) < 2 or any(not step for step in self.sequence)):
            raise ValueError("A sequence needs at least two nonempty steps")
        if self.type == "aggregation" and not (self.distinct_field or self.sum_field):
            raise ValueError("Aggregation requires distinct_field or sum_field")
        if self.type == "anomaly" and not self.sum_field:
            raise ValueError("Anomaly requires a numeric sum_field")
        if self.type == "beacon" and self.count < 4:
            raise ValueError("Beacon needs at least four observations")
        return self


class ExceptionRule(StrictModel):
    reason: str = Field(min_length=10, max_length=500)
    predicates: list[Predicate] = Field(min_length=1, max_length=20)


class DetectionRule(StrictModel):
    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_-]{2,79}$")
    name: str = Field(min_length=5, max_length=300)
    description: str = Field(min_length=10, max_length=2000)
    selection: list[Predicate] = Field(min_length=1, max_length=30)
    condition: Condition = Field(default_factory=Condition)
    severity: Severity = "medium"
    confidence: int = Field(75, ge=1, le=100)
    tags: list[str] = Field(default_factory=list, max_length=30)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=20)
    cooldown_seconds: int = Field(900, ge=1, le=86400)
    exceptions: list[ExceptionRule] = Field(default_factory=list, max_length=100)
    recommended_actions: list[str] = Field(
        default_factory=lambda: ["Review source evidence and validate asset ownership."]
    )

    @field_validator("mitre_techniques")
    @classmethod
    def mitre(cls, values):
        if any(not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value) for value in values):
            raise ValueError("Invalid ATT&CK technique identifier")
        return values


class SearchQuery(StrictModel):
    text: str = Field("", max_length=500)
    filters: list[Predicate] = Field(default_factory=list, max_length=20)
    start: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(hours=24))
    end: datetime = Field(default_factory=lambda: datetime.now(UTC))
    limit: int = Field(50, ge=1, le=500)
    cursor: str | None = Field(None, max_length=2000)
    sort: Literal["asc", "desc"] = "desc"
    aggregate: str | None = None

    @model_validator(mode="after")
    def window(self):
        if self.start.tzinfo is None or self.end.tzinfo is None or self.start >= self.end:
            raise ValueError("Provide an increasing timezone-aware time range")
        if self.end - self.start > timedelta(days=366):
            raise ValueError("Time range exceeds 366 days")
        if self.aggregate and self.aggregate not in FIELDS - {
            "message",
            "command_line",
            "http.path",
            "http.user_agent",
            "file.path",
        }:
            raise ValueError("Unsupported aggregation")
        return self


def parse_query(text: str) -> SearchQuery:
    if len(text) > 500:
        raise ValueError("Query too long")
    if not any(char in text for char in "=><"):
        return SearchQuery(text=text)
    predicates = []
    start = datetime.now(UTC) - timedelta(hours=24)
    for clause in re.split(r"\s+AND\s+(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", text):
        time_match = re.fullmatch(r"timestamp\s*>\s*now\(\)-(\d{1,6})([hmd])", clause.strip())
        if time_match:
            amount, unit = time_match.groups()
            start = datetime.now(UTC) - timedelta(
                seconds=int(amount) * {"h": 3600, "m": 60, "d": 86400}[unit]
            )
            continue
        match = re.fullmatch(r'([\w.]+)\s*=\s*("[^"\n]{0,200}"|\d+|true|false)', clause.strip())
        if not match:
            raise ValueError('Use field = "value" joined with AND, or plain text')
        predicates.append(Predicate(field=match[1], value=json.loads(match[2])))
    return SearchQuery(filters=predicates, start=start)


class IOCInput(StrictModel):
    type: Literal["ip", "domain", "url", "hash", "email", "hostname"]
    value: str = Field(min_length=1, max_length=2048)
    source: str = Field(default="analyst", max_length=100)
    confidence: int = Field(80, ge=1, le=100)
    severity: Severity = "high"
    description: str = Field(default="Analyst-supplied indicator", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=30)
    expires: float | None = None

    @model_validator(mode="after")
    def valid_value(self):
        if self.type == "ip":
            self.value = str(ipaddress.ip_address(self.value))
        elif self.type == "hash":
            if not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", self.value):
                raise ValueError("Expected MD5, SHA1 or SHA256 hash")
            self.value = self.value.lower()
        elif self.type == "url":
            parsed = urlsplit(self.value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
                raise ValueError("Expected an HTTP(S) URL without credentials")
        elif self.type == "email":
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", self.value):
                raise ValueError("Invalid email")
            self.value = self.value.lower()
        else:
            if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", self.value):
                raise ValueError("Invalid domain or hostname")
            self.value = self.value.lower()
        return self


class Login(StrictModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class UserInput(Login):
    password: str = Field(min_length=14, max_length=256)
    role: RoleName = "ANALYST"


class UpdateStatus(StrictModel):
    status: str = Field(max_length=25)
    revision: int = Field(ge=1)
    assignee: str | None = None
    resolution: str = Field("", max_length=10000)


class IncidentInput(StrictModel):
    title: str = Field(min_length=5, max_length=300)
    severity: Severity = "medium"
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    priority: int = Field(2, ge=1, le=4)


class NoteInput(StrictModel):
    text: str = Field(min_length=1, max_length=10000)


class ResponseInput(StrictModel):
    action: Literal[
        "gather_evidence",
        "notify_analyst",
        "isolate_host",
        "unisolate_host",
        "terminate_process",
        "disable_account",
        "block_ioc",
    ]
    target: str = Field(min_length=1, max_length=200)
    params: dict[str, Any] = Field(default_factory=dict)


class AgentHeartbeatInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(default="1.0.0", max_length=30)
    os: str = Field(default="unknown", max_length=50)
    os_release: str = Field(default="", max_length=50)
    ip: str = Field(default="127.0.0.1", max_length=50)
    status: str = Field(default="ONLINE", max_length=30)
    isolation_status: str = Field(default="NONE", max_length=30)
    capabilities: list[str] = Field(
        default_factory=lambda: ["isolate_host", "unisolate_host", "terminate_process"]
    )


class AgentReceiptInput(StrictModel):
    command_id: str = Field(min_length=1, max_length=80)
    action: str = Field(min_length=1, max_length=50)
    status: Literal["SUCCESS", "FAILED"]
    receipt_hash: str = Field(min_length=64, max_length=64)
    details: dict[str, Any] = Field(default_factory=dict)

