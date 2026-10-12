from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now() -> datetime:
    return datetime.now(UTC)


def uid() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    audit_head: Mapped[str] = mapped_column(String(64), default="0" * 64)


class Owned:
    id: Mapped[str] = mapped_column(String(80), primary_key=True, default=uid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class User(Owned, Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30))
    active: Mapped[bool] = mapped_column(default=True)
    failed_logins: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[float] = mapped_column(default=0.0)
    mfa_enabled: Mapped[bool] = mapped_column(default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), default=None)


class SessionToken(Owned, Base):
    __tablename__ = "sessions"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires: Mapped[float]


class APIKey(Owned, Base):
    __tablename__ = "api_keys"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(100))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    permissions: Mapped[list] = mapped_column(JSON)
    expires: Mapped[float]
    revoked: Mapped[bool] = mapped_column(default=False)


class PasswordReset(Owned, Base):
    __tablename__ = "password_resets"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[float]
    used: Mapped[bool] = mapped_column(default=False)


class EventRecord(Owned, Base):
    __tablename__ = "events_metadata"
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(200))
    # Durable source of truth until explicit retention; OpenSearch is a rebuildable search projection.
    payload: Mapped[dict] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)
    attempts: Mapped[int] = mapped_column(default=0)
    available_at: Mapped[float] = mapped_column(default=0.0, index=True)
    last_error: Mapped[str | None] = mapped_column(String(100))
    __table_args__ = (Index("ix_event_queue", "state", "available_at", "created_at"),)


class Rule(Owned, Base):
    __tablename__ = "detection_rules"
    rule_id: Mapped[str] = mapped_column(String(80))
    version: Mapped[int] = mapped_column(default=1)
    enabled: Mapped[bool] = mapped_column(default=True)
    document: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("organization_id", "rule_id"),)


class RuleVersion(Owned, Base):
    __tablename__ = "rule_versions"
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"))
    version: Mapped[int]
    author: Mapped[str] = mapped_column(ForeignKey("users.id"))
    summary: Mapped[str] = mapped_column(String(500))
    document: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("rule_id", "version"),)


class Alert(Owned, Base):
    __tablename__ = "alerts"
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(15), index=True)
    status: Mapped[str] = mapped_column(String(25), default="NEW", index=True)
    rule_id: Mapped[str] = mapped_column(String(80), index=True)
    rule_version: Mapped[int]
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    correlation_key: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[int]
    risk_score: Mapped[int]
    risk_factors: Mapped[dict] = mapped_column(JSON)
    explanation: Mapped[dict] = mapped_column(JSON)
    mitre_techniques: Mapped[list] = mapped_column(JSON)
    entity_ids: Mapped[list] = mapped_column(JSON)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(default=0)
    assignee: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    revision: Mapped[int] = mapped_column(default=1)


class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events_metadata.id"), primary_key=True)


class Incident(Owned, Base):
    __tablename__ = "incidents"
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(15), index=True)
    status: Mapped[str] = mapped_column(String(25), default="OPEN", index=True)
    priority: Mapped[int] = mapped_column(default=2)
    assignee: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    correlation_key: Mapped[str | None] = mapped_column(String(64), unique=True)
    resolution: Mapped[str] = mapped_column(default="")
    revision: Mapped[int] = mapped_column(default=1)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), primary_key=True)


class Case(Owned, Base):
    __tablename__ = "cases"
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(25), default="OPEN")
    assignee: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    revision: Mapped[int] = mapped_column(default=1)


class CaseNote(Owned, Base):
    __tablename__ = "case_notes"
    resource_type: Mapped[str] = mapped_column(String(20))
    resource_id: Mapped[str] = mapped_column(String(80), index=True)
    author: Mapped[str] = mapped_column(ForeignKey("users.id"))
    text: Mapped[str]


class CaseEvidence(Owned, Base):
    __tablename__ = "case_evidence"
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"))
    resource_type: Mapped[str] = mapped_column(String(20))
    resource_id: Mapped[str] = mapped_column(String(80))
    evidence_hash: Mapped[str] = mapped_column(String(64))
    attached_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class Entity(Owned, Base):
    __tablename__ = "entities"
    type: Mapped[str] = mapped_column(String(20), index=True)
    value: Mapped[str] = mapped_column(String(500), index=True)
    risk_score: Mapped[int] = mapped_column(default=0)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (UniqueConstraint("organization_id", "type", "value"),)


class EntityRelationship(Owned, Base):
    __tablename__ = "entity_relationships"
    source_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events_metadata.id"))
    relation: Mapped[str] = mapped_column(String(40), default="observed_with")
    __table_args__ = (UniqueConstraint("source_id", "target_id", "event_id"),)


class IOC(Owned, Base):
    __tablename__ = "iocs"
    type: Mapped[str] = mapped_column(String(15))
    value: Mapped[str] = mapped_column(String(2048), index=True)
    source: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[int]
    severity: Mapped[str] = mapped_column(String(15))
    description: Mapped[str]
    tags: Mapped[list] = mapped_column(JSON, default=list)
    expires: Mapped[float | None]
    __table_args__ = (UniqueConstraint("organization_id", "type", "value"),)


class IOCMatch(Base):
    __tablename__ = "ioc_matches"
    ioc_id: Mapped[str] = mapped_column(ForeignKey("iocs.id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events_metadata.id"), primary_key=True)


class Collector(Owned, Base):
    __tablename__ = "collectors"
    name: Mapped[str] = mapped_column(String(200))
    type: Mapped[str] = mapped_column(String(80))
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    events_received: Mapped[int] = mapped_column(default=0)
    events_processed: Mapped[int] = mapped_column(default=0)
    errors: Mapped[int] = mapped_column(default=0)
    version: Mapped[str] = mapped_column(String(30), default="0.1.0")
    __table_args__ = (UniqueConstraint("organization_id", "name"),)


class SavedSearch(Owned, Base):
    __tablename__ = "saved_searches"
    name: Mapped[str] = mapped_column(String(200))
    query: Mapped[dict] = mapped_column(JSON)
    author: Mapped[str] = mapped_column(ForeignKey("users.id"))


class PlaybookExecution(Owned, Base):
    __tablename__ = "playbook_executions"
    action: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(30), default="REQUESTED")
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    revision: Mapped[int] = mapped_column(default=1)


class Notification(Owned, Base):
    __tablename__ = "notifications"
    title: Mapped[str] = mapped_column(String(300))
    resource_id: Mapped[str] = mapped_column(String(80))
    read: Mapped[bool] = mapped_column(default=False)


class Report(Owned, Base):
    __tablename__ = "reports"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    generated_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    content: Mapped[dict] = mapped_column(JSON)
    content_hash: Mapped[str] = mapped_column(String(64))


class AuditLog(Owned, Base):
    __tablename__ = "audit_logs"
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(100))
    resource_id: Mapped[str] = mapped_column(String(80))
    result: Mapped[str] = mapped_column(String(30), default="success")
    details: Mapped[dict] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)
    key_version: Mapped[int] = mapped_column(default=1)


class AuditHead(Base):
    __tablename__ = "audit_heads"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    audit_head: Mapped[str] = mapped_column(String(64), default="0" * 64)
    sequence_number: Mapped[int] = mapped_column(default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditCheckpoint(Owned, Base):
    __tablename__ = "audit_checkpoints"
    sequence_number: Mapped[int] = mapped_column(index=True)
    head_entry_hash: Mapped[str] = mapped_column(String(64))
    checkpoint_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(256))
    key_version: Mapped[int] = mapped_column(default=1)


class Agent(Owned, Base):
    __tablename__ = "agents"
    name: Mapped[str] = mapped_column(String(200), index=True)
    public_key: Mapped[str] = mapped_column(String(128))  # Ed25519 public key in hex
    status: Mapped[str] = mapped_column(String(30), default="ENROLLED")  # ENROLLED, REVOKED, PENDING
    os: Mapped[str] = mapped_column(String(50), default="unknown")
    os_release: Mapped[str] = mapped_column(String(50), default="")
    ip: Mapped[str] = mapped_column(String(50), default="127.0.0.1")
    version: Mapped[str] = mapped_column(String(30), default="1.0.0")
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    isolation_status: Mapped[str] = mapped_column(String(30), default="NONE")
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    auth_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, default=None)
    __table_args__ = (UniqueConstraint("organization_id", "name"),)


class AgentEnrollmentToken(Owned, Base):
    __tablename__ = "agent_enrollment_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[float] = mapped_column(index=True)
    used: Mapped[bool] = mapped_column(default=False)
    used_by_agent_id: Mapped[str | None] = mapped_column(String(80), default=None)


class WindowState(Base):
    __tablename__ = "window_state"
    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    data: Mapped[list] = mapped_column(JSON, default=list)
    expires: Mapped[float] = mapped_column(index=True)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_health"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    last_seen: Mapped[float]
    processed: Mapped[int] = mapped_column(default=0)


class SearchJob(Base):
    __tablename__ = "search_jobs"
    event_id: Mapped[str] = mapped_column(ForeignKey("events_metadata.id"), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    state: Mapped[str] = mapped_column(String(20), default="PENDING")
    attempts: Mapped[int] = mapped_column(default=0)
    available_at: Mapped[float] = mapped_column(default=0.0)
    last_error: Mapped[str | None] = mapped_column(String(100))
    __table_args__ = (Index("ix_search_jobs_ready", "state", "available_at"),)


class Integration(Owned, Base):
    __tablename__ = "integrations"
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(30))
    endpoint: Mapped[str] = mapped_column(String(2048))
    secret_env: Mapped[str | None] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(default=True)
    revision: Mapped[int] = mapped_column(default=1)
    status: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    last_error: Mapped[str | None] = mapped_column(String(100))
    last_success: Mapped[float | None]
    __table_args__ = (UniqueConstraint("organization_id", "name"),)


class Delivery(Owned, Base):
    __tablename__ = "notification_deliveries"
    notification_id: Mapped[str] = mapped_column(ForeignKey("notifications.id"))
    integration_id: Mapped[str] = mapped_column(ForeignKey("integrations.id"))
    state: Mapped[str] = mapped_column(String(20), default="PENDING")
    attempts: Mapped[int] = mapped_column(default=0)
    available_at: Mapped[float] = mapped_column(default=0.0)
    last_error: Mapped[str | None] = mapped_column(String(100))
    delivered_at: Mapped[float | None]
    __table_args__ = (
        UniqueConstraint("notification_id", "integration_id"),
        Index("ix_delivery_ready", "state", "available_at"),
    )


def database(url: str):
    engine = create_engine(
        url, pool_pre_ping=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}
    )
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def sqlite_constraints(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")

    return engine, sessionmaker(engine, expire_on_commit=False)


def as_dict(row) -> dict:
    return {
        column.name: (
            value.isoformat() if isinstance(value := getattr(row, column.name), datetime) else value
        )
        for column in row.__table__.columns
    }
