"""Integration checks executed inside the API image against real dependencies."""

from datetime import UTC, datetime
from uuid import uuid4

from redis import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from aegis.config import get_settings
from aegis.db import Alert, AlertEvent, AuditLog, EventRecord, Incident, Organization, WindowState, database
from aegis.detection import SQLState
from aegis.investigation import investigate
from aegis.parsers import ParserRegistry
from aegis.schemas import EventInput, SearchQuery
from aegis.security import verify_audit
from aegis.storage import OpenSearchStorage


def main():
    settings = get_settings()
    if not settings.redis_url or not settings.opensearch_url:
        raise RuntimeError("Distributed service configuration required")
    _, sessions = database(settings.database_url)
    redis = Redis.from_url(settings.redis_url, socket_timeout=3)
    if not redis.ping():
        raise RuntimeError("Redis ping failed")
    checks = 1
    with sessions() as db:
        db.execute(text("SELECT 1"))
        if db.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")).scalar():
            raise RuntimeError("API runtime role must not be a database superuser")
        checks += 1
        incident = db.scalar(select(Incident))
        if not incident:
            raise RuntimeError("Run the synthetic attack chain first")
        organization_id = incident.organization_id
        result = investigate(db, incident.organization_id, incident.id)
        if not result["evidence"] or not result["iocs"]:
            raise RuntimeError("PostgreSQL investigation join failed")
        if not verify_audit(db, settings, incident.organization_id):
            raise RuntimeError("Audit verification failed")
        checks += 3
        record = db.scalar(select(AuditLog).where(AuditLog.organization_id == incident.organization_id))
        try:
            db.execute(
                text("UPDATE audit_logs SET action = :action WHERE id = :id"),
                {"action": "tamper-test", "id": record.id},
            )
            db.rollback()
            raise RuntimeError("Append-only audit trigger did not reject mutation")
        except DBAPIError:
            db.rollback()
            checks += 1
    storage = OpenSearchStorage(settings)
    if storage.health() != "HEALTHY":
        raise RuntimeError("Search is unhealthy")
    query = SearchQuery(limit=2, aggregate="event_category")
    first = storage.search(organization_id, query)
    if not first["items"] or not first["next_cursor"]:
        raise RuntimeError("OpenSearch search/aggregation failed")
    second = storage.search(organization_id, query.model_copy(update={"cursor": first["next_cursor"]}))
    if {item["event_id"] for item in first["items"]} & {item["event_id"] for item in second["items"]}:
        raise RuntimeError("OpenSearch pagination repeated events")
    if storage.search(str(uuid4()), query)["total"] != 0:
        raise RuntimeError("OpenSearch tenant isolation failed")
    checks += 3
    key = "integration-" + str(uuid4())
    event = (
        ParserRegistry()
        .normalize(
            EventInput(
                source="integration", timestamp=datetime.now(UTC), raw_event={"message": "state replay test"}
            ),
            "integration",
        )
        .model_dump(mode="json")
    )
    with sessions() as db:
        state = SQLState(db)
        if len(state.append(key, event, 60)) != 1 or len(state.append(key, event, 60)) != 1:
            raise RuntimeError("Transactional replay is not idempotent")
        db.flush()
        db.rollback()
        if db.get(WindowState, key):
            raise RuntimeError("Rolled-back correlation state persisted")
    checks += 2
    with sessions() as db:
        event_record = db.scalar(select(EventRecord))
        try:
            event_record.evidence_hash = "f" * 64
            db.flush()
        except DBAPIError:
            db.rollback()
            checks += 1
        else:
            db.rollback()
            raise RuntimeError("Database allowed original evidence mutation")
    with sessions() as db:
        alert = db.scalar(select(Alert).where(Alert.organization_id == organization_id))
        other = Organization(name="Isolated tenant constraint check")
        db.add(other)
        db.flush()
        record = EventRecord(
            organization_id=other.id,
            timestamp=datetime.now(UTC),
            source="tenant-check",
            evidence_hash="0" * 64,
            payload={},
        )
        db.add(record)
        db.flush()
        try:
            db.add(AlertEvent(alert_id=alert.id, event_id=record.id))
            db.flush()
        except DBAPIError:
            db.rollback()
            checks += 1
        else:
            db.rollback()
            raise RuntimeError("Database accepted a cross-tenant evidence link")
    print(f"Distributed integration checks: {checks} passed")


if __name__ == "__main__":
    main()
