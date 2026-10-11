import time
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, tuple_

from aegis.db import (
    IOC,
    Alert,
    AlertEvent,
    Collector,
    Entity,
    EntityRelationship,
    EventRecord,
    Incident,
    IncidentAlert,
    IOCMatch,
    Notification,
    Organization,
    Rule,
    SearchJob,
    uid,
)
from aegis.detection import SQLState, evaluate, risk
from aegis.parsers import ParserRegistry, canonical, digest
from aegis.rules import builtin_rules
from aegis.schemas import DetectionRule, EventInput, get_field
from aegis.security import audit


def seed_rules(db, organization_id: str):
    existing = set(db.scalars(select(Rule.rule_id).where(Rule.organization_id == organization_id)))
    for rule in builtin_rules():
        if rule.id not in existing:
            db.add(
                Rule(organization_id=organization_id, rule_id=rule.id, document=rule.model_dump(mode="json"))
            )


def ingest(db, settings, organization_id: str, events: list[EventInput], actor: str, request=None):
    if len(events) > settings.max_batch_events:
        raise ValueError("Batch exceeds configured event limit")
    if not db.scalar(select(Organization.id).where(Organization.id == organization_id)):
        raise ValueError("Organization not found")
    registry = ParserRegistry()
    normalized = []
    for incoming in events:
        if len(canonical(incoming.raw_event).encode()) > settings.max_event_bytes:
            raise ValueError("Event exceeds configured byte limit")
        normalized.append(registry.normalize(incoming, organization_id))
    ids = [event.event_id for event in normalized]
    existing = {row.id: row for row in db.scalars(select(EventRecord).where(EventRecord.id.in_(ids)))}
    depth = db.scalar(
        select(func.count())
        .select_from(EventRecord)
        .where(EventRecord.organization_id == organization_id, EventRecord.state.in_(["PENDING", "RETRY"]))
    )
    search_depth = db.scalar(
        select(func.count())
        .select_from(SearchJob)
        .where(SearchJob.organization_id == organization_id, SearchJob.state != "INDEXED")
    )
    new_count = len(set(ids) - set(existing))
    if new_count and depth + search_depth + new_count > settings.queue_capacity:
        raise OverflowError("Tenant ingestion/search backlog is full; retry later")
    collectors = {
        row.name: row
        for row in db.scalars(select(Collector).where(Collector.organization_id == organization_id))
    }
    accepted, duplicates = [], []
    for event in normalized:
        evidence_hash = digest(event.raw_event)
        if event.event_id in existing:
            if existing[event.event_id].evidence_hash != evidence_hash:
                raise ValueError("Source sequence was reused with different evidence")
            duplicates.append(event.event_id)
            continue
        row = EventRecord(
            id=event.event_id,
            organization_id=organization_id,
            timestamp=event.timestamp,
            source=event.source,
            evidence_hash=evidence_hash,
            payload=event.model_dump(mode="json"),
        )
        db.add(row)
        existing[row.id] = row
        accepted.append(row.id)
        collector = collectors.get(event.collector)
        if not collector:
            collector = Collector(
                organization_id=organization_id,
                name=event.collector,
                type=event.source_type,
                events_received=0,
                events_processed=0,
                errors=0,
            )
            collectors[event.collector] = collector
            db.add(collector)
        collector.events_received += 1
        collector.last_heartbeat = event.ingest_timestamp
    audit(
        db,
        settings,
        organization_id,
        actor,
        "events.ingest",
        details={"accepted": len(accepted), "duplicates": len(duplicates)},
        request=request,
    )
    return {"accepted": accepted, "duplicates": duplicates, "delivery": "at-least-once"}


def enrich(event: dict, iocs: list[IOC]) -> list[IOC]:
    fields = {
        "ip": ["source_ip", "destination_ip"],
        "hostname": ["host", "hostname"],
        "domain": ["http.domain"],
        "url": ["http.url"],
        "hash": ["file.hash"],
        "email": ["username"],
    }
    matched = [
        ioc
        for ioc in iocs
        if (ioc.expires is None or ioc.expires > time.time())
        and any(str(get_field(event, field) or "").lower() == ioc.value.lower() for field in fields[ioc.type])
    ]
    event["metadata"] = event.get("metadata", {}) | {
        "ioc_match": bool(matched),
        "ioc_ids": [ioc.id for ioc in matched],
    }
    return matched


def track_entities(db, org, event, cache, max_entities: int = 15):
    descriptors = [
        (kind, str(value))
        for field, kind in [
            ("username", "user"),
            ("host", "host"),
            ("source_ip", "ip"),
            ("destination_ip", "ip"),
            ("process.name", "process"),
            ("file.hash", "file"),
            ("http.domain", "domain"),
            ("http.url", "url"),
            ("cloud.resource", "cloud_resource"),
        ]
        if (value := get_field(event, field))
    ]
    # Bound extracted entities per event to prevent combinatorial explosion
    descriptors = list(dict.fromkeys(descriptors))[:max_entities]
    entities = []
    for kind, value in descriptors:
        key = (kind, value)
        entity = cache.get(key)
        if not entity:
            entity = Entity(
                id=uid(), organization_id=org, type=kind, value=value, risk_score=0, attributes={}
            )
            db.add(entity)
            cache[key] = entity
        observed = datetime.fromisoformat(event["timestamp"])
        from datetime import UTC

        previous = (
            entity.last_seen.replace(tzinfo=UTC)
            if entity.last_seen and entity.last_seen.tzinfo is None
            else entity.last_seen
        )
        entity.last_seen = max(previous, observed) if previous else observed
        entities.append(entity)
    db.flush()

    # Generate semantic relationships instead of indiscriminate complete pairwise graphs
    pairs: list[tuple[Any, Any, str]] = []
    by_type: dict[str, list[Any]] = {}
    for ent in entities:
        by_type.setdefault(ent.type, []).append(ent)

    for host in by_type.get("host", []):
        for user in by_type.get("user", []):
            pairs.append((user, host, "authenticated_on"))
        for proc in by_type.get("process", []):
            pairs.append((proc, host, "executed_on"))
        for ip in by_type.get("ip", []):
            pairs.append((host, ip, "assigned_ip"))
        for domain in by_type.get("domain", []):
            pairs.append((host, domain, "queried_domain"))
        for url in by_type.get("url", []):
            pairs.append((host, url, "accessed_url"))

    for proc in by_type.get("process", []):
        for f in by_type.get("file", []):
            pairs.append((proc, f, "accessed_file"))
        for ip in by_type.get("ip", []):
            pairs.append((proc, ip, "connected_to"))

    for user in by_type.get("user", []):
        for cloud in by_type.get("cloud_resource", []):
            pairs.append((user, cloud, "managed_resource"))

    if not pairs and len(entities) >= 2:
        for i in range(len(entities) - 1):
            pairs.append((entities[i], entities[i + 1], "observed_with"))

    pairs = pairs[:max_entities]
    if pairs:
        candidate_ids = {
            digest([org, left.id, right.id, event["event_id"]]): (left, right, rel)
            for left, right, rel in pairs
        }
        existing_ids = set(
            db.scalars(
                select(EntityRelationship.id).where(EntityRelationship.id.in_(list(candidate_ids.keys())))
            )
        )
        for rel_id, (left, right, rel_name) in candidate_ids.items():
            if rel_id not in existing_ids:
                db.add(
                    EntityRelationship(
                        id=rel_id,
                        organization_id=org,
                        source_id=left.id,
                        target_id=right.id,
                        event_id=event["event_id"],
                        relation=rel_name,
                    )
                )
    return entities


def detect_batch(db, settings, records, redis=None):
    if not records:
        return
    org = records[0].organization_id
    rules = [
        (row, DetectionRule.model_validate(row.document))
        for row in db.scalars(select(Rule).where(Rule.organization_id == org, Rule.enabled.is_(True)))
    ]
    iocs = list(db.scalars(select(IOC).where(IOC.organization_id == org)))
    descriptors = set()
    for record in records:
        for field, kind in [
            ("username", "user"),
            ("host", "host"),
            ("source_ip", "ip"),
            ("destination_ip", "ip"),
            ("process.name", "process"),
            ("file.hash", "file"),
            ("http.domain", "domain"),
            ("http.url", "url"),
            ("cloud.resource", "cloud_resource"),
        ]:
            value = get_field(record.payload, field)
            if value:
                if len(str(value)) > 500:
                    raise ValueError("Entity value exceeds 500 characters")
                descriptors.add((kind, str(value)))
    cache = {
        (entity.type, entity.value): entity
        for entity in db.scalars(
            select(Entity).where(
                Entity.organization_id == org, tuple_(Entity.type, Entity.value).in_(descriptors)
            )
        )
    }
    collectors = {
        row.name: row for row in db.scalars(select(Collector).where(Collector.organization_id == org))
    }
    state = SQLState(db, settings.detection_lateness_seconds, settings.detection_window_limit)
    for record in records:
        event = dict(record.payload)
        for ioc in enrich(event, iocs):
            if not db.get(IOCMatch, (ioc.id, record.id)):
                db.add(IOCMatch(ioc_id=ioc.id, event_id=record.id))
        entities = track_entities(db, org, event, cache, max_entities=getattr(settings, "max_entities_per_event", 15))
        record.payload = event
        for row, rule in rules:
            explanation = evaluate(rule, event, state, org)
            if not explanation:
                continue
            stamp = datetime.fromisoformat(event["timestamp"])
            fingerprint = digest(
                [
                    org,
                    rule.id,
                    row.version,
                    explanation["group"],
                    int(stamp.timestamp()) // rule.cooldown_seconds,
                ]
            )
            alert = db.scalar(select(Alert).where(Alert.fingerprint == fingerprint))
            score, factors = risk(rule, event, len(explanation["event_ids"]))
            correlation = (
                digest(
                    [
                        org,
                        event.get("host"),
                        event.get("username"),
                        event.get("source_ip"),
                        int(stamp.timestamp()) // 1800,
                    ]
                )
                if event.get("host")
                else digest([org, fingerprint])
            )
            if not alert:
                evidence_stamps = [
                    datetime.fromisoformat(payload["timestamp"])
                    for payload in db.scalars(
                        select(EventRecord.payload).where(EventRecord.id.in_(explanation["event_ids"]))
                    )
                ]
                alert = Alert(
                    id="ALT-" + uid(),
                    organization_id=org,
                    title=rule.name,
                    severity=rule.severity,
                    rule_id=rule.id,
                    rule_version=row.version,
                    fingerprint=fingerprint,
                    correlation_key=correlation,
                    confidence=rule.confidence,
                    risk_score=score,
                    risk_factors=factors,
                    explanation=explanation,
                    mitre_techniques=rule.mitre_techniques,
                    entity_ids=[entity.id for entity in entities],
                    first_seen=min(evidence_stamps, default=stamp),
                    last_seen=stamp,
                    event_count=0,
                )
                db.add(alert)
                db.flush()
                audit(db, settings, org, "worker", "alerts.create", alert.id, details={"rule_id": rule.id})
                if rule.severity == "critical":
                    db.add(Notification(organization_id=org, title=rule.name, resource_id=alert.id))
            else:
                from datetime import UTC

                previous = (
                    alert.last_seen.replace(tzinfo=UTC) if alert.last_seen.tzinfo is None else alert.last_seen
                )
                alert.last_seen = max(previous, stamp)
                alert.revision += 1
                alert.explanation = explanation
                alert.entity_ids = list(set(alert.entity_ids) | {entity.id for entity in entities})
                if score > alert.risk_score:
                    alert.risk_score, alert.risk_factors = score, factors
            for event_id in explanation["event_ids"]:
                if not db.get(AlertEvent, (alert.id, event_id)):
                    db.add(AlertEvent(alert_id=alert.id, event_id=event_id))
                    alert.event_count += 1
            for entity in entities:
                entity.risk_score = max(entity.risk_score, score)
            if rule.id == "AEGIS-CORR-001":
                incident = db.scalar(select(Incident).where(Incident.correlation_key == correlation))
                if not incident:
                    incident = Incident(
                        id="INC-" + uid(),
                        organization_id=org,
                        title="Potential account compromise",
                        severity="critical",
                        correlation_key=correlation,
                    )
                    db.add(incident)
                    db.flush()
                    audit(db, settings, org, "worker", "incidents.create", incident.id)
                    db.add(Notification(organization_id=org, title=incident.title, resource_id=incident.id))
                related = db.scalars(
                    select(Alert).where(Alert.organization_id == org, Alert.correlation_key == correlation)
                )
                for related_alert in related:
                    if not db.get(IncidentAlert, (incident.id, related_alert.id)):
                        db.add(IncidentAlert(incident_id=incident.id, alert_id=related_alert.id))
        record.state, record.last_error = "PROCESSED", None
        if not db.get(SearchJob, record.id):
            db.add(SearchJob(event_id=record.id, organization_id=org))
        collector = collectors.get(event["collector"])
        if collector:
            collector.events_processed += 1
        db.flush()
