import html
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import or_, select

from aegis.db import (
    IOC,
    Alert,
    AlertEvent,
    AuditLog,
    CaseNote,
    Entity,
    EntityRelationship,
    EventRecord,
    Incident,
    IncidentAlert,
    IOCMatch,
    Report,
    as_dict,
    uid,
)
from aegis.parsers import digest
from aegis.security import audit


def owned(db, model, resource_id, organization_id):
    row = db.scalar(select(model).where(model.id == resource_id, model.organization_id == organization_id))
    if not row:
        raise HTTPException(404, "Resource does not exist")
    return row


def investigate(db, organization_id, resource_id):
    from aegis.intelligence import source_context
    if resource_id.startswith("ALT-"):
        resource = owned(db, Alert, resource_id, organization_id)
        alerts = [resource]
        incidents = list(
            db.scalars(
                select(Incident)
                .join(IncidentAlert)
                .where(IncidentAlert.alert_id == resource.id, Incident.organization_id == organization_id)
            )
        )
        kind = "alerts"
    else:
        resource = owned(db, Incident, resource_id, organization_id)
        alerts = list(
            db.scalars(
                select(Alert)
                .join(IncidentAlert)
                .where(IncidentAlert.incident_id == resource.id, Alert.organization_id == organization_id)
            )
        )
        incidents = [resource]
        kind = "incidents"
    alert_ids = [alert.id for alert in alerts]
    event_query = select(EventRecord).where(
        EventRecord.id.in_(select(AlertEvent.event_id).where(AlertEvent.alert_id.in_(alert_ids))),
        EventRecord.organization_id == organization_id,
    )
    events = list(db.scalars(event_query.order_by(EventRecord.timestamp, EventRecord.id).limit(500)))
    entity_ids = list({entity for alert in alerts for entity in alert.entity_ids})
    entities = list(
        db.scalars(select(Entity).where(Entity.id.in_(entity_ids), Entity.organization_id == organization_id))
    )
    relationships = list(
        db.scalars(
            select(EntityRelationship)
            .where(
                EntityRelationship.organization_id == organization_id,
                EntityRelationship.source_id.in_(entity_ids),
                EntityRelationship.target_id.in_(entity_ids),
            )
            .limit(500)
        )
    )
    iocs = list(
        db.scalars(
            select(IOC).where(
                IOC.id.in_(
                    select(IOCMatch.ioc_id).where(IOCMatch.event_id.in_([event.id for event in events]))
                ),
                IOC.organization_id == organization_id,
            )
        )
    )
    related = list(
        db.scalars(
            select(Alert)
            .where(
                Alert.organization_id == organization_id,
                Alert.correlation_key.in_([alert.correlation_key for alert in alerts]),
                Alert.id.not_in(alert_ids),
            )
            .limit(100)
        )
    )
    notes = list(
        db.scalars(
            select(CaseNote)
            .where(CaseNote.organization_id == organization_id, CaseNote.resource_id == resource_id)
            .order_by(CaseNote.created_at)
            .limit(200)
        )
    )
    activity = list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == organization_id, AuditLog.resource_id == resource_id)
            .order_by(AuditLog.created_at)
            .limit(200)
        )
    )
    return {
        "resource": as_dict(resource),
        "kind": kind,
        "alerts": [as_dict(alert) for alert in alerts],
        "incidents": [as_dict(item) for item in incidents],
        "evidence": [{"hash": item.evidence_hash, "event": item.payload} for item in events],
        "evidence_limit": 500,
        "entities": [as_dict(entity) for entity in entities],
        "relationships": [as_dict(item) for item in relationships],
        "related_alerts": [as_dict(item) for item in related],
        "iocs": [as_dict(ioc) for ioc in iocs],
        "intelligence": source_context(db, organization_id, events),
        "mitre_techniques": sorted({t for alert in alerts for t in alert.mitre_techniques}),
        "notes": [as_dict(note) for note in notes],
        "activity": [as_dict(item) for item in activity],
    }


def entity_detail(db, org, entity_id):
    entity = owned(db, Entity, entity_id, org)
    relationships = list(
        db.scalars(
            select(EntityRelationship)
            .where(
                EntityRelationship.organization_id == org,
                or_(EntityRelationship.source_id == entity_id, EntityRelationship.target_id == entity_id),
            )
            .limit(200)
        )
    )
    ids = {item.source_id for item in relationships} | {item.target_id for item in relationships}
    related = list(db.scalars(select(Entity).where(Entity.organization_id == org, Entity.id.in_(ids))))
    events = list(
        db.scalars(
            select(EventRecord)
            .where(
                EventRecord.organization_id == org,
                EventRecord.id.in_({item.event_id for item in relationships}),
            )
            .order_by(EventRecord.timestamp.desc())
            .limit(100)
        )
    )
    return {
        "resource": as_dict(entity),
        "entities": [as_dict(item) for item in related],
        "relationships": [as_dict(item) for item in relationships],
        "events": [event.payload for event in events],
    }


def create_report(db, settings, principal, incident_id, request=None):
    investigation = investigate(db, principal.organization_id, incident_id)
    incident = investigation["resource"]
    if investigation["kind"] != "incidents":
        raise HTTPException(422, "Reports require an incident")
    report_id = "RPT-" + uid()
    content = {
        "report_id": report_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "generated_by": principal.user.id,
        "incident_id": incident_id,
        "executive_summary": f"{incident['title']}: {len(investigation['alerts'])} associated alerts; status {incident['status']}.",
        "incident_details": incident,
        "timeline": [
            {
                "timestamp": item["event"]["timestamp"],
                "event_id": item["event"]["event_id"],
                "message": item["event"]["message"],
            }
            for item in investigation["evidence"]
        ],
        "affected_assets": investigation["entities"],
        "evidence": investigation["evidence"],
        "alerts": investigation["alerts"],
        "mitre_mapping": investigation["mitre_techniques"],
        "indicators": investigation["iocs"],
        "risk_assessment": [
            {"alert_id": alert["id"], "score": alert["risk_score"], "factors": alert["risk_factors"]}
            for alert in investigation["alerts"]
        ],
        "investigation_findings": investigation["notes"],
        "actions_taken": investigation["activity"],
        "recommendations": sorted(
            {
                action
                for alert in investigation["alerts"]
                for action in alert["explanation"].get("recommended_actions", [])
            }
        ),
        "evidence_scope": {
            "event_ids": [item["event"]["event_id"] for item in investigation["evidence"]],
            "maximum_events": 500,
        },
    }
    report = Report(
        id=report_id,
        organization_id=principal.organization_id,
        incident_id=incident_id,
        generated_by=principal.user.id,
        content=content,
        content_hash=digest(content),
    )
    db.add(report)
    audit(
        db,
        settings,
        principal.organization_id,
        principal.user.id,
        "reports.create",
        report_id,
        request=request,
    )
    return as_dict(report)


def report_html(report):
    import json

    sections = "".join(
        f"<section><h2>{html.escape(key.replace('_', ' ').title())}</h2><pre>{html.escape(json.dumps(value, indent=2, ensure_ascii=False) if not isinstance(value, str) else value)}</pre></section>"
        for key, value in report.content.items()
    )
    return f'<!doctype html><html lang="en"><meta charset="utf-8"><title>AEGIS {html.escape(report.id)}</title><style>body{{font:15px system-ui;max-width:1000px;margin:40px auto;padding:20px;color:#16202c}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}h2{{border-bottom:1px solid #ccd}}@media print{{section{{break-inside:avoid}}}}</style><h1>AEGIS Incident Report</h1><p>SHA-256: {report.content_hash}</p>{sections}</html>'
