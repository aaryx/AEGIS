"""Bounded, anchor-based correlation of persisted production alerts.

Membership is append-only: late evidence never silently merges analyst cases.
All mutations participate in the caller's transaction.
"""

from datetime import UTC
from ipaddress import ip_address

from fastapi import HTTPException
from sqlalchemy import select, text

from aegis.db import Alert, Entity, Incident, IncidentAlert, Storyline, StorylineMember, as_dict
from aegis.parsers import digest
from aegis.security import audit

SEVERITY = {"low": 20, "medium": 40, "high": 70, "critical": 90}
MAX_ALERTS = 5000


def stamp(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def signals(alert, entities):
    result = set()
    for identifier in alert.entity_ids if isinstance(alert.entity_ids, list) else []:
        if not isinstance(identifier, str):
            continue
        entity = entities.get(identifier)
        if not entity or entity.type not in {"host", "user", "ip"}:
            continue
        value = entity.value.strip()
        if not value or value.lower() in {"unknown", "none", "null", "-", "n/a"}:
            continue
        if entity.type == "ip":
            try:
                address = ip_address(value)
                if address.is_unspecified or address.is_multicast:
                    continue
                value = str(address)
            except ValueError:
                continue
        result.add((entity.type, value))
    return result


def reasons(left, right, entities, window):
    distance = abs((stamp(left.first_seen) - stamp(right.first_seen)).total_seconds())
    if distance > window:
        return []
    shared = sorted(signals(left, entities) & signals(right, entities))
    return [
        {
            "type": kind,
            "value": value,
            "anchor_alert_id": left.id,
            "distance_seconds": distance,
            "window_seconds": window,
        }
        for kind, value in shared
    ]


def summarize(alerts, memberships):
    ordered = sorted(alerts, key=lambda a: (stamp(a.first_seen), a.id))
    types = {r["type"] for m in memberships for r in m.reasons}
    rule_count = len({a.rule_id for a in alerts})
    techniques = sorted({t for a in alerts for t in a.mitre_techniques})
    severity = max((a.severity for a in alerts), key=lambda s: SEVERITY.get(s, 0))
    factors = {
        "severity": SEVERITY.get(severity, 0),
        "corroborating_identity_types": min(10, max(0, len(types) - 1) * 5),
        "distinct_rules": min(10, max(0, rule_count - 1) * 2),
    }
    # Confidence is a heuristic evidence-strength score, never a probability.
    confidence = min(95, 35 + len(types) * 15 + min(15, max(0, rule_count - 1) * 5))
    return {
        "first_seen": stamp(ordered[0].first_seen).isoformat(),
        "last_seen": max(stamp(a.last_seen) for a in alerts).isoformat(),
        "alert_count": len(alerts),
        "severity": severity,
        "confidence": confidence,
        "risk_score": min(100, sum(factors.values())),
        "risk_factors": factors,
        "mitre_techniques": techniques,
        "timeline": [
            {
                "alert_id": a.id,
                "timestamp": stamp(a.first_seen).isoformat(),
                "rule_id": a.rule_id,
                "rule_name": a.title,
                "severity": a.severity,
                "mitre_techniques": a.mitre_techniques,
            }
            for a in ordered
        ],
    }


def correlate(db, settings, principal, window_seconds):
    org = principal.organization_id
    # A separate transaction lock avoids reversing audit's AuditHead -> Organization
    # lock order. Never lock Organization before writing an audit entry.
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": int(digest(["storyline-v1", org])[:15], 16)}
        )
    alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.organization_id == org)
            .order_by(Alert.first_seen, Alert.id)
            .limit(MAX_ALERTS + 1)
        )
    )
    if len(alerts) > MAX_ALERTS:
        raise HTTPException(422, "Correlation supports at most 5000 retained alerts per tenant")
    by_id = {a.id: a for a in alerts}
    entity_ids = {
        i
        for a in alerts
        for i in (a.entity_ids if isinstance(a.entity_ids, list) else [])
        if isinstance(i, str)
    }
    entities = {
        e.id: e
        for e in db.scalars(select(Entity).where(Entity.organization_id == org, Entity.id.in_(entity_ids)))
    }
    stories = list(
        db.scalars(
            select(Storyline)
            .where(Storyline.organization_id == org)
            .order_by(Storyline.created_at, Storyline.id)
        )
    )
    members = list(db.scalars(select(StorylineMember).where(StorylineMember.organization_id == org)))
    assigned = {m.alert_id for m in members}
    incidents = {
        i.id: i
        for i in db.scalars(
            select(Incident)
            .where(
                Incident.organization_id == org,
                Incident.id.in_([s.incident_id for s in stories]),
            )
            .order_by(Incident.id)
            .with_for_update()
        )
    }
    pending: list[Alert] = []
    changed = set()
    for alert in alerts:
        if alert.id in assigned:
            continue
        chosen, explanation = None, []
        for story in stories:
            incident = incidents.get(story.incident_id)
            if not incident or incident.status in {"RESOLVED", "CLOSED"}:
                continue
            anchor = by_id.get(story.anchor_alert_id)
            if not anchor:
                continue
            explanation = reasons(anchor, alert, entities, story.window_seconds)
            if explanation:
                chosen = story
                break
        if chosen is None:
            for anchor in pending:
                explanation = reasons(anchor, alert, entities, window_seconds)
                if explanation:
                    key = digest([org, "storyline-v1", anchor.id])
                    incident = Incident(
                        id="INC-" + key,
                        organization_id=org,
                        title="Attack storyline: " + anchor.title[:240],
                        severity=anchor.severity,
                    )
                    db.add(incident)
                    db.flush()
                    chosen = Storyline(
                        id="STL-" + key,
                        organization_id=org,
                        incident_id=incident.id,
                        anchor_alert_id=anchor.id,
                        window_seconds=window_seconds,
                    )
                    db.add(chosen)
                    db.flush()
                    stories.append(chosen)
                    incidents[incident.id] = incident
                    anchor_member = StorylineMember(
                        organization_id=org, storyline_id=chosen.id, alert_id=anchor.id, reasons=[]
                    )
                    db.add(anchor_member)
                    members.append(anchor_member)
                    db.add(IncidentAlert(incident_id=incident.id, alert_id=anchor.id))
                    assigned.add(anchor.id)
                    pending.remove(anchor)
                    audit(
                        db,
                        settings,
                        org,
                        principal.user.id,
                        "incidents.create",
                        incident.id,
                        details={"storyline_id": chosen.id},
                    )
                    break
        if chosen is None:
            pending.append(alert)
            continue
        member = StorylineMember(
            organization_id=org, storyline_id=chosen.id, alert_id=alert.id, reasons=explanation
        )
        db.add(member)
        members.append(member)
        assigned.add(alert.id)
        db.add(IncidentAlert(incident_id=chosen.incident_id, alert_id=alert.id))
        changed.add(chosen.id)
    for story in stories:
        group = [m for m in members if m.storyline_id == story.id and m.alert_id in by_id]
        if not group:
            continue
        summary = summarize([by_id[m.alert_id] for m in group], group)
        if story.summary != summary:
            changed.add(story.id)
            story.summary = summary
            incident = incidents.get(story.incident_id)
            if incident:
                incident.severity = summary["severity"]
                incident.priority = 1 if summary["risk_score"] >= 80 else 2 if summary["risk_score"] >= 50 else 3
                incident.revision += 1
                audit(
                    db,
                    settings,
                    org,
                    principal.user.id,
                    "storylines.correlate",
                    incident.id,
                    details={
                        "storyline_id": story.id,
                        "alert_count": len(group),
                        "window_seconds": story.window_seconds,
                    },
                )
    db.flush()
    return {
        "changed": len(changed),
        "storylines": len(stories),
        "unassigned_alerts": len(alerts) - len(assigned),
    }


def detail(db, org, story):
    from aegis.investigation import investigate

    result = as_dict(story)
    result["members"] = [
        as_dict(m)
        for m in db.scalars(
            select(StorylineMember)
            .where(StorylineMember.organization_id == org, StorylineMember.storyline_id == story.id)
            .order_by(StorylineMember.alert_id)
        )
    ]
    result["investigation"] = investigate(db, org, story.incident_id)
    return result
