"""Authenticated UEBA operations; all evidence joins are tenant scoped."""

from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import aliased

from aegis.db import (
    Alert,
    AlertEvent,
    BehaviorEvidence,
    BehaviorFinding,
    BehaviorJob,
    BehaviorProfile,
    EventRecord,
    Incident,
    IncidentAlert,
    Storyline,
    as_dict,
    now,
)
from aegis.investigation import owned
from aegis.schemas import StrictModel
from aegis.security import audit, db_session, require, require_evidence_scope
from aegis.soar import lock_tenant
from aegis.ueba import DETECTORS, VERSION, config, key

router = APIRouter(prefix="/api/v1/ueba", tags=["ueba"])


class Analysis(StrictModel):
    window_end: datetime
    refresh_only: bool = False

    @field_validator("window_end")
    @classmethod
    def bounded(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timezone required")
        value = value.astimezone(UTC)
        if value != value.replace(hour=0, minute=0, second=0, microsecond=0):
            raise ValueError("Use UTC midnight at the end of the observation day")
        if not now() - timedelta(days=90) <= value <= now():
            raise ValueError("Window must be completed and within the past 90 days")
        return value


class Decision(StrictModel):
    status: Literal["ACKNOWLEDGED", "RESOLVED", "SUPPRESSED", "NEW"]
    reason: str = Field(min_length=3, max_length=500)


def evidence_access(principal):
    require_evidence_scope(principal)


def require_queue_capacity(db, org):
    # Call while holding the tenant lock, including when retrying FAILED jobs.
    pending = db.scalar(
        select(func.count())
        .select_from(BehaviorJob)
        .where(BehaviorJob.organization_id == org, BehaviorJob.state.in_(["PENDING", "RETRY"]))
    )
    if pending >= 10:
        raise HTTPException(429, "Tenant analysis queue is full")


@router.get("/detectors")
def detectors(request: Request, principal=Depends(require("ueba.read"))):
    return {
        "items": [{"id": k, "version": VERSION, "enabled": True, **v} for k, v in DETECTORS.items()],
        "config": config(request.app.state.settings),
        "scheduling": "explicit bounded jobs",
        "risk_formula": "impact * (0.5 + 0.5*confidence) * (0.5 + 0.5*min(1,deviation/6)); round, clamp 0..100",
    }


@router.post("/analyze", status_code=202)
def submit(
    data: Analysis, request: Request, principal=Depends(require("ueba.execute")), db=Depends(db_session)
):
    evidence_access(principal)
    org = principal.organization_id
    lock_tenant(db, org)
    identifier = key(org, data.window_end.isoformat(), data.refresh_only)
    job = db.scalar(
        select(BehaviorJob).where(BehaviorJob.organization_id == org, BehaviorJob.id == identifier)
    )
    if job:
        return as_dict(job)
    require_queue_capacity(db, org)
    job = BehaviorJob(
        id=identifier,
        organization_id=org,
        window_end=data.window_end,
        refresh_only=data.refresh_only,
        config=config(request.app.state.settings),
    )
    db.add(job)
    audit(
        db,
        request.app.state.settings,
        org,
        principal.user.id,
        "ueba.analysis_requested",
        identifier,
        details=data.model_dump(mode="json"),
    )
    db.commit()
    return as_dict(job)


@router.get("/jobs")
def jobs(principal=Depends(require("ueba.read")), db=Depends(db_session)):
    evidence_access(principal)
    return {
        "items": [
            as_dict(r)
            for r in db.scalars(
                select(BehaviorJob)
                .where(BehaviorJob.organization_id == principal.organization_id)
                .order_by(BehaviorJob.created_at.desc())
                .limit(50)
            )
        ]
    }


@router.get("/jobs/{identifier}")
def job(identifier: str, principal=Depends(require("ueba.read")), db=Depends(db_session)):
    evidence_access(principal)
    return as_dict(owned(db, BehaviorJob, identifier, principal.organization_id))


@router.get("/profiles")
def profiles(
    entity: str = Query("", max_length=254),
    offset: int = Query(0, ge=0, le=100000),
    limit: int = Query(50, ge=1, le=100),
    principal=Depends(require("ueba.read")),
    db=Depends(db_session),
):
    evidence_access(principal)
    query = select(BehaviorProfile).where(BehaviorProfile.organization_id == principal.organization_id)
    if entity:
        query = query.where(BehaviorProfile.entity.contains(entity, autoescape=True))
    return {
        "items": [
            as_dict(r)
            for r in db.scalars(
                query.order_by(BehaviorProfile.risk_score.desc(), BehaviorProfile.id)
                .offset(offset)
                .limit(limit)
            )
        ]
    }


@router.post("/jobs/{identifier}/retry")
def retry_job(
    identifier: str, request: Request, principal=Depends(require("ueba.execute")), db=Depends(db_session)
):
    evidence_access(principal)
    org = principal.organization_id
    lock_tenant(db, org)
    row = owned(db, BehaviorJob, identifier, org)
    if row.state != "FAILED":
        raise HTTPException(409, "Only failed jobs can be retried")
    require_queue_capacity(db, org)
    row.state, row.attempts, row.available_at = "PENDING", 0, 0
    row.config = config(request.app.state.settings)
    audit(
        db,
        request.app.state.settings,
        org,
        principal.user.id,
        "ueba.job_retried",
        identifier,
        details={"config": row.config},
    )
    db.commit()
    return as_dict(row)


@router.get("/profiles/{identifier}")
def profile(identifier: str, principal=Depends(require("ueba.read")), db=Depends(db_session)):
    evidence_access(principal)
    org = principal.organization_id
    row = owned(db, BehaviorProfile, identifier, org)
    history = db.execute(
        select(BehaviorFinding.window_end, func.max(BehaviorFinding.risk_score))
        .where(BehaviorFinding.organization_id == org, BehaviorFinding.profile_id == identifier)
        .group_by(BehaviorFinding.window_end)
        .order_by(BehaviorFinding.window_end.desc())
        .limit(90)
    )
    return {
        **as_dict(row),
        "risk_history": [{"window_end": end, "risk_score": risk} for end, risk in history],
        "history_scope": "maximum finding priority per observation day; days without findings omitted",
    }


@router.get("/findings")
def findings(
    entity: str = Query("", max_length=254),
    detector: str = Query("", max_length=60),
    status: Literal["NEW", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"] | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    offset: int = Query(0, ge=0, le=100000),
    limit: int = Query(50, ge=1, le=100),
    principal=Depends(require("ueba.read")),
    db=Depends(db_session),
):
    evidence_access(principal)
    org = principal.organization_id
    previous = aliased(BehaviorFinding)
    repeated = (
        select(previous.id)
        .where(
            previous.organization_id == org,
            previous.profile_id == BehaviorFinding.profile_id,
            previous.detector == BehaviorFinding.detector,
            previous.window_end < BehaviorFinding.window_end,
        )
        .exists()
    )
    query = (
        select(BehaviorFinding, BehaviorProfile, repeated)
        .join(
            BehaviorProfile,
            (BehaviorProfile.id == BehaviorFinding.profile_id) & (BehaviorProfile.organization_id == org),
        )
        .where(BehaviorFinding.organization_id == org)
    )
    if entity:
        query = query.where(BehaviorProfile.entity.contains(entity, autoescape=True))
    for field, value in [
        (BehaviorFinding.detector, detector),
        (BehaviorFinding.status, status),
        (BehaviorFinding.severity, severity),
    ]:
        if value:
            query = query.where(field == value)
    if since:
        query = query.where(BehaviorFinding.last_seen >= since)
    if until:
        query = query.where(BehaviorFinding.first_seen <= until)
    return {
        "items": [
            {**as_dict(f), "entity": p.entity, "entity_type": p.entity_type, "repeated": repeat}
            for f, p, repeat in db.execute(
                query.order_by(
                    BehaviorFinding.window_end.desc(), BehaviorFinding.risk_score.desc(), BehaviorFinding.id
                )
                .offset(offset)
                .limit(limit)
            )
        ]
    }


def related(db, org, identifier):
    ids = select(BehaviorEvidence.event_id).where(
        BehaviorEvidence.organization_id == org, BehaviorEvidence.finding_id == identifier
    )
    alerts = (
        select(Alert.id)
        .join(AlertEvent, AlertEvent.alert_id == Alert.id)
        .where(Alert.organization_id == org, AlertEvent.event_id.in_(ids))
    )
    incidents = (
        select(Incident.id)
        .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
        .where(Incident.organization_id == org, IncidentAlert.alert_id.in_(alerts))
    )
    return {
        "alerts": list(db.scalars(alerts.distinct().limit(100))),
        "incidents": list(db.scalars(incidents.distinct().limit(100))),
        "storylines": list(
            db.scalars(
                select(Storyline.id)
                .where(Storyline.organization_id == org, Storyline.incident_id.in_(incidents))
                .limit(100)
            )
        ),
    }


@router.get("/findings/{identifier}")
def finding(
    identifier: str,
    offset: int = Query(0, ge=0, le=50000),
    limit: int = Query(50, ge=1, le=100),
    principal=Depends(require("ueba.read")),
    db=Depends(db_session),
):
    evidence_access(principal)
    org = principal.organization_id
    row = owned(db, BehaviorFinding, identifier, org)
    refs = list(
        db.scalars(
            select(BehaviorEvidence)
            .where(BehaviorEvidence.organization_id == org, BehaviorEvidence.finding_id == identifier)
            .order_by(BehaviorEvidence.event_id)
            .offset(offset)
            .limit(limit)
        )
    )
    available = set(
        db.scalars(
            select(EventRecord.id).where(
                EventRecord.organization_id == org, EventRecord.id.in_([r.event_id for r in refs])
            )
        )
    )
    prior = db.scalar(
        select(func.count())
        .select_from(BehaviorFinding)
        .where(
            BehaviorFinding.organization_id == org,
            BehaviorFinding.profile_id == row.profile_id,
            BehaviorFinding.detector == row.detector,
            BehaviorFinding.window_end < row.window_end,
        )
    )
    return {
        **as_dict(row),
        "evidence": [
            {"event_id": r.event_id, "evidence_hash": r.evidence_hash, "available": r.event_id in available}
            for r in refs
        ],
        "related": related(db, org, identifier),
        "repeated": bool(prior),
        "prior_occurrences": prior,
        "recommendation": "Review authentication logs and related investigations before considering an approved SOAR playbook.",
    }


@router.post("/findings/{identifier}/status")
def decision(
    identifier: str,
    data: Decision,
    request: Request,
    principal=Depends(require("ueba.update")),
    db=Depends(db_session),
):
    evidence_access(principal)
    org = principal.organization_id
    lock_tenant(db, org)
    row = owned(db, BehaviorFinding, identifier, org)
    if row.status != data.status:
        if len(row.lifecycle) >= 100:
            raise HTTPException(409, "Lifecycle history bound reached")
        row.status = data.status
        row.lifecycle = [
            *row.lifecycle,
            {
                "status": data.status,
                "reason": data.reason,
                "actor": principal.user.id,
                "at": now().isoformat(),
            },
        ]
        audit(
            db,
            request.app.state.settings,
            org,
            principal.user.id,
            "ueba.status_changed",
            identifier,
            details=data.model_dump(),
        )
        db.commit()
    return as_dict(row)


@router.get("/summary")
def summary(principal=Depends(require("ueba.read")), db=Depends(db_session)):
    evidence_access(principal)
    org = principal.organization_id
    distribution = db.execute(
        select(BehaviorFinding.severity, func.count())
        .where(BehaviorFinding.organization_id == org, BehaviorFinding.status.in_(["NEW", "ACKNOWLEDGED"]))
        .group_by(BehaviorFinding.severity)
    )
    return {
        "active_findings_by_severity": dict(distribution.all()),
        "profiles": db.scalar(
            select(func.count()).select_from(BehaviorProfile).where(BehaviorProfile.organization_id == org)
        ),
    }


@router.get("/context/{kind}/{identifier}")
def context(
    kind: Literal["event", "alert", "incident", "storyline"],
    identifier: str,
    principal=Depends(require("ueba.read")),
    db=Depends(db_session),
):
    evidence_access(principal)
    org = principal.organization_id
    source = owned(
        db,
        {"event": EventRecord, "alert": Alert, "incident": Incident, "storyline": Storyline}[kind],
        identifier,
        org,
    )
    events = select(EventRecord.id).where(EventRecord.organization_id == org)
    if kind == "event":
        events = events.where(EventRecord.id == identifier)
    else:
        events = (
            events.join(AlertEvent, AlertEvent.event_id == EventRecord.id)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(Alert.organization_id == org)
        )
        if kind == "alert":
            events = events.where(Alert.id == identifier)
        else:
            incident_id = source.incident_id if kind == "storyline" else identifier
            owned(db, Incident, incident_id, org)
            events = events.join(IncidentAlert, IncidentAlert.alert_id == Alert.id).where(
                IncidentAlert.incident_id == incident_id
            )
    ids = select(BehaviorEvidence.finding_id).where(
        BehaviorEvidence.organization_id == org, BehaviorEvidence.event_id.in_(events)
    )
    return {
        "items": [
            as_dict(r)
            for r in db.scalars(
                select(BehaviorFinding)
                .where(BehaviorFinding.organization_id == org, BehaviorFinding.id.in_(ids))
                .order_by(BehaviorFinding.risk_score.desc(), BehaviorFinding.id)
                .limit(100)
            )
        ]
    }
