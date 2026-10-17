"""Tenant-owned observations and durable optional lookups, separate from curated IOC risk."""

import time

from fastapi import HTTPException
from sqlalchemy import func, or_, select, update

from aegis.db import (
    Alert,
    AlertEvent,
    Enrichment,
    EnrichmentHistory,
    EventRecord,
    Incident,
    IncidentAlert,
    Observable,
    ObservableEvent,
    Storyline,
    WindowState,
    as_dict,
    now,
    uid,
)
from aegis.intel_providers import PROVIDERS, ProviderResult
from aegis.investigation import owned
from aegis.observables import extract, normalize
from aegis.parsers import digest
from aegis.security import audit
from aegis.soar import lock_tenant

ACTIVE = {"QUEUED", "RUNNING"}


def observe(db, org, kind, value, event=None):
    kind, value, allowed = normalize(kind, value)
    key = digest([kind, value])
    row = db.scalar(
        select(Observable).where(Observable.organization_id == org, Observable.normalized_key == key)
    )
    if row is None:
        row = Observable(
            organization_id=org, type=kind, value=value, external_allowed=allowed, normalized_key=key
        )
        db.add(row)
        db.flush()
    row.last_seen = now()
    if event is not None:
        if event.organization_id != org:
            raise HTTPException(404, "Source does not exist")
        link = db.scalar(
            select(ObservableEvent.id).where(
                ObservableEvent.organization_id == org,
                ObservableEvent.observable_id == row.id,
                ObservableEvent.event_id == event.id,
            )
        )
        if link is None:
            db.add(ObservableEvent(organization_id=org, observable_id=row.id, event_id=event.id))
            db.flush()
    return row


def queue(db, settings, observable, provider, refresh=False):
    if provider not in PROVIDERS:
        raise HTTPException(422, "Unknown provider")
    org = observable.organization_id
    row = db.scalar(
        select(Enrichment).where(
            Enrichment.organization_id == org,
            Enrichment.observable_id == observable.id,
            Enrichment.provider == provider,
        )
    )
    if row:
        if row.status in ACTIVE:
            return row
        if row.enriched_at and time.time() < row.enriched_at + settings.intel_refresh_seconds:
            return row
        if not refresh and row.expires_at > time.time():
            return row
    count = db.scalar(
        select(func.count())
        .select_from(Enrichment)
        .where(Enrichment.organization_id == org, Enrichment.status.in_(ACTIVE))
    )
    if count >= settings.intel_queue_capacity:
        raise HTTPException(429, "Intelligence queue capacity reached")
    if row is None:
        row = Enrichment(organization_id=org, observable_id=observable.id, provider=provider)
        db.add(row)
    row.status, row.attempts, row.available_at = "QUEUED", 0, time.time()
    row.lease_token, row.lease_until = None, 0
    # Preserve old evidence in history, never expose it as the current assessment while refreshing.
    row.result = {}
    db.flush()
    return row


def result_view(row):
    stale = row.expires_at <= time.time()
    usable = not stale and row.status in {"COMPLETE", "UNKNOWN"}
    data = as_dict(row)
    data.pop("lease_token", None)
    data["stale"] = stale
    data["assessment"] = (
        row.result if usable else {"verdict": "unknown", "confidence": None, "reason": "not_current"}
    )
    return data


def context_for_values(db, org, values):
    keys = [digest([kind, value]) for kind, value, _ in values]
    if not keys:
        return []
    pairs = db.execute(
        select(Observable, Enrichment)
        .join(
            Enrichment,
            (Enrichment.observable_id == Observable.id)
            & (Enrichment.organization_id == Observable.organization_id),
        )
        .where(Observable.organization_id == org, Observable.normalized_key.in_(keys))
        .limit(64)
    )
    return [
        {
            "observable_id": obs.id,
            "type": obs.type,
            "value": obs.value,
            "provider": row.provider,
            "enrichment_id": row.id,
            "status": row.status,
            "expires_at": row.expires_at,
            **result_view(row)["assessment"],
        }
        for obs, row in pairs
    ]


def detection_context(db, org, event):
    """Explicit cache-only overlay. Does not alter curated IOC matches or risk weights."""
    results = context_for_values(db, org, extract(event))
    fresh = [r for r in results if r.get("assessment_origin") not in {None, "mock", "none"}]
    verdicts = {r["verdict"] for r in fresh}
    confidence = [r["confidence"] for r in fresh if r.get("confidence") is not None]
    return {
        "intel_verdict": next(
            (v for v in ("malicious", "suspicious", "undetected") if v in verdicts), "unknown"
        ),
        "intel_verdicts": sorted({r["verdict"] for r in fresh}) or ["unknown"],
        "intel_confidence": max(confidence) if confidence else None,
        "intel_enrichment_ids": [r["enrichment_id"] for r in fresh],
    }


def source_events(db, org, kind, identifier):
    model = {"event": EventRecord, "alert": Alert, "incident": Incident, "storyline": Storyline}[kind]
    source = owned(db, model, identifier, org)
    if kind == "event":
        return [source]
    if kind == "storyline":
        source = owned(db, Incident, source.incident_id, org)
    query = (
        select(EventRecord)
        .join(AlertEvent, AlertEvent.event_id == EventRecord.id)
        .join(Alert, Alert.id == AlertEvent.alert_id)
        .where(EventRecord.organization_id == org, Alert.organization_id == org)
    )
    if kind == "alert":
        query = query.where(Alert.id == identifier)
    else:
        query = query.join(IncidentAlert, IncidentAlert.alert_id == Alert.id).where(
            IncidentAlert.incident_id == source.id
        )
    records = list(db.scalars(query.distinct().order_by(EventRecord.id).limit(201)))
    if len(records) > 200:
        raise HTTPException(422, "Source exceeds 200-event enrichment bound")
    return records


def source_context(db, org, events):
    values = list(
        {(kind, value, allowed) for event in events for kind, value, allowed in extract(event.payload)}
    )[:200]
    return context_for_values(db, org, values)


def index_once(settings, sessions):
    """Independent post-detection extraction; failure never rolls back detection."""
    with sessions() as db:
        candidates = list(
            db.execute(
                select(EventRecord.id, EventRecord.organization_id)
                .where(EventRecord.state == "PROCESSED", EventRecord.intel_indexed.is_(False))
                .order_by(EventRecord.created_at)
                .limit(50)
            )
        )
    for identifier, org in candidates:
        with sessions.begin() as db:
            lock_tenant(db, org)
            event = owned(db, EventRecord, identifier, org)
            if event.intel_indexed:
                continue
            for kind, value, _ in extract(event.payload):
                obs = observe(db, org, kind, value, event)
                if settings.intel_auto_provider != "none":
                    try:
                        queue(db, settings, obs, settings.intel_auto_provider)
                    except HTTPException as exc:
                        if exc.status_code != 429:
                            raise
            event.intel_indexed = True
    return len(candidates)


def reserve_provider(db, settings, provider):
    # Existing transient-state table; shared API credential quota across ALL tenants/workers.
    dialect = db.get_bind().dialect.name
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    key = "intel-rate:" + provider
    statement = pg_insert(WindowState) if dialect == "postgresql" else sqlite_insert(WindowState)
    db.execute(statement.values(key=key, data=[], expires=0).on_conflict_do_nothing())
    interval = 60 / settings.intel_requests_per_minute if provider == "virustotal" else 0
    return (
        db.execute(
            update(WindowState)
            .where(WindowState.key == key, WindowState.expires <= time.time())
            .values(expires=time.time() + interval)
        ).rowcount
        == 1
    )


def lookup_once(settings, sessions):
    with sessions() as db:
        candidates = list(
            db.execute(
                select(Enrichment.id, Enrichment.organization_id)
                .where(
                    or_(
                        (Enrichment.status == "QUEUED") & (Enrichment.available_at <= time.time()),
                        (Enrichment.status == "RUNNING") & (Enrichment.lease_until <= time.time()),
                    )
                )
                .order_by(Enrichment.available_at, Enrichment.created_at)
                .limit(10)
            )
        )
    completed = 0
    for identifier, org in candidates:
        token = uid()
        with sessions.begin() as db:
            lock_tenant(db, org)
            row = owned(db, Enrichment, identifier, org)
            if (
                row.status not in ACTIVE
                or (row.status == "RUNNING" and row.lease_until > time.time())
                or row.available_at > time.time()
            ):
                continue
            if not reserve_provider(db, settings, row.provider):
                continue
            row.attempts += 1
            row.status, row.lease_token, row.lease_until = "RUNNING", token, time.time() + 180
            observable = owned(db, Observable, row.observable_id, org)
            provider, attempts = row.provider, row.attempts
        # No database transaction or tenant lock spans network I/O.
        try:
            result = (
                ProviderResult(status="FAILED", reason="retry_budget_exhausted")
                if attempts > 3
                else PROVIDERS[provider].lookup(settings, observable)
            )
        except Exception:
            result = ProviderResult(status="FAILED", reason="provider_error", retryable=True)
        with sessions.begin() as db:
            lock_tenant(db, org)
            row = owned(db, Enrichment, identifier, org)
            if row.lease_token != token or row.status != "RUNNING" or row.lease_until < time.time():
                continue
            stamp = time.time()
            row.result = result.model_dump()
            db.add(
                EnrichmentHistory(
                    organization_id=org, enrichment_id=row.id, status=result.status, result=row.result
                )
            )
            row.enriched_at, row.lease_until, row.lease_token = stamp, 0, None
            row.status = "QUEUED" if result.retryable and attempts < 3 else result.status
            row.available_at = stamp + min(60, 2**attempts)
            row.expires_at = stamp + (
                settings.intel_cache_seconds
                if result.status in {"COMPLETE", "UNKNOWN"}
                else settings.intel_failure_cache_seconds
            )
            audit(
                db,
                settings,
                org,
                "intel-worker",
                "iocs.enrichment_completed",
                row.id,
                result=result.status.lower(),
                details={"provider": provider, "attempt": attempts, "reason": result.reason},
            )
            completed += 1
    return completed


def related(db, org, observable_id):
    owned(db, Observable, observable_id, org)
    event_ids = select(ObservableEvent.event_id).where(
        ObservableEvent.organization_id == org, ObservableEvent.observable_id == observable_id
    )
    alert_ids = (
        select(AlertEvent.alert_id)
        .join(Alert, Alert.id == AlertEvent.alert_id)
        .where(Alert.organization_id == org, AlertEvent.event_id.in_(event_ids))
    )
    incident_ids = (
        select(IncidentAlert.incident_id)
        .join(Incident, Incident.id == IncidentAlert.incident_id)
        .where(Incident.organization_id == org, IncidentAlert.alert_id.in_(alert_ids))
    )
    return {
        "events": [
            r.id
            for r in db.scalars(
                select(EventRecord)
                .where(EventRecord.organization_id == org, EventRecord.id.in_(event_ids))
                .limit(100)
            )
        ],
        "alerts": [
            r.id
            for r in db.scalars(
                select(Alert).where(Alert.organization_id == org, Alert.id.in_(alert_ids)).limit(100)
            )
        ],
        "incidents": [
            r.id
            for r in db.scalars(
                select(Incident)
                .where(Incident.organization_id == org, Incident.id.in_(incident_ids))
                .limit(100)
            )
        ],
        "storylines": [
            r.id
            for r in db.scalars(
                select(Storyline)
                .where(Storyline.organization_id == org, Storyline.incident_id.in_(incident_ids))
                .limit(100)
            )
        ],
    }
