"""Intelligence operations extend the existing IOC API namespace."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field
from sqlalchemy import select

from aegis.db import IOC, Enrichment, EnrichmentHistory, Observable, as_dict
from aegis.intelligence import observe, queue, related, result_view, source_context, source_events
from aegis.investigation import owned
from aegis.observables import ObservableInput, extract
from aegis.schemas import StrictModel
from aegis.security import audit, db_session, require, require_evidence_scope
from aegis.soar import lock_tenant

router = APIRouter(prefix="/api/v1/iocs", tags=["intelligence"])


class Lookup(StrictModel):
    observable: ObservableInput
    provider: Literal["mock", "virustotal"] = "virustotal"
    refresh: bool = False


class Batch(StrictModel):
    observables: list[ObservableInput] = Field(min_length=1, max_length=50)
    provider: Literal["mock", "virustotal"] = "virustotal"
    refresh: bool = False


class Source(StrictModel):
    source_type: Literal["event", "alert", "incident", "storyline"]
    source_id: str = Field(min_length=1, max_length=80)
    provider: Literal["mock", "virustotal"] = "virustotal"
    refresh: bool = False


def submit(db, settings, principal, inputs, provider, refresh):
    lock_tenant(db, principal.organization_id)
    items = []
    for value in inputs:
        obs = observe(db, principal.organization_id, value.type, value.value)
        lookup = queue(db, settings, obs, provider, refresh)
        items.append({"observable": as_dict(obs), "lookup": result_view(lookup)})
    audit(
        db,
        settings,
        principal.organization_id,
        principal.user.id,
        "iocs.enrich_requested",
        details={"provider": provider, "count": len(items), "refresh": refresh},
    )
    db.commit()
    return {"items": items}


@router.post("/enrich")
def enrich(data: Lookup, request: Request, principal=Depends(require("iocs.write")), db=Depends(db_session)):
    return submit(db, request.app.state.settings, principal, [data.observable], data.provider, data.refresh)[
        "items"
    ][0]


@router.post("/enrich-batch")
def batch(data: Batch, request: Request, principal=Depends(require("iocs.write")), db=Depends(db_session)):
    return submit(db, request.app.state.settings, principal, data.observables, data.provider, data.refresh)


@router.post("/enrich-source")
def enrich_source(
    data: Source, request: Request, principal=Depends(require("iocs.write")), db=Depends(db_session)
):
    require_evidence_scope(principal)
    org = principal.organization_id
    lock_tenant(db, org)
    events = source_events(db, org, data.source_type, data.source_id)
    values = {(k, v) for event in events for k, v, _ in extract(event.payload)}
    if len(values) > 50:
        raise HTTPException(422, "Source exceeds 50-observable batch bound")
    observations = {}
    for event in events:
        for k, v, _ in extract(event.payload):
            obs = observe(db, org, k, v, event)
            observations[obs.id] = obs
    items = [
        {
            "observable": as_dict(obs),
            "lookup": result_view(queue(db, request.app.state.settings, obs, data.provider, data.refresh)),
        }
        for obs in observations.values()
    ]
    audit(
        db,
        request.app.state.settings,
        org,
        principal.user.id,
        "iocs.enrich_source",
        data.source_id,
        details={"source_type": data.source_type, "count": len(items), "provider": data.provider},
    )
    db.commit()
    return {"items": items}


@router.get("/source-context/{kind}/{identifier}")
def context(
    kind: Literal["event", "alert", "incident", "storyline"],
    identifier: str,
    principal=Depends(require("iocs.read")),
    db=Depends(db_session),
):
    require_evidence_scope(principal)
    return {
        "items": source_context(
            db, principal.organization_id, source_events(db, principal.organization_id, kind, identifier)
        )
    }


@router.get("/providers")
def providers(request: Request, principal=Depends(require("iocs.read")), db=Depends(db_session)):
    settings = request.app.state.settings
    items = []
    for name, enabled, configured in [
        ("mock", settings.intel_mock_enabled, settings.intel_mock_enabled),
        ("virustotal", settings.intel_vt_enabled, bool(settings.intel_vt_api_key.get_secret_value())),
    ]:
        last = db.scalar(
            select(Enrichment)
            .where(
                Enrichment.organization_id == principal.organization_id,
                Enrichment.provider == name,
                Enrichment.enriched_at.is_not(None),
            )
            .order_by(Enrichment.enriched_at.desc())
            .limit(1)
        )
        items.append(
            {
                "provider": name,
                "enabled": enabled,
                "configured": configured,
                "last_status": last.status if last else "NOT_CHECKED",
                "last_checked": last.enriched_at if last else None,
                "health_scope": "last tenant lookup; not a live health probe",
            }
        )
    return {"items": items}


@router.get("/observables")
def observables(
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    principal=Depends(require("iocs.read")),
    db=Depends(db_session),
):
    query = select(Observable).where(Observable.organization_id == principal.organization_id)
    if q:
        query = query.where(Observable.value.contains(q, autoescape=True))
    return {
        "items": [
            as_dict(r)
            for r in db.scalars(
                query.order_by(Observable.last_seen.desc(), Observable.id).offset(offset).limit(limit)
            )
        ]
    }


@router.get("/observables/{identifier}")
def detail(identifier: str, principal=Depends(require("iocs.read")), db=Depends(db_session)):
    require_evidence_scope(principal)
    obs = owned(db, Observable, identifier, principal.organization_id)
    lookups = list(
        db.scalars(
            select(Enrichment)
            .where(
                Enrichment.organization_id == principal.organization_id, Enrichment.observable_id == obs.id
            )
            .order_by(Enrichment.provider)
        )
    )
    return as_dict(obs) | {
        "lookups": [result_view(r) for r in lookups],
        "related": related(db, principal.organization_id, obs.id),
    }


@router.get("/enrichments/{identifier}/history")
def history(
    identifier: str,
    offset: int = Query(0, ge=0),
    principal=Depends(require("iocs.read")),
    db=Depends(db_session),
):
    owned(db, Enrichment, identifier, principal.organization_id)
    return {
        "items": [
            as_dict(r)
            for r in db.scalars(
                select(EnrichmentHistory)
                .where(
                    EnrichmentHistory.organization_id == principal.organization_id,
                    EnrichmentHistory.enrichment_id == identifier,
                )
                .order_by(EnrichmentHistory.created_at.desc(), EnrichmentHistory.id)
                .offset(offset)
                .limit(50)
            )
        ]
    }


@router.get("/enrichments/{identifier}")
def lookup_detail(identifier: str, principal=Depends(require("iocs.read")), db=Depends(db_session)):
    return result_view(owned(db, Enrichment, identifier, principal.organization_id))


@router.post("/{identifier}/enrich")
def curated(
    identifier: str,
    request: Request,
    provider: Literal["mock", "virustotal"] = "virustotal",
    principal=Depends(require("iocs.write")),
    db=Depends(db_session),
):
    ioc = owned(db, IOC, identifier, principal.organization_id)
    if ioc.type not in {"ip", "domain", "url", "hash"}:
        raise HTTPException(422, "This curated indicator type is not supported for enrichment")
    try:
        value = ObservableInput(type=ioc.type, value=ioc.value)
    except ValueError:
        raise HTTPException(422, "Curated indicator is not a valid observable") from None
    return submit(db, request.app.state.settings, principal, [value], provider, False)
