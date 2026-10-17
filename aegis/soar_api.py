"""Tenant-scoped workflow API; legacy single-action response APIs remain intact."""

import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field
from sqlalchemy import select

from aegis.db import AuditLog, Playbook, PlaybookVersion, WorkflowRun, as_dict
from aegis.investigation import owned
from aegis.schemas import StrictModel
from aegis.security import audit, db_session, require, require_evidence_scope
from aegis.soar import ACTIVE, ActionResult, Definition, RunInput, enqueue, finish, lock_tenant, record

router = APIRouter(prefix="/api/v1/soar", tags=["soar"])


class Write(StrictModel):
    name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9 _-]*$")
    definition: Definition
    enabled: bool = False
    expected_version: int = Field(default=0, ge=0)


class Decision(StrictModel):
    decision: str = Field(pattern="^(approve|reject|cancel|retry)$")


@router.post("/validate")
def validate(data: Definition, principal=Depends(require("playbooks.read"))):
    return {"valid": True, "definition": data.model_dump(), "output_schema": ActionResult.model_json_schema()}


@router.get("/playbooks")
def books(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    principal=Depends(require("playbooks.read")),
    db=Depends(db_session),
):
    return {
        "items": [
            as_dict(row)
            for row in db.scalars(
                select(Playbook)
                .where(Playbook.organization_id == principal.organization_id)
                .order_by(Playbook.name)
                .offset(offset)
                .limit(limit)
            )
        ]
    }


@router.post("/playbooks")
def write(
    data: Write, request: Request, principal=Depends(require("playbooks.write")), db=Depends(db_session)
):
    org = principal.organization_id
    lock_tenant(db, org)
    book = db.scalar(select(Playbook).where(Playbook.organization_id == org, Playbook.name == data.name))
    if (book.version if book else 0) != data.expected_version:
        raise HTTPException(409, "Version conflict; reload before editing")
    if book:
        book.version += 1
        book.enabled = data.enabled
    else:
        book = Playbook(organization_id=org, name=data.name, enabled=data.enabled, version=1)
        db.add(book)
        db.flush()
    db.add(
        PlaybookVersion(
            organization_id=org,
            playbook_id=book.id,
            version=book.version,
            document=data.definition.model_dump(),
            author=principal.user.id,
        )
    )
    audit(
        db,
        request.app.state.settings,
        org,
        principal.user.id,
        "soar.version_created",
        book.id,
        details={"version": book.version, "enabled": book.enabled},
    )
    db.commit()
    return as_dict(book)


@router.get("/playbooks/{identifier}")
def book_detail(identifier: str, principal=Depends(require("playbooks.read")), db=Depends(db_session)):
    book = owned(db, Playbook, identifier, principal.organization_id)
    versions = list(
        db.scalars(
            select(PlaybookVersion)
            .where(
                PlaybookVersion.organization_id == principal.organization_id,
                PlaybookVersion.playbook_id == identifier,
            )
            .order_by(PlaybookVersion.version.desc())
            .limit(100)
        )
    )
    return as_dict(book) | {"versions": [as_dict(v) for v in versions]}


@router.post("/playbooks/{identifier}/execute")
def execute(
    identifier: str,
    data: RunInput,
    request: Request,
    principal=Depends(require("playbooks.execute", "incidents.update")),
    db=Depends(db_session),
):
    require_evidence_scope(principal)
    try:
        run = enqueue(db, request.app.state.settings, principal, identifier, data)
    except HTTPException as exc:
        db.rollback()
        audit(
            db,
            request.app.state.settings,
            principal.organization_id,
            principal.user.id,
            "soar.trigger_rejected",
            identifier,
            result="rejected",
            details={"status_code": exc.status_code},
        )
        db.commit()
        raise
    db.commit()
    return as_dict(run)


@router.get("/executions")
def runs(
    status: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    principal=Depends(require("playbooks.read")),
    db=Depends(db_session),
):
    require_evidence_scope(principal)
    query = select(WorkflowRun).where(WorkflowRun.organization_id == principal.organization_id)
    if status:
        query = query.where(WorkflowRun.status == status)
    return {
        "items": [
            as_dict(r)
            for r in db.scalars(query.order_by(WorkflowRun.created_at.desc()).offset(offset).limit(limit))
        ]
    }


@router.get("/executions/{identifier}")
def run_detail(identifier: str, principal=Depends(require("playbooks.read")), db=Depends(db_session)):
    require_evidence_scope(principal)
    return as_dict(owned(db, WorkflowRun, identifier, principal.organization_id))


@router.get("/executions/{identifier}/audit")
def run_audit(
    identifier: str, principal=Depends(require("playbooks.read", "audit.read")), db=Depends(db_session)
):
    owned(db, WorkflowRun, identifier, principal.organization_id)
    return {
        "items": [
            as_dict(r)
            for r in db.scalars(
                select(AuditLog)
                .where(
                    AuditLog.organization_id == principal.organization_id, AuditLog.resource_id == identifier
                )
                .order_by(AuditLog.created_at)
                .limit(500)
            )
        ]
    }


@router.post("/executions/{identifier}/decision")
def decision(
    identifier: str,
    data: Decision,
    request: Request,
    principal=Depends(require("playbooks.read")),
    db=Depends(db_session),
):
    require_evidence_scope(principal)
    settings = request.app.state.settings
    resource_id = identifier

    def reject(status, message):
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "soar.decision_rejected",
            resource_id,
            result="rejected",
            details={"decision": data.decision, "status_code": status},
        )
        db.commit()
        raise HTTPException(status, message)

    permission = "playbooks.approve" if data.decision in {"approve", "reject"} else "playbooks.execute"
    if permission not in principal.permissions:
        reject(403, "Missing " + permission)
    lock_tenant(db, principal.organization_id)
    run = owned(db, WorkflowRun, identifier, principal.organization_id)
    resource_id = run.id
    if run.status in ACTIVE and time.time() >= run.deadline:
        finish(db, settings, run, "TIMED_OUT")
        db.commit()
        raise HTTPException(409, "Execution timed out")
    if data.decision == "cancel":
        if run.status not in ACTIVE:
            reject(409, "Execution is already terminal")
        finish(db, settings, run, "CANCELLED")
    elif data.decision == "retry":
        if run.status != "FAILED" or run.attempts >= 4 or time.time() >= run.deadline:
            reject(409, "Retry unavailable or attempt budget exhausted")
        run.status, run.completed_at, run.available_at = "QUEUED", None, time.time()
        run.approved_by, run.approved_at = None, None
    else:
        if run.status != "WAITING_FOR_APPROVAL":
            reject(409, "Execution is not awaiting approval")
        if run.requested_by == principal.user.id:
            reject(403, "Independent human approval required")
        if data.decision == "reject":
            finish(db, settings, run, "CANCELLED")
        else:
            run.approved_by, run.approved_at, run.status = principal.user.id, time.time(), "QUEUED"
    record(db, settings, run, data.decision, principal.user.id)
    db.commit()
    return as_dict(run)
