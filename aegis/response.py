from typing import Protocol

from fastapi import HTTPException
from sqlalchemy import select

from aegis.db import Agent, AuditLog, Collector, Entity, Notification, PlaybookExecution, User
from aegis.investigation import owned
from aegis.parsers import digest
from aegis.security import audit

HIGH_IMPACT = {"isolate_host", "unisolate_host", "terminate_process", "disable_account", "block_ioc"}


class ResponseProvider(Protocol):
    def execute(self, db, organization_id: str, action: str, target: str) -> dict: ...


class LocalResponseProvider:
    """Persists local policy intent; never reports remote enforcement."""

    def execute(self, db, organization_id, action, target):
        if action == "notify_analyst":
            db.add(
                Notification(
                    organization_id=organization_id, title="Analyst response requested", resource_id=target
                )
            )
            return {"verified": True, "scope": "aegis", "notification": "persisted"}
        if action == "gather_evidence":
            from aegis.investigation import investigate

            evidence = investigate(db, organization_id, target)
            return {
                "verified": True,
                "scope": "aegis",
                "evidence_ids": [item["event"]["event_id"] for item in evidence["evidence"]],
            }
        entity = owned(db, Entity, target, organization_id)
        allowed = {
            "isolate_host": {"host"},
            "unisolate_host": {"host"},
            "terminate_process": {"host", "process"},
            "disable_account": {"user"},
            "block_ioc": {"ip", "domain", "url"},
        }
        if entity.type not in allowed[action]:
            raise HTTPException(422, "Target entity type is incompatible with this action")
        entity.attributes = entity.attributes | {
            "local_policy": {"action": action, "enforced_externally": False}
        }
        return {
            "verified": True,
            "scope": "local-policy-only",
            "enforced_externally": False,
            "entity_id": entity.id,
            "message": "Local policy recorded. No external host, account or firewall was changed.",
        }


def request_execution(db, settings, principal, data, idempotency_key, request=None):
    from aegis.soar import lock_tenant
    lock_tenant(db, principal.organization_id)
    key = digest([principal.organization_id, idempotency_key])
    existing = db.scalar(select(PlaybookExecution).where(PlaybookExecution.idempotency_key == key))
    if existing:
        if (existing.action != data.action or existing.target != data.target
                or (existing.result or {}).get("params", {}) != data.params):
            raise HTTPException(409, "Idempotency key belongs to a different request")
        return existing
    if data.action in HIGH_IMPACT:
        entity = owned(db, Entity, data.target, principal.organization_id)
        allowed = {
            "isolate_host": {"host"},
            "unisolate_host": {"host"},
            "terminate_process": {"host", "process"},
            "disable_account": {"user"},
            "block_ioc": {"ip", "domain", "url"},
        }
        if entity.type not in allowed[data.action]:
            raise HTTPException(422, "Target entity type is incompatible with this action")
    else:
        from aegis.investigation import investigate

        investigate(db, principal.organization_id, data.target)
    execution = PlaybookExecution(
        organization_id=principal.organization_id,
        action=data.action,
        target=data.target,
        requested_by=principal.user.id,
        idempotency_key=key,
        status="APPROVAL_REQUIRED" if data.action in HIGH_IMPACT else "REQUESTED",
        result={"params": data.params} if getattr(data, "params", None) else {},
    )
    db.add(execution)
    db.flush()
    audit(
        db,
        settings,
        principal.organization_id,
        principal.user.id,
        "playbooks.request",
        execution.id,
        request=request,
    )
    if data.action in HIGH_IMPACT:
        db.add(
            Notification(
                organization_id=principal.organization_id,
                title="Response approval required",
                resource_id=execution.id,
            )
        )
    return execution


def execute(db, settings, principal, execution_id, request=None):
    from aegis.soar import lock_tenant
    lock_tenant(db, principal.organization_id)
    execution = db.scalar(
        select(PlaybookExecution)
        .where(
            PlaybookExecution.id == execution_id,
            PlaybookExecution.organization_id == principal.organization_id,
        )
        .with_for_update()
    )
    if not execution:
        raise HTTPException(404, "Execution does not exist")
    if execution.status in {"VERIFIED", "SIMULATED", "ENFORCED", "RELEASED", "UNKNOWN", "FAILED"}:
        return execution
    if execution.status not in {"REQUESTED", "APPROVED", "DISPATCHED"}:
        raise HTTPException(409, "Execution requires approval or is not executable")
    if execution.action in HIGH_IMPACT and (
        not execution.approved_by or execution.approved_by == execution.requested_by
    ):
        raise HTTPException(403, "Independent human approval required")
    if execution.action in HIGH_IMPACT:
        from datetime import UTC, datetime

        from aegis.security import ROLES

        requester = db.get(User, execution.requested_by)
        if (not requester or not requester.active or requester.organization_id != principal.organization_id
                or "playbooks.execute" not in ROLES[requester.role]):
            raise HTTPException(403, "Requester is no longer authorized")
        approver = db.get(User, execution.approved_by)
        approval = db.scalar(
            select(AuditLog)
            .where(
                AuditLog.organization_id == principal.organization_id,
                AuditLog.resource_id == execution.id,
                AuditLog.action == "playbooks.approve",
            )
            .order_by(AuditLog.created_at.desc())
            .limit(1)
        )
        if (
            not approver
            or not approver.active
            or approver.organization_id != principal.organization_id
            or "playbooks.approve" not in ROLES[approver.role]
            or not approval
        ):
            raise HTTPException(403, "Approver is no longer authorized")
        approved_at = (
            approval.created_at.replace(tzinfo=UTC)
            if approval.created_at.tzinfo is None
            else approval.created_at
        )
        if (datetime.now(UTC) - approved_at).total_seconds() > settings.response_approval_seconds:
            raise HTTPException(409, "Approval expired; submit a fresh request")

    if execution.status == "DISPATCHED":
        return execution
    if execution.action in {"isolate_host", "unisolate_host", "terminate_process"}:
        conflict = db.scalar(select(PlaybookExecution.id).where(
            PlaybookExecution.organization_id == principal.organization_id,
            PlaybookExecution.target == execution.target,
            PlaybookExecution.id != execution.id,
            PlaybookExecution.status.in_(["DISPATCHED", "EXECUTING"]),
        ).limit(1))
        if conflict:
            raise HTTPException(409, "Endpoint already has an unresolved command")

    entity = db.get(Entity, execution.target) if execution.action in HIGH_IMPACT else None
    agent = None
    if entity and entity.type == "host":
        agent = db.scalar(
            select(Collector).where(
                Collector.organization_id == principal.organization_id,
                Collector.type == "endpoint-agent",
                Collector.name == entity.value,
            )
        )

    if entity and agent and execution.action in {"isolate_host", "unisolate_host", "terminate_process"}:
        execution.status = "DISPATCHED"
        if execution.action in {"isolate_host", "unisolate_host"}:
            entity.attributes = dict(entity.attributes or {}) | {
                "isolation_status": "UNKNOWN", "containment_execution_id": execution.id,
                "containment_semantics_version": 2,
            }
            endpoint = db.scalar(select(Agent).where(
                Agent.organization_id == principal.organization_id, Agent.name == agent.name,
            ))
            if endpoint:
                endpoint.isolation_status = "UNKNOWN"
        execution.result = (execution.result or {}) | {
            "verified": False,
            "scope": "dispatched-to-agent",
            "enforced_externally": False,
            "agent": agent.name,
            "pending_receipt": True,
            "message": f"Command dispatched to active endpoint agent {agent.name}. Awaiting execution receipt.",
        }
        execution.revision += 1
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "playbooks.dispatch",
            execution.id,
            details=execution.result,
            request=request,
        )
        return execution

    execution.status = "EXECUTING"
    result = LocalResponseProvider().execute(
        db, principal.organization_id, execution.action, execution.target
    )
    if execution.action in {"isolate_host", "unisolate_host"}:
        result = result | {"semantics_version": 2, "containment_status": "UNKNOWN", "verified": False}
        execution.status = "UNKNOWN"
    else:
        execution.status = "VERIFIED"
    execution.result = result | {"params": (execution.result or {}).get("params", {})}
    execution.revision += 1
    audit(
        db,
        settings,
        principal.organization_id,
        principal.user.id,
        "playbooks.execute",
        execution.id,
        details=result,
        request=request,
    )
    return execution

