"""Declarative, bounded SOAR workflows. No executable expressions or external connectors."""

import time
from ipaddress import ip_address
from typing import Literal, Protocol

from fastapi import HTTPException
from pydantic import Field, model_validator
from sqlalchemy import func, select, update

from aegis.db import (
    IOC,
    Alert,
    AlertEvent,
    CaseNote,
    Entity,
    EventRecord,
    Incident,
    IncidentAlert,
    Observable,
    Organization,
    Playbook,
    PlaybookVersion,
    Storyline,
    User,
    WorkflowRun,
)
from aegis.investigation import owned
from aegis.parsers import digest
from aegis.schemas import StrictModel
from aegis.security import ROLES, audit

ACTIVE = {"QUEUED", "RUNNING", "WAITING_FOR_APPROVAL"}
CONTAINMENT = {"simulate_block_ip", "simulate_disable_account", "simulate_isolate_host"}
SEVERITIES = {"informational": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


class Condition(StrictModel):
    field: Literal[
        "severity", "status", "rule_id", "risk_score", "intel_verdict", "intel_confidence", "intel_status"
    ]
    op: Literal["eq", "gte"] = "eq"
    value: str | int = Field(union_mode="left_to_right")

    @model_validator(mode="after")
    def valid_comparison(self):
        if self.op == "gte" and self.field not in {"severity", "risk_score", "intel_confidence"}:
            raise ValueError("gte is only supported for severity and risk_score")
        if self.field == "severity" and self.value not in SEVERITIES:
            raise ValueError("Unknown severity")
        if self.field in {"risk_score", "intel_confidence"}:
            if (
                isinstance(self.value, bool)
                or not str(self.value).isdigit()
                or not 0 <= int(self.value) <= 100
            ):
                raise ValueError("risk_score must be 0..100")
            self.value = int(self.value)
        elif len(str(self.value)) > 100:
            raise ValueError("Condition value too long")
        return self


class Trigger(StrictModel):
    source: Literal["alert", "incident", "storyline"]
    required_evidence_fields: list[Literal["host", "username", "source_ip", "destination_ip", "event_id"]] = (
        Field(default_factory=list, max_length=5)
    )
    conditions: list[Condition] = Field(default_factory=list, max_length=12)
    required_fields: list[Literal["severity", "status", "rule_id", "risk_score"]] = Field(
        default_factory=list, max_length=4
    )


class Step(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    action: Literal[
        "enrich",
        "enrich_observable",
        "incident_note",
        "simulate_block_ip",
        "simulate_disable_account",
        "simulate_isolate_host",
        "summary",
    ]
    when: Condition | None = None
    on_false: str | None = Field(default=None, max_length=40)
    retries: int = Field(default=0, ge=0, le=3)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    provider: Literal["mock", "virustotal"] = "virustotal"


class Definition(StrictModel):
    description: str = Field(min_length=1, max_length=1000)
    trigger: Trigger
    steps: list[Step] = Field(min_length=1, max_length=32)
    # Deliberately restricted schemas: only tenant-owned references can be inputs.
    input_schema: dict[
        Literal["target_id", "ioc_id", "observable_id"], Literal["entity", "ioc", "observable"]
    ] = Field(default_factory=dict)
    output_schema: Literal["aegis.action-result.v1"] = "aegis.action-result.v1"
    timeout_seconds: int = Field(default=300, ge=1, le=3600)

    @model_validator(mode="after")
    def graph(self):
        ids = [step.id for step in self.steps]
        if len(set(ids)) != len(ids):
            raise ValueError("Step IDs must be unique")
        for index, step in enumerate(self.steps):
            if step.on_false and (not step.when or step.on_false not in ids[index + 1 :]):
                raise ValueError("Branches must point forward to an existing step")
        if (
            any(s.action in CONTAINMENT for s in self.steps)
            and self.input_schema.get("target_id") != "entity"
        ):
            raise ValueError("Containment simulation requires target_id: entity input")
        if any(s.action == "incident_note" for s in self.steps) and self.trigger.source == "alert":
            raise ValueError("Incident notes require an incident or storyline trigger")
        if any(
            {"target_id": "entity", "ioc_id": "ioc", "observable_id": "observable"}[k] != v
            for k, v in self.input_schema.items()
        ):
            raise ValueError("Input reference types do not match")
        if (
            any(s.action == "enrich_observable" for s in self.steps)
            and self.input_schema.get("observable_id") != "observable"
        ):
            raise ValueError("enrich_observable requires an observable_id input")
        return self


class RunInput(StrictModel):
    source_type: Literal["alert", "incident", "storyline"]
    source_id: str = Field(min_length=1, max_length=80)
    inputs: dict[Literal["target_id", "ioc_id", "observable_id"], str] = Field(default_factory=dict)
    dry_run: bool = True
    idempotency_key: str = Field(min_length=8, max_length=128)


class ActionResult(StrictModel):
    simulated: bool = False
    dry_run: bool
    external_changed: Literal[False] = False
    data: dict = Field(default_factory=dict)


class Adapter(Protocol):
    """Adapters must be bounded and transactional; network I/O is not permitted here.

    A real connector needs its own outbox, fencing and reconciliation contract.
    """

    def execute(self, db, run: WorkflowRun, step: Step) -> ActionResult: ...


def lock_tenant(db, org):
    # A write lock also serializes SQLite, where SELECT FOR UPDATE is ignored.
    # Do not flush pending resource mutations before obtaining the tenant gate.
    with db.no_autoflush:
        db.execute(update(Organization).where(Organization.id == org).values(name=Organization.name))


def snapshot(db, org, kind, identifier):
    row = owned(db, {"alert": Alert, "incident": Incident, "storyline": Storyline}[kind], identifier, org)
    if kind == "storyline":
        incident = owned(db, Incident, row.incident_id, org)
        return {
            "severity": incident.severity,
            "status": incident.status,
            "risk_score": row.summary.get("risk_score", 0),
            "incident_id": incident.id,
        }
    return {
        key: getattr(row, key) for key in ("severity", "status", "rule_id", "risk_score") if hasattr(row, key)
    } | ({"incident_id": row.id} if kind == "incident" else {})


def matches(condition, context):
    value = context.get(condition.field)
    expected = condition.value
    if condition.field == "severity":
        value, expected = SEVERITIES.get(value, -1), SEVERITIES.get(expected, -1)
    elif condition.field in {"risk_score", "intel_confidence"}:
        try:
            if value is not None and not isinstance(value, bool):
                value = int(value)
        except (ValueError, TypeError):
            return False
    if value is None:
        return False
    if condition.op == "eq":
        return value == expected
    try:
        return value >= expected
    except TypeError:
        return False


def version_document(db, run):
    return Definition.model_validate(
        db.scalar(
            select(PlaybookVersion.document).where(
                PlaybookVersion.organization_id == run.organization_id,
                PlaybookVersion.playbook_id == run.playbook_id,
                PlaybookVersion.version == run.version,
            )
        )
    )


def validate_targets(db, org, definition, inputs):
    if set(inputs) != set(definition.input_schema):
        raise HTTPException(422, "Inputs must exactly match the declared reference schema")
    for key, kind in definition.input_schema.items():
        if not 1 <= len(inputs[key]) <= 80:
            raise HTTPException(422, "Invalid reference")
        owned(db, {"entity": Entity, "ioc": IOC, "observable": Observable}[kind], inputs[key], org)
    for step in definition.steps:
        if step.action in CONTAINMENT:
            target = owned(db, Entity, inputs["target_id"], org)
            expected = {
                "simulate_block_ip": "ip",
                "simulate_disable_account": "user",
                "simulate_isolate_host": "host",
            }[step.action]
            if target.type != expected:
                raise HTTPException(422, "Target entity type does not match action")
            if expected == "ip":
                try:
                    ip_address(target.value)
                except ValueError:
                    raise HTTPException(422, "Invalid IP target") from None


def enqueue(db, settings, principal, playbook_id, data):
    org = principal.organization_id
    lock_tenant(db, org)
    book = owned(db, Playbook, playbook_id, org)
    fingerprint = digest([playbook_id, data.model_dump(exclude={"idempotency_key"})])
    key = digest(data.idempotency_key)
    existing = db.scalar(
        select(WorkflowRun).where(WorkflowRun.organization_id == org, WorkflowRun.idempotency_key == key)
    )
    if existing:
        if existing.fingerprint != fingerprint:
            raise HTTPException(409, "Idempotency key already used for a different request")
        return existing
    if not book.enabled:
        raise HTTPException(409, "Playbook is disabled")
    document = db.scalar(
        select(PlaybookVersion.document).where(
            PlaybookVersion.organization_id == org,
            PlaybookVersion.playbook_id == book.id,
            PlaybookVersion.version == book.version,
        )
    )
    definition = Definition.model_validate(document)
    if (
        any(s.action == "enrich_observable" for s in definition.steps)
        and "iocs.write" not in principal.permissions
    ):
        raise HTTPException(403, "Enrichment requires iocs.write")
    if data.source_type != definition.trigger.source:
        raise HTTPException(422, "Trigger source does not match")
    context = snapshot(db, org, data.source_type, data.source_id)
    if any(context.get(key) in (None, "") for key in definition.trigger.required_fields) or not all(
        matches(c, context) for c in definition.trigger.conditions
    ):
        raise HTTPException(409, "Trigger conditions not satisfied")
    if definition.trigger.required_evidence_fields:
        evidence = (
            select(EventRecord.payload)
            .join(AlertEvent, AlertEvent.event_id == EventRecord.id)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(EventRecord.organization_id == org, Alert.organization_id == org)
        )
        if data.source_type == "alert":
            evidence = evidence.where(Alert.id == data.source_id)
        else:
            evidence = evidence.join(IncidentAlert, IncidentAlert.alert_id == Alert.id).where(
                IncidentAlert.incident_id == context["incident_id"]
            )
        payloads = list(db.scalars(evidence.limit(2001)))
        if len(payloads) > 2000:
            raise HTTPException(422, "Evidence validation exceeds 2000 event bound")
        present = {
            key
            for key in definition.trigger.required_evidence_fields
            if any(payload.get(key) not in (None, "") for payload in payloads)
        }
        if present != set(definition.trigger.required_evidence_fields):
            raise HTTPException(409, "Required evidence fields are missing")
    validate_targets(db, org, definition, data.inputs)
    # One explicit trigger per source/version/mode, independent of caller request key.
    duplicate = db.scalar(
        select(WorkflowRun).where(
            WorkflowRun.organization_id == org,
            WorkflowRun.playbook_id == book.id,
            WorkflowRun.version == book.version,
            WorkflowRun.source_type == data.source_type,
            WorkflowRun.source_id == data.source_id,
            WorkflowRun.dry_run == data.dry_run,
        )
    )
    if duplicate:
        if duplicate.fingerprint != fingerprint:
            raise HTTPException(409, "Source already triggered this version with different inputs")
        return duplicate
    count = db.scalar(
        select(func.count())
        .select_from(WorkflowRun)
        .where(WorkflowRun.organization_id == org, WorkflowRun.status.in_(ACTIVE))
    )
    if count >= settings.soar_queue_capacity:
        raise HTTPException(429, "Tenant workflow queue is full")
    run = WorkflowRun(
        organization_id=org,
        playbook_id=book.id,
        version=book.version,
        requested_by=principal.user.id,
        source_type=data.source_type,
        source_id=data.source_id,
        dry_run=data.dry_run,
        idempotency_key=key,
        fingerprint=fingerprint,
        context={"source": context, "inputs": data.inputs},
        deadline=time.time() + definition.timeout_seconds,
    )
    db.add(run)
    db.flush()
    record(db, settings, run, "queued", principal.user.id)
    return run


def record(db, settings, run, event, actor="soar-worker"):
    audit(
        db,
        settings,
        run.organization_id,
        actor,
        "soar." + event,
        run.id,
        result=event,
        details={"step": run.cursor, "dry_run": run.dry_run, "version": run.version},
    )


class LocalAdapter:
    def execute(self, db, run, step):
        org = run.organization_id
        # Re-resolve references before use; never return raw evidence or credentials.
        source = snapshot(db, org, run.source_type, run.source_id)
        inputs = run.context["inputs"]
        result = ActionResult(dry_run=run.dry_run)
        if step.action in CONTAINMENT:
            result.simulated = True
            result.data = {
                "action": step.action,
                "entity_id": inputs["target_id"],
                "message": "Simulation only. No external system was changed.",
            }
        elif step.action == "incident_note":
            if not run.dry_run:
                intelligence = run.context["source"]
                note = f"SOAR workflow {run.id}, step {step.id}: investigation reviewed. No external containment performed."
                if intelligence.get("intel_enrichment_id"):
                    note += (
                        f" Advisory intelligence: lookup {intelligence['intel_enrichment_id']}, "
                        f"provider {intelligence.get('intel_provider')}, "
                        f"verdict {intelligence.get('intel_verdict')}, "
                        f"origin {intelligence.get('intel_origin')}. This is not proof of compromise."
                    )
                db.add(
                    CaseNote(
                        organization_id=org,
                        resource_type="incidents",
                        resource_id=source["incident_id"],
                        author=run.requested_by,
                        text=note,
                    )
                )
            result.data = {"note_added": not run.dry_run}
        elif step.action == "enrich":
            result.data = {
                key: source[key] for key in ("severity", "status", "rule_id", "risk_score") if key in source
            }
            if "ioc_id" in inputs:
                ioc = owned(db, IOC, inputs["ioc_id"], org)
                result.data["ioc"] = {"id": ioc.id, "severity": ioc.severity, "confidence": ioc.confidence}
                from aegis.intelligence import context_for_values
                from aegis.observables import normalize

                if ioc.type in {"ip", "domain", "url", "hash"}:
                    try:
                        normalized = [normalize(ioc.type, ioc.value)]
                    except (ValueError, UnicodeError):
                        normalized = []
                    result.data["intelligence"] = context_for_values(db, org, normalized)
        else:
            result.data = {
                "source_id": run.source_id,
                "severity": source.get("severity"),
                "status": source.get("status"),
                "completed_steps": len(run.history),
            }
        return result


ADAPTERS: dict[str, Adapter] = {
    name: LocalAdapter() for name in ("enrich", "incident_note", "summary", *CONTAINMENT)
}


class IntelligenceAdapter:
    def __init__(self, settings):
        self.settings = settings

    def execute(self, db, run, step):
        from aegis.intelligence import queue, result_view

        obs = owned(db, Observable, run.context["inputs"]["observable_id"], run.organization_id)
        if run.dry_run:
            return ActionResult(
                dry_run=True,
                data={
                    "verdict": "unknown",
                    "confidence": None,
                    "status": "DRY_RUN",
                    "message": "No provider lookup queued.",
                },
            )
        row = queue(db, self.settings, obs, step.provider)
        if row.status in {"FAILED", "UNAVAILABLE"}:
            raise ValueError("Intelligence unavailable")
        waiting = row.status in {"QUEUED", "RUNNING"}
        return ActionResult(
            dry_run=False,
            data={
                "waiting": waiting,
                "enrichment_id": row.id,
                "provider": row.provider,
                "status": row.status,
                **result_view(row)["assessment"],
            },
        )


def finish(db, settings, run, status):
    run.status, run.completed_at = status, time.time()
    record(db, settings, run, status.lower())


def advance(db, settings, run):
    if run.status not in ACTIVE:
        return
    if time.time() >= run.deadline:
        finish(db, settings, run, "TIMED_OUT")
        return
    definition = version_document(db, run)
    user = db.get(User, run.requested_by)
    if (
        not user
        or not user.active
        or user.organization_id != run.organization_id
        or "playbooks.execute" not in ROLES[user.role]
    ):
        finish(db, settings, run, "FAILED")
        return
    if run.status == "WAITING_FOR_APPROVAL":
        return
    if run.available_at > time.time():
        return
    if run.started_at is None:
        run.started_at = time.time()
    run.status = "RUNNING"
    step = definition.steps[run.cursor]
    if step.when and not matches(step.when, run.context["source"]):
        run.history = [*run.history, {"step": step.id, "status": "SKIPPED", "completed_at": time.time()}]
        run.cursor = (
            next(i for i, s in enumerate(definition.steps) if s.id == step.on_false)
            if step.on_false
            else run.cursor + 1
        )
        record(db, settings, run, "skipped")
    else:
        if step.action in CONTAINMENT and not run.dry_run:
            approver = db.get(User, run.approved_by) if run.approved_by else None
            if (
                not approver
                or not approver.active
                or approver.organization_id != run.organization_id
                or "playbooks.approve" not in ROLES[approver.role]
                or not run.approved_at
                or time.time() - run.approved_at > settings.response_approval_seconds
            ):
                run.approved_by, run.approved_at = None, None
                run.status = "WAITING_FOR_APPROVAL"
                record(db, settings, run, "approval_required")
                return
        started = time.time()
        run.attempts += 1
        try:
            with db.begin_nested():
                validate_targets(db, run.organization_id, definition, run.context["inputs"])
                if step.action == "enrich_observable" and "iocs.write" not in ROLES[user.role]:
                    raise ValueError("Enrichment permission revoked")
                adapter = (
                    IntelligenceAdapter(settings)
                    if step.action == "enrich_observable"
                    else ADAPTERS[step.action]
                )
                result = adapter.execute(db, run, step)
                result = ActionResult.model_validate(result)
                if time.time() >= min(run.deadline, started + step.timeout_seconds):
                    raise TimeoutError()
                db.flush()
        except Exception as exc:
            # Never persist exception text, which can contain credentials or evidence.
            timed_out = isinstance(exc, TimeoutError)
            run.history = [
                *run.history,
                {
                    "step": step.id,
                    "attempt": run.attempts,
                    "status": "TIMED_OUT" if timed_out else "FAILED",
                    "error": "action_timeout" if timed_out else "action_failed",
                    "started_at": started,
                    "completed_at": time.time(),
                },
            ]
            record(db, settings, run, "action_failed")
            if timed_out:
                finish(db, settings, run, "TIMED_OUT")
            elif run.attempts <= step.retries:
                run.available_at = time.time() + 2**run.attempts
            else:
                finish(db, settings, run, "FAILED")
            return
        if step.action == "enrich_observable":
            if result.data.get("waiting"):
                run.attempts -= 1
                run.available_at = time.time() + 2
                return
            run.context = {
                **run.context,
                "source": {
                    **run.context["source"],
                    "intel_verdict": result.data.get("verdict", "unknown"),
                    "intel_confidence": result.data.get("confidence"),
                    "intel_status": result.data.get("status", "UNKNOWN"),
                    "intel_enrichment_id": result.data.get("enrichment_id"),
                    "intel_provider": result.data.get("provider"),
                    "intel_origin": result.data.get("assessment_origin"),
                },
            }
        run.history = [
            *run.history,
            {
                "step": step.id,
                "attempt": run.attempts,
                "status": "SUCCEEDED",
                "started_at": started,
                "completed_at": time.time(),
                "output": result.model_dump(),
            },
        ]
        record(db, settings, run, "simulated" if result.simulated or run.dry_run else "action_completed")
        run.cursor += 1
    run.attempts = 0
    run.approved_by, run.approved_at = None, None
    if run.cursor >= len(definition.steps):
        finish(db, settings, run, "SUCCEEDED")


def process_workflows(settings, sessions):
    # One step per transaction; process death rolls back the step and its local effects.
    with sessions() as db:
        candidates = list(
            db.execute(
                select(WorkflowRun.id, WorkflowRun.organization_id)
                .where(
                    WorkflowRun.status.in_(ACTIVE),
                    (
                        (WorkflowRun.status != "WAITING_FOR_APPROVAL")
                        & (WorkflowRun.available_at <= time.time())
                    )
                    | (WorkflowRun.deadline <= time.time()),
                )
                .order_by(WorkflowRun.available_at, WorkflowRun.created_at)
                .limit(settings.soar_batch_size)
            )
        )
    for identifier, org in candidates:
        with sessions.begin() as db:
            lock_tenant(db, org)
            run = owned(db, WorkflowRun, identifier, org)
            advance(db, settings, run)
    return len(candidates)
