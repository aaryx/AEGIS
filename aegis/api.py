import asyncio
import csv
import hashlib
import hmac
import io
import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from prometheus_client import generate_latest
from pydantic import Field
from redis import Redis
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from aegis import __version__
from aegis.ai import analyze_with_fallback, provider
from aegis.config import Settings, get_settings
from aegis.crypto import (
    ed25519_sign_canonical,
    ed25519_verify_canonical,
    generate_totp_secret,
    get_controller_public_key_hex,
    get_controller_signing_key,
    get_totp_uri,
    verify_totp,
)
from aegis.db import (
    IOC,
    Agent,
    AgentEnrollmentToken,
    Alert,
    APIKey,
    AuditLog,
    Base,
    Case,
    CaseEvidence,
    CaseNote,
    Collector,
    Entity,
    EventRecord,
    Incident,
    IncidentAlert,
    Notification,
    Organization,
    PasswordReset,
    PlaybookExecution,
    Report,
    Rule,
    RuleVersion,
    SavedSearch,
    SearchJob,
    SessionToken,
    User,
    WorkerHeartbeat,
    as_dict,
    database,
    now,
    uid,
)
from aegis.detection import SQLState, evaluate
from aegis.investigation import create_report, entity_detail, investigate, owned, report_html
from aegis.observability import API_LATENCY, API_REQUESTS, SEARCH_LATENCY
from aegis.parsers import ParserRegistry, canonical, digest
from aegis.pipeline import ingest
from aegis.response import execute, request_execution
from aegis.rules import MITRE
from aegis.schemas import (
    AgentEnrollInput,
    AgentHeartbeatInput,
    AgentKeyRotateInput,
    AgentReceiptInput,
    AgentRevokeInput,
    DetectionRule,
    EventInput,
    IncidentInput,
    IOCInput,
    Login,
    MFAVerifyInput,
    NoteInput,
    ResponseInput,
    RoleName,
    SearchQuery,
    StrictModel,
    UpdateStatus,
    UserInput,
    parse_query,
)
from aegis.security import (
    DUMMY_PASSWORD_HASH,
    PASSWORDS,
    audit,
    authenticate,
    check_password,
    db_session,
    issue_session,
    rate_limit,
    require,
    require_evidence_scope,
    revoke_sessions,
    token_hash,
    verify_audit,
)
from aegis.storage import LocalStorage, OpenSearchStorage

logger = logging.getLogger("aegis.api")
PREFIX = "/api/v1"
ALERT_STATUSES = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"}
INCIDENT_STATUSES = [
    "OPEN",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT",
    "ERADICATION",
    "RECOVERY",
    "RESOLVED",
    "CLOSED",
]
RESOURCES: dict[str, Any] = {
    "alerts": Alert,
    "incidents": Incident,
    "cases": Case,
    "entities": Entity,
    "rules": Rule,
    "iocs": IOC,
    "collectors": Collector,
    "hunts": SavedSearch,
    "reports": Report,
    "playbooks": PlaybookExecution,
    "audit": AuditLog,
    "notifications": Notification,
}


class IngestBatch(StrictModel):
    events: list[EventInput] = Field(min_length=1, max_length=2000)


class RuleWrite(StrictModel):
    document: DetectionRule
    summary: str = Field(min_length=10, max_length=500)
    version: int = Field(0, ge=0)
    enabled: bool = True


class RuleTest(StrictModel):
    document: DetectionRule
    events: list[EventInput] = Field(min_length=1, max_length=500)


class SaveHunt(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    query: SearchQuery


class Question(StrictModel):
    question: str = Field(min_length=1, max_length=500)


class CaseInput(StrictModel):
    title: str = Field(min_length=5, max_length=300)
    tags: list[str] = Field(default_factory=list, max_length=30)


class EvidenceInput(StrictModel):
    resource_type: Literal["alerts", "events", "entities"]
    resource_id: str = Field(max_length=80)


class KeyInput(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    permissions: list[str] = Field(min_length=1, max_length=50)
    days: int = Field(30, ge=1, le=90)


class ResetComplete(StrictModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=14, max_length=256)


class RoleUpdate(StrictModel):
    role: RoleName
    active: bool = True


class BodyLimitMiddleware:
    def __init__(self, app, maximum):
        self.app, self.maximum = app, maximum

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.maximum:
                response = JSONResponse(
                    {
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": "Request exceeds byte limit",
                            "request_id": uid(),
                        }
                    },
                    status_code=413,
                )
                return await response(scope, receive, send)
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


def health_state(app, organization_id=None):
    components = {
        "api": "HEALTHY",
        "database": "UNKNOWN",
        "redis": "UNKNOWN",
        "search": "UNKNOWN",
        "workers": "UNKNOWN",
    }
    queue = {}
    search_queue = {}
    try:
        with app.state.sessions() as db:
            db.execute(text("SELECT 1"))
            components["database"] = "HEALTHY"
            heartbeat = db.scalar(
                select(func.max(WorkerHeartbeat.last_seen)).where(
                    WorkerHeartbeat.id.not_like("notifications-%")
                )
            )
            components["workers"] = "HEALTHY" if heartbeat and heartbeat > time.time() - 30 else "DOWN"
            statement = select(EventRecord.state, func.count()).group_by(EventRecord.state)
            search_statement = select(SearchJob.state, func.count()).group_by(SearchJob.state)
            if organization_id:
                statement = statement.where(EventRecord.organization_id == organization_id)
                search_statement = search_statement.where(SearchJob.organization_id == organization_id)
            queue = dict(db.execute(statement).all())
            search_queue = dict(db.execute(search_statement).all())
    except SQLAlchemyError:
        components["database"] = "DOWN"
    try:
        components["redis"] = "HEALTHY" if app.state.redis and app.state.redis.ping() else "UNKNOWN"
    except Exception:
        components["redis"] = "DOWN"
    try:
        components["search"] = app.state.storage.health()
    except Exception:
        components["search"] = "DOWN"
    return {
        "status": "DEGRADED"
        if "DOWN" in components.values() or queue.get("DEAD", 0) or search_queue.get("DEAD", 0)
        else "HEALTHY",
        "components": components,
        "queue": queue,
        "search_queue": search_queue,
        "mode": "distributed" if app.state.settings.opensearch_url else "local",
        "version": __version__,
    }


def create_app(settings: Settings | None = None):
    settings = settings or get_settings()
    engine, sessions = database(settings.database_url)

    @asynccontextmanager
    async def lifespan(app):
        if settings.environment in {"development", "testing"} and settings.database_url.startswith("sqlite"):
            Base.metadata.create_all(engine)
        yield
        engine.dispose()

    app = FastAPI(
        title="AEGIS Security Intelligence & Operations",
        version=__version__,
        lifespan=lifespan,
        description="Tenant-scoped security operations API. Cookie sessions require X-CSRF-Token on writes. CLI clients may use bearer sessions or scoped API keys.",
    )
    app.state.settings, app.state.engine, app.state.sessions = settings, engine, sessions
    app.state.redis = (
        Redis.from_url(settings.redis_url, socket_timeout=3, socket_connect_timeout=3)
        if settings.redis_url
        else None
    )
    app.state.storage = OpenSearchStorage(settings) if settings.opensearch_url else LocalStorage(sessions)
    app.add_middleware(BodyLimitMiddleware, maximum=settings.max_request_bytes)
    from aegis.integrations import router as integration_router

    app.include_router(integration_router)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request.state.request_id = uid()
        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.error(
                "request_failed: %s",
                exc,
                exc_info=True,
                extra={"request_id": request.state.request_id, "error_type": type(exc).__name__},
            )
            response = JSONResponse(
                {
                    "error": {
                        "code": "SERVICE_UNAVAILABLE",
                        "message": "Operation could not be completed; retry or contact an administrator",
                        "request_id": request.state.request_id,
                    }
                },
                status_code=503,
            )
        response.headers.update(
            {
                "X-Request-ID": request.state.request_id,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
            }
        )
        if request.url.path not in {"/docs", "/redoc"}:
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        route = request.scope.get("route")
        API_LATENCY.labels(request.method, getattr(route, "path", "unmatched")).observe(
            time.monotonic() - started
        )
        API_REQUESTS.labels(request.method, response.status_code).inc()
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": f"HTTP_{exc.status_code}",
                    "message": str(exc.detail),
                    "request_id": request.state.request_id,
                }
            },
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        fields = [".".join(str(part) for part in error["loc"]) for error in exc.errors()]
        return JSONResponse(
            {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid request fields: " + ", ".join(fields),
                    "request_id": request.state.request_id,
                }
            },
            status_code=422,
        )

    @app.exception_handler(ValueError)
    async def value_error(request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": "INVALID_INPUT",
                    "message": "Input failed validation; check fields, time range and source identifiers",
                    "request_id": request.state.request_id,
                }
            },
            status_code=422,
        )

    @app.exception_handler(IntegrityError)
    async def conflict_error(request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": "CONFLICT",
                    "message": "Resource already exists or a concurrent update conflicted",
                    "request_id": request.state.request_id,
                }
            },
            status_code=409,
        )

    @app.get("/health", tags=["system"])
    @app.get(PREFIX + "/health", tags=["system"])
    @app.get(PREFIX + "/system/liveness", tags=["system"])
    def liveness():
        return {"status": "HEALTHY", "version": __version__}

    @app.get(PREFIX + "/system/readiness", tags=["system"])
    def readiness(response: Response):
        health = health_state(app)
        if (
            health["components"]["database"] != "HEALTHY"
            or (settings.opensearch_url and health["components"]["search"] != "HEALTHY")
            or (settings.redis_url and health["components"]["redis"] != "HEALTHY")
        ):
            response.status_code = 503
        return {"status": "READY" if response.status_code != 503 else "NOT_READY"}

    @app.get(PREFIX + "/system/health", tags=["system"])
    def health(principal=Depends(require("system.read"))):
        return health_state(app, principal.organization_id) | {
            "ai": {
                "provider": settings.ai_provider,
                "status": "HEALTHY" if settings.ai_provider == "local" else "UNKNOWN",
            },
            "threat_intelligence": "local IOC store",
        }

    @app.get(PREFIX + "/system/metrics", tags=["system"])
    def metrics(principal=Depends(require("system.manage")), db=Depends(db_session)):
        states = dict(
            db.execute(
                select(EventRecord.state, func.count())
                .where(EventRecord.organization_id == principal.organization_id)
                .group_by(EventRecord.state)
            ).all()
        )
        custom = f"\naegis_events_ingested_total {sum(states.values())}\naegis_events_processed_total {states.get('PROCESSED', 0)}\naegis_events_failed_total {states.get('DEAD', 0)}\naegis_queue_depth {states.get('PENDING', 0) + states.get('RETRY', 0)}\n"
        process_metrics = (
            generate_latest() if principal.user.role == "SUPER_ADMIN" and not principal.api_key_id else b""
        )
        return Response(process_metrics + custom.encode(), media_type="text/plain; version=0.0.4")

    @app.get(PREFIX + "/system/config", tags=["system"])
    def system_config(principal=Depends(require("system.read"))):
        return {
            key: getattr(settings, key)
            for key in (
                "environment",
                "max_request_bytes",
                "max_event_bytes",
                "max_batch_events",
                "queue_capacity",
                "worker_batch_size",
                "worker_max_attempts",
                "max_search_days",
                "retention_days",
                "ai_provider",
                "ai_model",
                "ai_max_tokens",
            )
        }

    @app.post(PREFIX + "/system/retention", tags=["system"])
    def trigger_retention(
        request: Request,
        dry_run: bool = Query(False),
        principal=Depends(require("system.manage")),
    ):
        rate_limit(request, f"retention:{principal.user.id}", 5)
        from aegis.retention import RetentionEngine

        engine = RetentionEngine(settings, request.app.state.sessions, request.app.state.storage)
        summaries = engine.run_cycle(dry_run=dry_run, actor=principal.user.id, request=request)
        return {"status": "ok", "dry_run": dry_run, "results": [s.to_dict() for s in summaries]}

    @app.post(PREFIX + "/auth/login", tags=["auth"])
    def login(data: Login, request: Request, response: Response, db=Depends(db_session)):
        if request.headers.get("origin") not in {None, settings.public_origin}:
            raise HTTPException(403, "Untrusted request origin")
        rate_limit(request, "login:" + (request.client.host if request.client else "unknown"), 10)
        user = db.scalar(select(User).where(User.username == data.username).with_for_update())
        valid = check_password(user.password_hash if user else DUMMY_PASSWORD_HASH, data.password)
        if not user or not user.active or user.locked_until > time.time() or not valid:
            if user:
                user.failed_logins += 1
                if user.failed_logins >= 5:
                    user.locked_until = time.time() + 900
                audit(
                    db,
                    settings,
                    user.organization_id,
                    user.id,
                    "auth.login",
                    result="denied",
                    request=request,
                )
                db.commit()
            raise HTTPException(401, "Invalid credentials or account temporarily locked")

        # Multi-factor authentication verification if enabled for user
        if user.mfa_enabled:
            if not data.mfa_code:
                return {
                    "mfa_required": True,
                    "user_id": user.id,
                    "message": "Multi-factor authentication code required",
                }
            if not user.mfa_secret or not verify_totp(user.mfa_secret, data.mfa_code):
                user.failed_logins += 1
                if user.failed_logins >= 5:
                    user.locked_until = time.time() + 900
                db.commit()
                raise HTTPException(401, "Invalid MFA authentication code")

        user.failed_logins, user.locked_until = 0, 0
        token, csrf = issue_session(db, user, settings)
        audit(db, settings, user.organization_id, user.id, "auth.login", request=request)
        db.commit()
        response.set_cookie(
            "aegis_session",
            token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            max_age=settings.session_hours * 3600,
            path="/",
        )
        response.set_cookie(
            "aegis_csrf",
            csrf,
            httponly=False,
            secure=settings.cookie_secure,
            samesite="strict",
            max_age=settings.session_hours * 3600,
            path="/",
        )
        return {
            "access_token": token,
            "token_type": "bearer",  # nosec B105 - protocol label, not a credential
            "csrf_token": csrf,
            "user": {"id": user.id, "username": user.username, "role": user.role},
            "expires_in": settings.session_hours * 3600,
        }

    @app.post(PREFIX + "/auth/mfa/setup", tags=["auth"])
    def mfa_setup(
        principal=Depends(authenticate),
        db=Depends(db_session),
    ):
        secret = generate_totp_secret()
        user = db.get(User, principal.user.id)
        if not user:
            raise HTTPException(404, "User not found")
        user.mfa_secret = secret
        db.commit()
        uri = get_totp_uri(secret, user.username)
        return {"secret": secret, "otpauth_uri": uri}

    @app.post(PREFIX + "/auth/mfa/verify", tags=["auth"])
    def mfa_verify(
        data: MFAVerifyInput,
        request: Request,
        principal=Depends(authenticate),
        db=Depends(db_session),
    ):
        user = db.get(User, principal.user.id)
        if not user or not user.mfa_secret:
            raise HTTPException(400, "MFA setup has not been initiated for this account")
        if not verify_totp(user.mfa_secret, data.code):
            raise HTTPException(400, "Invalid MFA verification code")
        user.mfa_enabled = True
        audit(
            db,
            settings,
            principal.organization_id,
            user.id,
            "auth.mfa_enabled",
            user.id,
            request=request,
        )
        db.commit()
        return {"status": "ok", "mfa_enabled": True}

    @app.get(PREFIX + "/auth/me", tags=["auth"])
    def me(principal=Depends(authenticate)):
        return {
            "id": principal.user.id,
            "username": principal.user.username,
            "role": principal.user.role,
            "organization_id": principal.organization_id,
            "permissions": sorted(principal.permissions),
        }

    @app.post(PREFIX + "/auth/logout", tags=["auth"])
    def logout(request: Request, response: Response, principal=Depends(authenticate), db=Depends(db_session)):
        if principal.session_id:
            db.execute(delete(SessionToken).where(SessionToken.id == principal.session_id))
        audit(db, settings, principal.organization_id, principal.user.id, "auth.logout", request=request)
        db.commit()
        response.delete_cookie("aegis_session", path="/")
        response.delete_cookie("aegis_csrf", path="/")
        return {"status": "logged_out"}

    @app.post(PREFIX + "/auth/refresh", tags=["auth"])
    def refresh(
        request: Request, response: Response, principal=Depends(authenticate), db=Depends(db_session)
    ):
        if not principal.session_id:
            raise HTTPException(403, "API keys cannot refresh sessions")
        deleted = db.execute(delete(SessionToken).where(SessionToken.id == principal.session_id))
        if deleted.rowcount != 1:
            raise HTTPException(401, "Session already rotated or revoked")
        token, csrf = issue_session(db, principal.user, settings)
        audit(db, settings, principal.organization_id, principal.user.id, "auth.refresh", request=request)
        db.commit()
        response.set_cookie(
            "aegis_session",
            token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            max_age=settings.session_hours * 3600,
        )
        response.set_cookie(
            "aegis_csrf",
            csrf,
            secure=settings.cookie_secure,
            samesite="strict",
            max_age=settings.session_hours * 3600,
        )
        return {"access_token": token, "csrf_token": csrf}

    @app.post(PREFIX + "/auth/password-reset/complete", tags=["auth"])
    def reset_complete(data: ResetComplete, request: Request, db=Depends(db_session)):
        rate_limit(request, "reset:" + (request.client.host if request.client else "unknown"), 5)
        reset = db.scalar(
            select(PasswordReset)
            .where(
                PasswordReset.token_hash == token_hash(data.token),
                PasswordReset.used.is_(False),
                PasswordReset.expires > time.time(),
            )
            .with_for_update()
        )
        if not reset:
            raise HTTPException(400, "Reset token is invalid or expired")
        user = db.get(User, reset.user_id)
        user.password_hash, user.failed_logins, user.locked_until = PASSWORDS.hash(data.password), 0, 0
        reset.used = True
        for pending in db.scalars(
            select(PasswordReset).where(PasswordReset.user_id == user.id, PasswordReset.used.is_(False))
        ):
            pending.used = True
        for key in db.scalars(select(APIKey).where(APIKey.user_id == user.id)):
            key.revoked = True
        revoke_sessions(db, user.id)
        audit(db, settings, user.organization_id, user.id, "auth.password_reset", request=request)
        db.commit()
        return {"status": "password_changed"}

    @app.get(PREFIX + "/users", tags=["users"])
    def users(
        limit: int = Query(50, ge=1, le=200),
        cursor: str = "",
        principal=Depends(require("users.manage")),
        db=Depends(db_session),
    ):
        rows = list(
            db.scalars(
                select(User)
                .where(User.organization_id == principal.organization_id, User.id > cursor)
                .order_by(User.id)
                .limit(limit + 1)
            )
        )
        return {
            "items": [
                {"id": row.id, "username": row.username, "role": row.role, "active": row.active}
                for row in rows[:limit]
            ],
            "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
        }

    @app.post(PREFIX + "/users", status_code=201, tags=["users"])
    def add_user(
        data: UserInput, request: Request, principal=Depends(require("users.manage")), db=Depends(db_session)
    ):
        if principal.api_key_id:
            raise HTTPException(403, "User administration requires a human session")
        if data.role == "SUPER_ADMIN" and principal.user.role != "SUPER_ADMIN":
            raise HTTPException(403, "Only a super administrator can create this role")
        user = User(
            organization_id=principal.organization_id,
            username=data.username,
            password_hash=PASSWORDS.hash(data.password),
            role=data.role,
        )
        db.add(user)
        db.flush()
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "users.create",
            user.id,
            details={"role": data.role},
            request=request,
        )
        db.commit()
        return {"id": user.id, "username": user.username, "role": user.role}

    @app.patch(PREFIX + "/users/{user_id}", tags=["users"])
    def update_user(
        user_id: str,
        data: RoleUpdate,
        request: Request,
        principal=Depends(require("users.manage")),
        db=Depends(db_session),
    ):
        if principal.api_key_id:
            raise HTTPException(403, "User administration requires a human session")
        user = owned(db, User, user_id, principal.organization_id)
        if user.id == principal.user.id:
            raise HTTPException(409, "Have another administrator change your access")
        if (
            data.role == "SUPER_ADMIN" or user.role == "SUPER_ADMIN"
        ) and principal.user.role != "SUPER_ADMIN":
            raise HTTPException(403, "Super administrator authorization required")
        user.role, user.active = data.role, data.active
        revoke_sessions(db, user.id)
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "users.permissions",
            user.id,
            details=data.model_dump(),
            request=request,
        )
        db.commit()
        return {"id": user.id, "role": user.role, "active": user.active}

    @app.post(PREFIX + "/users/{user_id}/password-reset", tags=["users"])
    def reset_issue(
        user_id: str, request: Request, principal=Depends(require("users.manage")), db=Depends(db_session)
    ):
        if principal.api_key_id:
            raise HTTPException(403, "Password recovery requires a human session")
        user = owned(db, User, user_id, principal.organization_id)
        if user.role == "SUPER_ADMIN" and principal.user.role != "SUPER_ADMIN":
            raise HTTPException(403, "Super administrator authorization required")
        token = secrets.token_urlsafe(48)
        db.add(
            PasswordReset(
                organization_id=principal.organization_id,
                user_id=user.id,
                token_hash=token_hash(token),
                expires=time.time() + 900,
            )
        )
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "auth.reset_issued",
            user.id,
            request=request,
        )
        db.commit()
        return {
            "token": token,
            "expires_in": 900,
            "delivery": "Deliver to the verified account owner through an approved channel",
        }

    @app.post(PREFIX + "/auth/api-keys", tags=["auth"])
    def create_key(
        data: KeyInput,
        request: Request,
        principal=Depends(require("integrations.manage")),
        db=Depends(db_session),
    ):
        if not set(data.permissions) <= principal.permissions:
            raise HTTPException(403, "Cannot grant permissions you do not have")
        token = "aegis_key_" + secrets.token_urlsafe(48)
        row = APIKey(
            organization_id=principal.organization_id,
            user_id=principal.user.id,
            name=data.name,
            permissions=data.permissions,
            key_hash=token_hash(token),
            expires=time.time() + data.days * 86400,
        )
        db.add(row)
        db.flush()
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "api_keys.create",
            row.id,
            request=request,
        )
        db.commit()
        return {"id": row.id, "key": token, "expires": row.expires}

    @app.delete(PREFIX + "/auth/api-keys/{key_id}", tags=["auth"])
    def revoke_key(
        key_id: str,
        request: Request,
        principal=Depends(require("integrations.manage")),
        db=Depends(db_session),
    ):
        row = owned(db, APIKey, key_id, principal.organization_id)
        row.revoked = True
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "api_keys.revoke",
            row.id,
            request=request,
        )
        db.commit()
        return {"revoked": True}

    @app.post(PREFIX + "/events/ingest", status_code=202, tags=["events"])
    def ingest_events(
        data: IngestBatch,
        request: Request,
        principal=Depends(require("events.ingest")),
        db=Depends(db_session),
    ):
        rate_limit(request, f"ingest:{principal.user.id}", 120)
        try:
            result = ingest(db, settings, principal.organization_id, data.events, principal.user.id, request)
        except OverflowError as exc:
            raise HTTPException(503, str(exc), headers={"Retry-After": "10"}) from exc
        db.commit()
        return result

    @app.post(PREFIX + "/events/search", tags=["events"])
    def search_events(query: SearchQuery, request: Request, principal=Depends(require("events.read"))):
        rate_limit(request, f"search:{principal.user.id}", 30)
        if query.end - query.start > timedelta(days=settings.max_search_days):
            raise HTTPException(422, "Search range exceeds configured maximum")
        with SEARCH_LATENCY.time():
            return app.state.storage.search(principal.organization_id, query)

    @app.post(PREFIX + "/hunts/parse", tags=["hunts"])
    def parse_hunt(data: Question, principal=Depends(require("hunts.read"))):
        return parse_query(data.question)

    @app.post(PREFIX + "/hunts", status_code=201, tags=["hunts"])
    def save_hunt(
        data: SaveHunt, request: Request, principal=Depends(require("hunts.write")), db=Depends(db_session)
    ):
        row = SavedSearch(
            organization_id=principal.organization_id,
            name=data.name,
            query=data.query.model_dump(mode="json"),
            author=principal.user.id,
        )
        db.add(row)
        db.flush()
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "hunts.create",
            row.id,
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.get(PREFIX + "/events/{event_id}", tags=["events"])
    def event_detail(event_id: str, principal=Depends(require("events.read")), db=Depends(db_session)):
        row = owned(db, EventRecord, event_id, principal.organization_id)
        return {"event": row.payload, "evidence_hash": row.evidence_hash, "state": row.state}

    @app.get(PREFIX + "/investigations/{resource_id}", tags=["investigations"])
    def investigation(resource_id: str, principal=Depends(require("events.read")), db=Depends(db_session)):
        require_evidence_scope(principal)
        result = investigate(db, principal.organization_id, resource_id)
        if "audit.read" not in principal.permissions:
            result["activity"] = []
        return result

    @app.post(PREFIX + "/investigations/{resource_id}/ai", tags=["ai"])
    def ai_analysis(
        resource_id: str, request: Request, principal=Depends(require("ai.use")), db=Depends(db_session)
    ):
        rate_limit(request, f"ai:{principal.user.id}", 5, 3600)
        require_evidence_scope(principal)
        result = analyze_with_fallback(settings, investigate(db, principal.organization_id, resource_id))
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "ai.analysis",
            resource_id,
            details={"provider": result.provider},
            request=request,
        )
        db.commit()
        return result

    @app.post(PREFIX + "/ai/query", tags=["ai"])
    def ai_query(
        data: Question, request: Request, principal=Depends(require("ai.use")), db=Depends(db_session)
    ):
        rate_limit(request, f"ai:{principal.user.id}", 5, 3600)
        result = provider(settings).query(data.question)
        if result.end - result.start > timedelta(days=settings.max_search_days):
            raise HTTPException(422, "Generated query exceeds allowed time range")
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "ai.query",
            details={"executed": False},
            request=request,
        )
        db.commit()
        return {"query": result, "executed": False, "requires_review": True}

    @app.post(PREFIX + "/incidents", status_code=201, tags=["incidents"])
    def add_incident(
        data: IncidentInput,
        request: Request,
        idempotency_key: str = Header(min_length=8, max_length=100),
        principal=Depends(require("incidents.create")),
        db=Depends(db_session),
    ):
        identifier = "INC-" + digest([principal.organization_id, idempotency_key])[:36]
        existing = db.get(Incident, identifier)
        if existing:
            attached = set(
                db.scalars(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == identifier))
            )
            if (
                existing.title != data.title
                or existing.severity != data.severity
                or existing.priority != data.priority
                or attached != set(data.alert_ids)
            ):
                raise HTTPException(409, "Idempotency key reused with different input")
            return as_dict(existing)
        alerts = [owned(db, Alert, alert_id, principal.organization_id) for alert_id in data.alert_ids]
        incident = Incident(
            id=identifier,
            organization_id=principal.organization_id,
            title=data.title,
            severity=data.severity,
            priority=data.priority,
        )
        db.add(incident)
        db.flush()
        for alert in {alert.id: alert for alert in alerts}.values():
            db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "incidents.create",
            incident.id,
            request=request,
        )
        db.add(
            Notification(
                organization_id=principal.organization_id, title=incident.title, resource_id=incident.id
            )
        )
        db.commit()
        return as_dict(incident)

    @app.post(PREFIX + "/incidents/{incident_id}/alerts/{alert_id}", tags=["incidents"])
    def attach_alert(
        incident_id: str,
        alert_id: str,
        request: Request,
        principal=Depends(require("incidents.update")),
        db=Depends(db_session),
    ):
        owned(db, Incident, incident_id, principal.organization_id)
        owned(db, Alert, alert_id, principal.organization_id)
        if not db.get(IncidentAlert, (incident_id, alert_id)):
            db.add(IncidentAlert(incident_id=incident_id, alert_id=alert_id))
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "incidents.attach_alert",
            incident_id,
            details={"alert_id": alert_id},
            request=request,
        )
        db.commit()
        return {"attached": True}

    @app.post(PREFIX + "/cases", status_code=201, tags=["cases"])
    def create_case(
        data: CaseInput, request: Request, principal=Depends(require("cases.write")), db=Depends(db_session)
    ):
        row = Case(organization_id=principal.organization_id, **data.model_dump())
        db.add(row)
        db.flush()
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "cases.create",
            row.id,
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.post(PREFIX + "/cases/{case_id}/evidence", tags=["cases"])
    def case_evidence(
        case_id: str,
        data: EvidenceInput,
        request: Request,
        principal=Depends(require("cases.write")),
        db=Depends(db_session),
    ):
        owned(db, Case, case_id, principal.organization_id)
        model = {"alerts": Alert, "events": EventRecord, "entities": Entity}[data.resource_type]
        target = owned(db, model, data.resource_id, principal.organization_id)
        if data.resource_type + ".read" not in principal.permissions:
            raise HTTPException(403, "Read access to attached evidence is required")
        row = CaseEvidence(
            organization_id=principal.organization_id,
            case_id=case_id,
            resource_type=data.resource_type,
            resource_id=data.resource_id,
            evidence_hash=target.evidence_hash
            if isinstance(target, EventRecord)
            else digest(as_dict(target)),
            attached_by=principal.user.id,
        )
        db.add(row)
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "cases.attach_evidence",
            case_id,
            details=data.model_dump(),
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.patch(PREFIX + "/{resource}/{resource_id}/status", tags=["workflow"])
    def update_status(
        resource: Literal["alerts", "incidents", "cases"],
        resource_id: str,
        data: UpdateStatus,
        request: Request,
        principal=Depends(authenticate),
        db=Depends(db_session),
    ):
        permission = "cases.write" if resource == "cases" else resource + ".update"
        if permission not in principal.permissions:
            raise HTTPException(403, "Permission denied")
        model = RESOURCES[resource]
        row = db.scalar(
            select(model)
            .where(model.id == resource_id, model.organization_id == principal.organization_id)
            .with_for_update()
        )
        if not row:
            raise HTTPException(404, "Resource does not exist")
        if row.revision != data.revision:
            raise HTTPException(409, "Resource changed; reload before updating")
        valid = ALERT_STATUSES if resource == "alerts" else set(INCIDENT_STATUSES)
        if data.status not in valid:
            raise HTTPException(422, "Invalid workflow status")
        if (
            resource == "incidents"
            and data.status != row.status
            and INCIDENT_STATUSES.index(data.status) != INCIDENT_STATUSES.index(row.status) + 1
        ):
            raise HTTPException(409, "Incident lifecycle must advance one stage at a time")
        if (
            resource == "incidents"
            and data.status in {"RESOLVED", "CLOSED"}
            and not (data.resolution or row.resolution)
        ):
            raise HTTPException(422, "Resolution notes are required")
        if data.assignee:
            owned(db, User, data.assignee, principal.organization_id)
        row.status, row.assignee, row.revision = data.status, data.assignee, row.revision + 1
        if resource == "incidents" and data.resolution:
            row.resolution = data.resolution
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            resource + ".update",
            row.id,
            details=data.model_dump(),
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.post(PREFIX + "/{resource}/{resource_id}/notes", tags=["workflow"])
    def add_note(
        resource: Literal["alerts", "incidents", "cases"],
        resource_id: str,
        data: NoteInput,
        request: Request,
        principal=Depends(authenticate),
        db=Depends(db_session),
    ):
        if ("cases.write" if resource == "cases" else resource + ".update") not in principal.permissions:
            raise HTTPException(403, "Permission denied")
        owned(db, RESOURCES[resource], resource_id, principal.organization_id)
        row = CaseNote(
            organization_id=principal.organization_id,
            resource_type=resource,
            resource_id=resource_id,
            author=principal.user.id,
            text=data.text,
        )
        db.add(row)
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            resource + ".note",
            resource_id,
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.post(PREFIX + "/iocs", status_code=201, tags=["iocs"])
    def add_ioc(
        data: IOCInput, request: Request, principal=Depends(require("iocs.write")), db=Depends(db_session)
    ):
        existing = db.scalar(
            select(IOC).where(
                IOC.organization_id == principal.organization_id,
                IOC.type == data.type,
                IOC.value == data.value,
            )
        )
        if existing:
            return as_dict(existing)
        row = IOC(organization_id=principal.organization_id, **data.model_dump())
        db.add(row)
        db.flush()
        audit(
            db, settings, principal.organization_id, principal.user.id, "iocs.create", row.id, request=request
        )
        db.commit()
        return as_dict(row)

    @app.delete(PREFIX + "/iocs/{ioc_id}", tags=["iocs"])
    def expire_ioc(
        ioc_id: str, request: Request, principal=Depends(require("iocs.write")), db=Depends(db_session)
    ):
        row = owned(db, IOC, ioc_id, principal.organization_id)
        row.expires = time.time()
        audit(
            db, settings, principal.organization_id, principal.user.id, "iocs.expire", row.id, request=request
        )
        db.commit()
        return {"expired": True}

    @app.post(PREFIX + "/rules/validate", tags=["rules"])
    def validate_rule(rule: DetectionRule, principal=Depends(require("rules.read"))):
        return {
            "valid": True,
            "rule": rule,
            "unknown_mitre": [technique for technique in rule.mitre_techniques if technique not in MITRE],
        }

    @app.post(PREFIX + "/rules/test", tags=["rules"])
    def test_rule(
        data: RuleTest, request: Request, principal=Depends(require("rules.execute")), db=Depends(db_session)
    ):
        rate_limit(request, f"rule-test:{principal.user.id}", 10)
        state = SQLState(db)
        namespace = "test:" + uid()
        events = [
            ParserRegistry().normalize(event, principal.organization_id).model_dump(mode="json")
            for event in data.events
        ]
        events.sort(key=lambda event: event["timestamp"])
        results = [result for event in events if (result := evaluate(data.document, event, state, namespace))]
        db.rollback()
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "rules.test",
            data.document.id,
            details={"matches": len(results)},
            request=request,
        )
        db.commit()
        return {"result": "MATCH" if results else "NO MATCH", "matches": results}

    @app.put(PREFIX + "/rules/{rule_id}", tags=["rules"])
    def save_rule(
        rule_id: str,
        data: RuleWrite,
        request: Request,
        principal=Depends(require("rules.write")),
        db=Depends(db_session),
    ):
        if rule_id != data.document.id:
            raise HTTPException(422, "Rule path and document ID differ")
        if any(technique not in MITRE for technique in data.document.mitre_techniques):
            raise HTTPException(422, "Technique is absent from the installed ATT&CK catalog")
        row = db.scalar(
            select(Rule)
            .where(Rule.organization_id == principal.organization_id, Rule.rule_id == rule_id)
            .with_for_update()
        )
        if row and row.version != data.version:
            raise HTTPException(409, "Rule version changed; reload before saving")
        if not row:
            if data.version != 0:
                raise HTTPException(409, "New rule must use version zero")
            row = Rule(organization_id=principal.organization_id, rule_id=rule_id, version=0)
            db.add(row)
        row.document, row.enabled, row.version = (
            data.document.model_dump(mode="json"),
            data.enabled,
            row.version + 1,
        )
        db.flush()
        db.add(
            RuleVersion(
                organization_id=principal.organization_id,
                rule_id=row.id,
                version=row.version,
                author=principal.user.id,
                summary=data.summary,
                document=row.document,
            )
        )
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "rules.update",
            row.id,
            details={"version": row.version, "summary": data.summary},
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.get(PREFIX + "/rules/{rule_id}/versions", tags=["rules"])
    def rule_versions(
        rule_id: str,
        limit: int = Query(50, ge=1, le=200),
        cursor: int = Query(0, ge=0),
        principal=Depends(require("rules.read")),
        db=Depends(db_session),
    ):
        row = owned(db, Rule, rule_id, principal.organization_id)
        versions = list(
            db.scalars(
                select(RuleVersion)
                .where(RuleVersion.rule_id == row.id, RuleVersion.version > cursor)
                .order_by(RuleVersion.version)
                .limit(limit + 1)
            )
        )
        return {
            "items": [as_dict(version) for version in versions[:limit]],
            "next_cursor": versions[limit - 1].version if len(versions) > limit else None,
        }

    @app.get(PREFIX + "/mitre", tags=["mitre"])
    def mitre(principal=Depends(require("mitre.read"))):
        return {
            "items": [
                {
                    "id": key,
                    "name": value[0],
                    "tactic": value[1],
                    "url": "https://attack.mitre.org/techniques/" + key.replace(".", "/") + "/",
                }
                for key, value in MITRE.items()
            ],
            "catalog": "curated detection coverage; not the complete ATT&CK dataset",
        }

    @app.get(PREFIX + "/mitre/{technique}", tags=["mitre"])
    def mitre_technique(technique: str, principal=Depends(require("mitre.read"))):
        if technique not in MITRE:
            raise HTTPException(404, "Technique is not in the installed catalog")
        return {"id": technique, "name": MITRE[technique][0], "tactic": MITRE[technique][1]}

    @app.post(PREFIX + "/reports/{incident_id}", tags=["reports"])
    def generate_report(
        incident_id: str,
        request: Request,
        principal=Depends(require("reports.create")),
        db=Depends(db_session),
    ):
        rate_limit(request, f"reports:{principal.user.id}", 10)
        require_evidence_scope(principal)
        result = create_report(db, settings, principal, incident_id, request)
        db.commit()
        return result

    @app.get(PREFIX + "/reports/{report_id}/html", response_class=HTMLResponse, tags=["reports"])
    def download_report(report_id: str, principal=Depends(require("reports.read")), db=Depends(db_session)):
        report = owned(db, Report, report_id, principal.organization_id)
        return HTMLResponse(
            report_html(report), headers={"Content-Disposition": f'attachment; filename="{report.id}.html"'}
        )

    @app.post(PREFIX + "/playbooks/request", tags=["playbooks"])
    def playbook_request(
        data: ResponseInput,
        request: Request,
        idempotency_key: str = Header(min_length=8, max_length=100),
        principal=Depends(require("playbooks.execute")),
        db=Depends(db_session),
    ):
        rate_limit(request, f"response:{principal.user.id}", 10)
        require_evidence_scope(principal)
        result = request_execution(db, settings, principal, data, idempotency_key, request)
        db.commit()
        return as_dict(result)

    @app.post(PREFIX + "/playbooks/{execution_id}/approve", tags=["playbooks"])
    def approve_playbook(
        execution_id: str,
        request: Request,
        principal=Depends(require("playbooks.approve")),
        db=Depends(db_session),
    ):
        row = db.scalar(
            select(PlaybookExecution)
            .where(
                PlaybookExecution.id == execution_id,
                PlaybookExecution.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if not row:
            raise HTTPException(404, "Execution does not exist")
        if principal.user.id == row.requested_by or principal.api_key_id:
            raise HTTPException(403, "A different human operator must approve")
        if row.status != "APPROVAL_REQUIRED":
            raise HTTPException(409, "Execution is not awaiting approval")
        row.approved_by, row.status, row.revision = principal.user.id, "APPROVED", row.revision + 1
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "playbooks.approve",
            row.id,
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.post(PREFIX + "/playbooks/{execution_id}/execute", tags=["playbooks"])
    def execute_playbook(
        execution_id: str,
        request: Request,
        principal=Depends(require("playbooks.execute")),
        db=Depends(db_session),
    ):
        rate_limit(request, f"response:{principal.user.id}", 10)
        require_evidence_scope(principal)
        result = execute(db, settings, principal, execution_id, request)
        db.commit()
        return as_dict(result)

    @app.post(PREFIX + "/agents/enrollment-tokens", tags=["agents"])
    def create_enrollment_token(
        request: Request,
        principal=Depends(require("users.manage")),
        db=Depends(db_session),
    ):
        raw_token = "aegis_enroll_" + secrets.token_urlsafe(32)
        expires_at = time.time() + 86400  # 24 hours single-use token
        token_record = AgentEnrollmentToken(
            id=uid(),
            organization_id=principal.organization_id,
            created_at=now(),
            token_hash=token_hash(raw_token),
            expires_at=expires_at,
            used=False,
        )
        db.add(token_record)
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "agents.enrollment_token.create",
            token_record.id,
            details={"expires_at": expires_at},
            request=request,
        )
        db.commit()
        return {"status": "ok", "token": raw_token, "enrollment_token": raw_token, "expires_at": expires_at}

    @app.post(PREFIX + "/agents/enroll", tags=["agents"])
    def enroll_agent(
        data: AgentEnrollInput,
        request: Request,
        db=Depends(db_session),
    ):
        rate_limit(request, f"enroll:{data.name}", 10)
        token_record = db.scalar(
            select(AgentEnrollmentToken)
            .where(
                AgentEnrollmentToken.token_hash == token_hash(data.enrollment_token),
                AgentEnrollmentToken.used.is_(False),
                AgentEnrollmentToken.expires_at > time.time(),
            )
            .with_for_update()
        )
        if not token_record:
            raise HTTPException(403, "Invalid, expired, or already-used enrollment token")

        org_id = token_record.organization_id
        agent = db.scalar(
            select(Agent)
            .where(
                Agent.organization_id == org_id,
                Agent.name == data.name,
            )
            .with_for_update()
        )
        if agent and agent.status == "REVOKED":
            raise HTTPException(403, "Agent identity is revoked. Re-enrollment prohibited without admin re-activation.")

        # Burn single-use enrollment token
        token_record.used = True

        raw_auth_token = "aegis_agt_" + secrets.token_urlsafe(32)
        auth_hash = token_hash(raw_auth_token)

        if not agent:
            agent = Agent(
                id="AGT-" + uid(),
                organization_id=org_id,
                name=data.name,
                public_key=data.public_key,
                status="ENROLLED",
                os=data.system_info.get("os", "unknown"),
                os_release=data.system_info.get("os_release", ""),
                ip=data.system_info.get("ip", "127.0.0.1"),
                version=data.system_info.get("version", "1.0.0"),
                capabilities=data.system_info.get("capabilities", []),
                isolation_status="NONE",
                last_heartbeat=now(),
                enrolled_at=now(),
                auth_token_hash=auth_hash,
            )
            db.add(agent)
            db.flush()
        else:
            agent.public_key = data.public_key
            agent.status = "ENROLLED"
            agent.auth_token_hash = auth_hash
            agent.enrolled_at = now()
            agent.last_heartbeat = now()
            agent.capabilities = data.system_info.get("capabilities", agent.capabilities)
            agent.os = data.system_info.get("os", agent.os)
            agent.ip = data.system_info.get("ip", agent.ip)

        token_record.used_by_agent_id = agent.id

        collector = db.scalar(
            select(Collector).where(
                Collector.organization_id == org_id,
                Collector.name == data.name,
                Collector.type == "endpoint-agent",
            )
        )
        if not collector:
            collector = Collector(
                organization_id=org_id,
                name=data.name,
                type="endpoint-agent",
                version=agent.version,
                last_heartbeat=now(),
            )
            db.add(collector)
            db.flush()

        entity = db.scalar(
            select(Entity).where(
                Entity.organization_id == org_id,
                Entity.type == "host",
                Entity.value == data.name,
            )
        )
        if not entity:
            entity = Entity(
                organization_id=org_id,
                type="host",
                value=data.name,
                attributes={},
            )
            db.add(entity)
            db.flush()

        entity.attributes = dict(entity.attributes or {}) | {
            "agent_id": agent.id,
            "collector_id": collector.id,
            "agent_version": agent.version,
            "os": agent.os,
            "ip": agent.ip,
            "isolation_status": agent.isolation_status,
            "public_key": agent.public_key,
        }

        ctrl_pubkey = get_controller_public_key_hex(settings)
        audit(
            db,
            settings,
            org_id,
            f"agent:{agent.id}",
            "agents.enroll",
            agent.id,
            details={"name": data.name, "public_key": data.public_key},
            request=request,
        )
        db.commit()
        return {
            "status": "ok",
            "agent_id": agent.id,
            "auth_token": raw_auth_token,
            "controller_public_key": ctrl_pubkey,
        }

    @app.post(PREFIX + "/agents/{name}/rotate-key", tags=["agents"])
    def rotate_agent_key(
        name: str,
        data: AgentKeyRotateInput,
        request: Request,
        principal=Depends(require("agents.poll", "agents.receipt")),
        db=Depends(db_session),
    ):
        agent = db.scalar(
            select(Agent).where(
                Agent.organization_id == principal.organization_id,
                Agent.name == name,
            ).with_for_update()
        )
        if not agent or agent.status != "ENROLLED":
            raise HTTPException(404, "Enrolled agent not found")
        if principal.agent and principal.agent.id != agent.id:
            raise HTTPException(403, "Agent not authorized to rotate keys for another endpoint")

        agent.public_key = data.new_public_key
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "agents.rotate_key",
            agent.id,
            details={"name": name, "new_public_key": data.new_public_key},
            request=request,
        )
        db.commit()
        return {"status": "ok", "public_key": agent.public_key}

    @app.post(PREFIX + "/agents/{name}/revoke", tags=["agents"])
    def revoke_agent(
        name: str,
        data: AgentRevokeInput,
        request: Request,
        principal=Depends(require("agents.revoke")),
        db=Depends(db_session),
    ):
        agent = db.scalar(
            select(Agent).where(
                Agent.organization_id == principal.organization_id,
                Agent.name == name,
            ).with_for_update()
        )
        if not agent:
            raise HTTPException(404, "Agent not found")
        agent.status = "REVOKED"
        agent.revoked_at = now()
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "agents.revoke",
            agent.id,
            details={"name": name, "reason": data.reason},
            request=request,
        )
        db.commit()
        return {"status": "REVOKED", "agent_id": agent.id}

    @app.post(PREFIX + "/agents/heartbeat", tags=["agents"])
    def agent_heartbeat(
        data: AgentHeartbeatInput,
        request: Request,
        principal=Depends(require("collectors.read")),
        db=Depends(db_session),
    ):
        rate_limit(request, f"agent:{data.name}", 60)
        from aegis.db import Collector, Entity, now

        # Update Agent table if registered
        agent_row = db.scalar(
            select(Agent).where(
                Agent.organization_id == principal.organization_id,
                Agent.name == data.name,
            )
        )
        if agent_row:
            if agent_row.status == "REVOKED":
                raise HTTPException(403, "Agent identity is revoked")
            agent_row.last_heartbeat = now()
            agent_row.isolation_status = data.isolation_status
            agent_row.ip = data.ip
            agent_row.version = data.version
            agent_row.capabilities = data.capabilities
            if data.public_key:
                agent_row.public_key = data.public_key
        elif data.public_key:
            agent_row = Agent(
                organization_id=principal.organization_id,
                name=data.name,
                public_key=data.public_key,
                status="ENROLLED",
                version=data.version,
                os=data.os,
                ip=data.ip,
                capabilities=data.capabilities,
                isolation_status=data.isolation_status,
                last_heartbeat=now(),
            )
            db.add(agent_row)
            db.flush()

        collector = db.scalar(
            select(Collector).where(
                Collector.organization_id == principal.organization_id,
                Collector.name == data.name,
                Collector.type == "endpoint-agent",
            )
        )
        if not collector:
            collector = Collector(
                organization_id=principal.organization_id,
                name=data.name,
                type="endpoint-agent",
                version=data.version,
                last_heartbeat=now(),
            )
            db.add(collector)
            db.flush()
        else:
            collector.last_heartbeat = now()
            collector.version = data.version

        entity = db.scalar(
            select(Entity).where(
                Entity.organization_id == principal.organization_id,
                Entity.type == "host",
                Entity.value == data.name,
            )
        )
        if not entity:
            entity = Entity(
                organization_id=principal.organization_id,
                type="host",
                value=data.name,
                attributes={},
            )
            db.add(entity)
            db.flush()

        entity.attributes = dict(entity.attributes or {}) | {
            "agent_id": collector.id,
            "endpoint_agent_id": agent_row.id if agent_row else None,
            "collector_id": collector.id,
            "agent_version": data.version,
            "os": data.os,
            "ip": data.ip,
            "isolation_status": data.isolation_status,
            "capabilities": data.capabilities,
            "last_heartbeat": now().isoformat(),
        }
        entity.last_seen = now()

        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "agents.heartbeat",
            collector.id,
            details={"name": data.name, "status": data.status, "isolation_status": data.isolation_status},
            request=request,
        )
        db.commit()
        return {
            "status": "ok",
            "collector_id": collector.id,
            "entity_id": entity.id,
            "name": data.name,
            "isolation_status": data.isolation_status,
            "timestamp": now().isoformat(),
        }

    @app.get(PREFIX + "/agents/{name}/commands", tags=["agents"])
    def agent_commands(
        name: str,
        principal=Depends(require("playbooks.read")),
        db=Depends(db_session),
    ):
        # Enforce agent-to-host authorization
        if principal.agent is not None:
            if principal.agent.name != name or principal.agent.status != "ENROLLED":
                raise HTTPException(403, "Agent not authorized for this host")

        entity = db.scalar(
            select(Entity).where(
                Entity.organization_id == principal.organization_id,
                Entity.type == "host",
                Entity.value == name,
            )
        )
        target_ids = {name}
        if entity:
            target_ids.add(entity.id)

        executions = list(
            db.scalars(
                select(PlaybookExecution)
                .where(
                    PlaybookExecution.organization_id == principal.organization_id,
                    PlaybookExecution.status.in_(["APPROVED", "DISPATCHED"]),
                    PlaybookExecution.target.in_(target_ids),
                )
                .order_by(PlaybookExecution.created_at.asc())
            )
        )

        agent = db.scalar(
            select(Agent).where(
                Agent.organization_id == principal.organization_id,
                Agent.name == name,
            )
        )
        agent_id = agent.id if agent else name

        ctrl_priv = get_controller_signing_key(settings)
        ctrl_pub = get_controller_public_key_hex(settings)

        results = []
        for execution in executions:
            res_dict = dict(execution.result or {})
            envelope = res_dict.get("command_envelope")
            ctrl_sig = res_dict.get("controller_signature")
            if not envelope or not ctrl_sig:
                envelope = {
                    "version": "1.0",
                    "command_id": execution.id,
                    "agent_id": agent_id,
                    "organization_id": principal.organization_id,
                    "action": execution.action,
                    "parameters": res_dict.get("params", {}),
                    "issued_at": time.time(),
                    "expires_at": time.time() + 300.0,
                    "nonce": secrets.token_hex(16),
                }
                ctrl_sig = ed25519_sign_canonical(ctrl_priv, envelope)
                res_dict["command_envelope"] = envelope
                res_dict["controller_signature"] = ctrl_sig
                res_dict["controller_public_key"] = ctrl_pub
                execution.result = res_dict

            results.append({
                "id": execution.id,
                "action": execution.action,
                "target": execution.target,
                "status": execution.status,
                "created_at": execution.created_at.isoformat(),
                "params": res_dict.get("params", {}),
                "envelope": envelope,
                "controller_signature": ctrl_sig,
                "controller_public_key": ctrl_pub,
            })
        db.commit()
        return results

    @app.post(PREFIX + "/agents/{name}/receipts", tags=["agents"])
    def agent_receipt(
        name: str,
        data: AgentReceiptInput,
        request: Request,
        principal=Depends(require("playbooks.execute")),
        db=Depends(db_session),
    ):
        rate_limit(request, f"receipt:{data.command_id}", 30)

        # Enforce agent-to-host authorization
        if principal.agent is not None:
            if principal.agent.name != name or principal.agent.status != "ENROLLED":
                raise HTTPException(403, "Agent not authorized to submit receipts for this host")

        agent = db.scalar(
            select(Agent).where(
                Agent.organization_id == principal.organization_id,
                Agent.name == name,
            )
        )
        if agent and agent.status == "REVOKED":
            raise HTTPException(403, "Agent identity is revoked")

        execution = db.scalar(
            select(PlaybookExecution)
            .where(
                PlaybookExecution.id == data.command_id,
                PlaybookExecution.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if not execution:
            raise HTTPException(404, "Command execution not found")
        if execution.status not in {"APPROVED", "DISPATCHED"}:
            raise HTTPException(409, f"Command execution status is '{execution.status}', not awaiting receipt")
        if execution.action != data.action:
            raise HTTPException(409, "Receipt action does not match execution command")

        # Cryptographic verification
        if data.receipt and data.signature:
            if not agent:
                raise HTTPException(400, "Endpoint agent not registered with public key")
            # Verify Ed25519 signature
            if not ed25519_verify_canonical(agent.public_key, data.signature, data.receipt):
                raise HTTPException(400, "Cryptographic execution receipt signature verification failed")

            # Verify cryptographic binding to command and scope
            receipt_cmd_id = data.receipt.get("command_id")
            receipt_action = data.receipt.get("action")
            receipt_agent = data.receipt.get("agent_id")
            if receipt_cmd_id != execution.id:
                raise HTTPException(400, "Receipt command ID does not match execution")
            if receipt_action != execution.action:
                raise HTTPException(400, "Receipt action does not match execution")
            if receipt_agent and receipt_agent != agent.id and receipt_agent != name:
                raise HTTPException(400, "Receipt agent ID does not match enrolled agent")

            expected_ctrl_sig = (execution.result or {}).get("controller_signature")
            receipt_ctrl_sig = data.receipt.get("command_signature")
            if expected_ctrl_sig and receipt_ctrl_sig and receipt_ctrl_sig != expected_ctrl_sig:
                raise HTTPException(400, "Receipt is not bound to the dispatched controller command")
        elif data.receipt_hash:
            expected_payload = {
                "command_id": data.command_id,
                "agent": name,
                "action": data.action,
                "status": data.status,
                "result": data.details,
            }
            expected_hash = hashlib.sha256(canonical(expected_payload).encode()).hexdigest()
            if not hmac.compare_digest(expected_hash, data.receipt_hash):
                raise HTTPException(400, "Cryptographic execution receipt hash does not match payload")

        from aegis.db import now

        receipt_details = data.receipt.get("result", data.details) if data.receipt else data.details
        if data.status == "SUCCESS":
            execution.status = "VERIFIED"
            execution.result = {
                "verified": True,
                "scope": "endpoint-live",
                "enforced_externally": True,
                "agent": name,
                "action": data.action,
                "receipt": data.receipt,
                "signature": data.signature,
                "receipt_hash": data.receipt_hash or (hashlib.sha256(canonical(data.receipt).encode()).hexdigest() if data.receipt else ""),
                "details": receipt_details,
                "enforced_at": now().isoformat(),
            }
            entity = db.scalar(
                select(Entity).where(
                    Entity.organization_id == principal.organization_id,
                    Entity.type == "host",
                    (Entity.id == execution.target) | (Entity.value == name),
                )
            )
            if entity:
                attrs = dict(entity.attributes or {})
                if data.action == "isolate_host":
                    attrs["isolation_status"] = "ISOLATED"
                elif data.action == "unisolate_host":
                    attrs["isolation_status"] = "NONE"
                entity.attributes = attrs
        else:
            execution.status = "FAILED"
            execution.result = {
                "verified": False,
                "scope": "endpoint-live",
                "enforced_externally": False,
                "agent": name,
                "action": data.action,
                "receipt": data.receipt,
                "signature": data.signature,
                "error": receipt_details.get("error", "Endpoint execution failed"),
            }

        execution.revision += 1
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "agent.receipt",
            execution.id,
            details=execution.result,
            request=request,
        )
        db.commit()
        return as_dict(execution)

    @app.get(PREFIX + "/agents", tags=["agents"])
    def list_agents(
        principal=Depends(require("collectors.read")),
        db=Depends(db_session),
    ):
        collectors = list(
            db.scalars(
                select(Collector)
                .where(
                    Collector.organization_id == principal.organization_id,
                    Collector.type == "endpoint-agent",
                )
                .order_by(Collector.name.asc())
            )
        )
        hosts = {
            e.value: e
            for e in db.scalars(
                select(Entity).where(
                    Entity.organization_id == principal.organization_id,
                    Entity.type == "host",
                )
            )
        }
        agents_map = {
            a.name: a
            for a in db.scalars(
                select(Agent).where(Agent.organization_id == principal.organization_id)
            )
        }
        return [
            {
                "id": c.id,
                "agent_id": agents_map[c.name].id if c.name in agents_map else c.id,
                "name": c.name,
                "version": c.version,
                "status": agents_map[c.name].status if c.name in agents_map else "ONLINE",
                "last_heartbeat": c.last_heartbeat.isoformat(),
                "isolation_status": hosts[c.name].attributes.get("isolation_status", "NONE")
                if c.name in hosts and hosts[c.name] and hosts[c.name].attributes
                else "NONE",
                "os": hosts[c.name].attributes.get("os", "unknown")
                if c.name in hosts and hosts[c.name] and hosts[c.name].attributes
                else "unknown",
                "ip": hosts[c.name].attributes.get("ip", "127.0.0.1")
                if c.name in hosts and hosts[c.name] and hosts[c.name].attributes
                else "127.0.0.1",
            }
            for c in collectors
        ]

    @app.get(PREFIX + "/audit/verify", tags=["audit"])
    def audit_verify(principal=Depends(require("audit.read")), db=Depends(db_session)):
        return {"valid": verify_audit(db, settings, principal.organization_id)}

    @app.post(PREFIX + "/system/dead-letter/{event_id}/retry", tags=["system"])
    def retry_event(
        event_id: str, request: Request, principal=Depends(require("system.manage")), db=Depends(db_session)
    ):
        row = owned(db, EventRecord, event_id, principal.organization_id)
        if row.state != "DEAD":
            raise HTTPException(409, "Event is not dead-lettered")
        row.state, row.attempts, row.available_at = "PENDING", 0, 0
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "events.retry",
            event_id,
            request=request,
        )
        db.commit()
        return {"state": row.state}

    @app.get(PREFIX + "/system/search-jobs", tags=["system"])
    def search_jobs(
        limit: int = Query(50, ge=1, le=200),
        cursor: str = "",
        principal=Depends(require("system.manage")),
        db=Depends(db_session),
    ):
        rows = list(
            db.scalars(
                select(SearchJob)
                .where(
                    SearchJob.organization_id == principal.organization_id,
                    SearchJob.event_id > cursor,
                    SearchJob.state != "INDEXED",
                )
                .order_by(SearchJob.event_id)
                .limit(limit + 1)
            )
        )
        return {
            "items": [as_dict(row) for row in rows[:limit]],
            "next_cursor": rows[limit - 1].event_id if len(rows) > limit else None,
        }

    @app.post(PREFIX + "/system/search-jobs/{event_id}/retry", tags=["system"])
    def retry_search(
        event_id: str, request: Request, principal=Depends(require("system.manage")), db=Depends(db_session)
    ):
        row = db.scalar(
            select(SearchJob)
            .where(SearchJob.event_id == event_id, SearchJob.organization_id == principal.organization_id)
            .with_for_update()
        )
        if not row:
            raise HTTPException(404, "Search job not found")
        if row.state != "DEAD":
            raise HTTPException(409, "Search job is not dead-lettered")
        row.state, row.attempts, row.available_at = "PENDING", 0, 0
        audit(
            db,
            settings,
            principal.organization_id,
            principal.user.id,
            "search.retry",
            event_id,
            request=request,
        )
        db.commit()
        return as_dict(row)

    @app.get(PREFIX + "/dashboard", tags=["dashboard"])
    def dashboard(principal=Depends(require("alerts.read")), db=Depends(db_session)):
        require_evidence_scope(principal)
        org = principal.organization_id
        severity = dict(
            db.execute(
                select(Alert.severity, func.count())
                .where(
                    Alert.organization_id == org,
                    Alert.status.not_in(["CLOSED", "RESOLVED", "FALSE_POSITIVE"]),
                )
                .group_by(Alert.severity)
            ).all()
        )
        events = db.scalar(
            select(func.count()).select_from(EventRecord).where(EventRecord.organization_id == org)
        )
        processed = db.scalar(
            select(func.count())
            .select_from(EventRecord)
            .where(EventRecord.organization_id == org, EventRecord.state == "PROCESSED")
        )
        alerts = db.scalar(select(func.count()).select_from(Alert).where(Alert.organization_id == org))
        open_incidents = db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.organization_id == org, Incident.status.not_in(["RESOLVED", "CLOSED"]))
        )
        recent_events = db.scalar(
            select(func.count())
            .select_from(EventRecord)
            .where(
                EventRecord.organization_id == org,
                EventRecord.created_at >= datetime.now(UTC) - timedelta(seconds=60),
            )
        )
        top_rules = db.execute(
            select(Alert.rule_id, func.count())
            .where(Alert.organization_id == org)
            .group_by(Alert.rule_id)
            .order_by(func.count().desc())
            .limit(8)
        ).all()
        recent = list(
            db.scalars(
                select(Alert).where(Alert.organization_id == org).order_by(Alert.created_at.desc()).limit(10)
            )
        )
        entities = list(
            db.scalars(
                select(Entity)
                .where(Entity.organization_id == org)
                .order_by(Entity.risk_score.desc())
                .limit(8)
            )
        )
        return {
            "events": events,
            "events_processed": processed,
            "alerts": alerts,
            "open_incidents": open_incidents,
            "severity": severity,
            "events_per_second": round(recent_events / 60, 2),
            "alerts_per_1000_events": round(alerts / max(processed, 1) * 1000, 2),
            "top_rules": [{"rule_id": key, "count": count} for key, count in top_rules],
            "recent_alerts": [as_dict(row) for row in recent],
            "top_entities": [as_dict(row) for row in entities],
        }

    @app.get(PREFIX + "/stream", tags=["realtime"])
    async def stream(request: Request, principal=Depends(require("alerts.read", "events.read"))):
        async def updates():
            previous = None
            while not await request.is_disconnected():

                def snapshot():
                    with sessions() as db:
                        user = db.get(User, principal.user.id)
                        session = db.get(SessionToken, principal.session_id) if principal.session_id else None
                        key = db.get(APIKey, principal.api_key_id) if principal.api_key_id else None
                        if (
                            not user
                            or not user.active
                            or (not session and not key)
                            or (session and session.expires <= time.time())
                            or (key and (key.revoked or key.expires <= time.time()))
                        ):
                            return None
                        return {
                            "alerts": db.scalar(
                                select(func.count())
                                .select_from(Alert)
                                .where(Alert.organization_id == principal.organization_id)
                            ),
                            "events": db.scalar(
                                select(func.count())
                                .select_from(EventRecord)
                                .where(EventRecord.organization_id == principal.organization_id)
                            ),
                            "activity": db.scalar(
                                select(Organization.audit_head).where(
                                    Organization.id == principal.organization_id
                                )
                            ),
                        }

                current = await asyncio.to_thread(snapshot)
                if current is None:
                    yield "event: expired\ndata: {}\n\n"
                    break
                if current != previous:
                    yield "data: " + json.dumps(current) + "\n\n"
                    previous = current
                else:
                    yield ": heartbeat\n\n"
                await asyncio.sleep(5)

        return StreamingResponse(
            updates(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )

    def list_resource(resource, limit, cursor, severity, status, q, sort, principal, db):
        permission = "alerts.read" if resource == "notifications" else resource + ".read"
        if resource not in RESOURCES or permission not in principal.permissions:
            raise HTTPException(403, "Resource access denied")
        model = RESOURCES[resource]
        statement = select(model).where(model.organization_id == principal.organization_id)
        if cursor:
            statement = statement.where(model.id > cursor if sort == "asc" else model.id < cursor)
        if severity and hasattr(model, "severity"):
            statement = statement.where(model.severity == severity)
        if status and hasattr(model, "status"):
            statement = statement.where(model.status == status)
        if q:
            field = next(
                (
                    getattr(model, name)
                    for name in ("title", "name", "value", "rule_id", "action")
                    if hasattr(model, name)
                ),
                model.id,
            )
            statement = statement.where(field.contains(q, autoescape=True))
        rows = list(
            db.scalars(
                statement.order_by(model.id.asc() if sort == "asc" else model.id.desc()).limit(limit + 1)
            )
        )
        return {
            "items": [as_dict(row) for row in rows[:limit]],
            "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
        }

    @app.get(PREFIX + "/export/{resource}", tags=["export"])
    def export(
        resource: str,
        format: Literal["json", "csv"] = "json",
        limit: int = Query(200, ge=1, le=500),
        cursor: str = "",
        principal=Depends(authenticate),
        db=Depends(db_session),
    ):
        result = list_resource(resource, limit, cursor, "", "", "", "asc", principal, db)
        if format == "json":
            return result
        rows = result["items"]
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=list(rows[0]))
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {
                        key: (
                            "'" + value
                            if isinstance(value, str)
                            and (s := value.lstrip(" \t\r\n"))
                            and s[0] in ("=", "+", "-", "@", "\t", "\r", "%")
                            else json.dumps(value)
                            if isinstance(value, (dict, list))
                            else value
                        )
                        for key, value in row.items()
                    }
                )
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers={
                "X-Next-Cursor": result["next_cursor"] or "",
                "Content-Disposition": 'attachment; filename="aegis-export.csv"',
            },
        )

    @app.get(PREFIX + "/{resource}", tags=["resources"])
    def resource_list(
        resource: str,
        limit: int = Query(50, ge=1, le=200),
        cursor: str = Query("", max_length=80),
        severity: str = "",
        status: str = "",
        q: str = Query("", max_length=200),
        sort: Literal["asc", "desc"] = "desc",
        principal=Depends(authenticate),
        db=Depends(db_session),
    ):
        return list_resource(resource, limit, cursor, severity, status, q, sort, principal, db)

    @app.get(PREFIX + "/{resource}/{resource_id}", tags=["resources"])
    def resource_detail(
        resource: str, resource_id: str, principal=Depends(authenticate), db=Depends(db_session)
    ):
        permission = "alerts.read" if resource == "notifications" else resource + ".read"
        if resource not in RESOURCES or permission not in principal.permissions:
            raise HTTPException(403, "Resource access denied")
        if resource == "entities":
            if "events.read" not in principal.permissions:
                raise HTTPException(403, "Entity evidence requires events.read")
            return entity_detail(db, principal.organization_id, resource_id)
        row = owned(db, RESOURCES[resource], resource_id, principal.organization_id)
        result = as_dict(row)
        if resource == "cases":
            result["notes"] = [
                as_dict(item)
                for item in db.scalars(
                    select(CaseNote)
                    .where(
                        CaseNote.organization_id == principal.organization_id, CaseNote.resource_id == row.id
                    )
                    .limit(200)
                )
            ]
            result["evidence"] = [
                as_dict(item)
                for item in db.scalars(
                    select(CaseEvidence)
                    .where(
                        CaseEvidence.organization_id == principal.organization_id,
                        CaseEvidence.case_id == row.id,
                    )
                    .limit(200)
                )
            ]
        return result

    return app


app = create_app()
