import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, select

from aegis.db import APIKey, AuditLog, Organization, SessionToken, User, WindowState, now, uid
from aegis.parsers import canonical

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_PASSWORD_HASH = PASSWORDS.hash("aegis-dummy-constant-salt-for-timing-mitigation")
READ = {
    f"{name}.read"
    for name in (
        "events",
        "alerts",
        "incidents",
        "cases",
        "entities",
        "rules",
        "iocs",
        "hunts",
        "reports",
        "mitre",
        "collectors",
        "system",
        "playbooks",
    )
}
ANALYST = READ | {
    "alerts.update",
    "incidents.create",
    "incidents.update",
    "cases.write",
    "hunts.write",
    "reports.create",
    "ai.use",
}
SENIOR = ANALYST | {"rules.execute", "iocs.write", "playbooks.execute"}
MANAGER = SENIOR | {"playbooks.approve", "audit.read"}
ADMIN = MANAGER | {"events.ingest", "rules.write", "users.manage", "integrations.manage", "system.manage"}
ROLES = {
    "VIEWER": READ,
    "ANALYST": ANALYST,
    "SENIOR_ANALYST": SENIOR,
    "SOC_MANAGER": MANAGER,
    "SECURITY_ADMIN": ADMIN,
    "SUPER_ADMIN": ADMIN,
}


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def check_password(encoded: str, password: str) -> bool:
    try:
        return PASSWORDS.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def db_session(request: Request):
    with request.app.state.sessions() as db:
        yield db


def audit(
    db,
    settings,
    organization_id: str,
    actor: str,
    action: str,
    resource_id: str = "",
    result="success",
    details=None,
    request=None,
):
    org = db.scalar(
        select(Organization)
        .where(Organization.id == organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    data = dict(details or {})
    if request:
        data.update(
            source_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "")[:300],
            request_id=request.state.request_id,
        )
    record = AuditLog(
        id=uid(),
        organization_id=organization_id,
        created_at=now(),
        actor=actor,
        action=action,
        resource_id=resource_id,
        result=result,
        details=data,
        previous_hash=org.audit_head,
    )
    message = canonical(
        {
            "id": record.id,
            "organization_id": organization_id,
            "timestamp": record.created_at.isoformat(),
            "actor": actor,
            "action": action,
            "resource": resource_id,
            "result": result,
            "details": data,
            "previous": org.audit_head,
        }
    )
    record.entry_hash = hmac.new(
        settings.audit_secret.get_secret_value().encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    org.audit_head = record.entry_hash
    db.add(record)
    db.flush()
    return record


def verify_audit(db, settings, organization_id: str) -> bool:
    records = list(db.scalars(select(AuditLog).where(AuditLog.organization_id == organization_id)))
    by_previous = {record.previous_hash: record for record in records}
    previous = "0" * 64
    visited = 0
    while previous in by_previous:
        record = by_previous.pop(previous)
        stamp = record.created_at
        from datetime import UTC

        stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp
        message = canonical(
            {
                "id": record.id,
                "organization_id": organization_id,
                "timestamp": stamp.isoformat(),
                "actor": record.actor,
                "action": record.action,
                "resource": record.resource_id,
                "result": record.result,
                "details": record.details,
                "previous": previous,
            }
        )
        expected = hmac.new(
            settings.audit_secret.get_secret_value().encode(), message.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, record.entry_hash):
            return False
        previous = record.entry_hash
        visited += 1
    return visited == len(records) and previous == db.get(Organization, organization_id).audit_head


def rate_limit(request: Request, key: str, maximum: int, seconds: int = 60):
    bucket = f"aegis:rate:{token_hash(key)}:{int(time.time()) // seconds}"
    redis = request.app.state.redis
    if redis:
        pipe = redis.pipeline()
        pipe.incr(bucket)
        pipe.expire(bucket, seconds * 2)
        count = pipe.execute()[0]
    else:
        with request.app.state.sessions.begin() as db:
            row = db.get(WindowState, bucket)
            count = (row.data[0] if row else 0) + 1
            if row:
                row.data = [count]
            else:
                db.add(WindowState(key=bucket, data=[count], expires=time.time() + seconds * 2))
    if count > maximum:
        raise HTTPException(429, "Rate limit exceeded; retry later", headers={"Retry-After": str(seconds)})


@dataclass
class Principal:
    user: User
    permissions: set[str]
    session_id: str | None = None
    api_key_id: str | None = None

    @property
    def organization_id(self):
        return self.user.organization_id


def authenticate(request: Request, db=Depends(db_session)) -> Principal:
    authorization = request.headers.get("authorization", "")
    bearer = authorization[7:] if authorization.startswith("Bearer ") else None
    token = bearer or request.cookies.get("aegis_session")
    if not token or len(token) > 200:
        raise HTTPException(401, "Authentication required")
    key = None
    session = None
    if token.startswith("aegis_key_"):
        key = db.scalar(
            select(APIKey).where(
                APIKey.key_hash == token_hash(token), APIKey.revoked.is_(False), APIKey.expires > time.time()
            )
        )
        user = db.get(User, key.user_id) if key else None
    else:
        session = db.scalar(
            select(SessionToken).where(
                SessionToken.token_hash == token_hash(token), SessionToken.expires > time.time()
            )
        )
        user = db.get(User, session.user_id) if session else None
    if not user or not user.active:
        raise HTTPException(401, "Session expired or invalid")
    if not bearer and request.method not in {"GET", "HEAD", "OPTIONS"}:
        csrf = request.headers.get("x-csrf-token", "")
        if not session or not hmac.compare_digest(session.csrf_hash, token_hash(csrf)):
            raise HTTPException(403, "CSRF validation failed")
        if request.headers.get("origin") not in {None, request.app.state.settings.public_origin}:
            raise HTTPException(403, "Untrusted request origin")
    permissions = ROLES[user.role] & set(key.permissions) if key else ROLES[user.role]
    principal = Principal(user, permissions, session.id if session else None, key.id if key else None)
    request.state.principal = principal
    return principal


def require(permission: str, *additional: str):
    def dependency(principal=Depends(authenticate)):
        missing = {permission, *additional} - principal.permissions
        if missing:
            raise HTTPException(403, "Permissions required: " + ", ".join(sorted(missing)))
        return principal

    return dependency


def issue_session(db, user, settings):
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    session = SessionToken(
        organization_id=user.organization_id,
        user_id=user.id,
        token_hash=token_hash(token),
        csrf_hash=token_hash(csrf),
        expires=time.time() + settings.session_hours * 3600,
    )
    db.add(session)
    return token, csrf


def revoke_sessions(db, user_id):
    db.execute(delete(SessionToken).where(SessionToken.user_id == user_id))


def require_evidence_scope(principal):
    """Composite responses expose each of these protected data classes."""
    needed = {"events.read", "alerts.read", "incidents.read", "entities.read", "iocs.read"}
    if not needed <= principal.permissions:
        raise HTTPException(
            403, "Investigation requires evidence, alert, incident, entity and IOC read access"
        )
