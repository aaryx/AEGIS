import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, select

from aegis.db import (
    Agent,
    APIKey,
    AuditCheckpoint,
    AuditHead,
    AuditLog,
    Organization,
    SessionToken,
    User,
    WindowState,
    now,
    uid,
)
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
        "agents",
        "ueba",
    )
}
ANALYST = READ | {
    "ueba.update",
    "alerts.update",
    "incidents.create",
    "incidents.update",
    "cases.write",
    "hunts.write",
    "reports.create",
    "ai.use",
}
SENIOR = ANALYST | {
    "ueba.execute",
    "rules.execute",
    "iocs.write",
    "playbooks.execute",
    "agents.poll",
    "agents.receipt",
}
MANAGER = SENIOR | {"playbooks.approve", "audit.read"}
ADMIN = MANAGER | {
    "playbooks.write",
    "events.ingest",
    "rules.write",
    "users.manage",
    "integrations.manage",
    "system.manage",
    "agents.manage",
    "agents.enroll",
    "agents.revoke",
}
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
    # Even ON CONFLICT can wait on an uncommitted first AuditHead insert.
    # Acquire the tenant gate BEFORE that insert, including pending ORM flushes.
    from aegis.soar import lock_tenant

    lock_tenant(db, organization_id)
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        db.execute(
            pg_insert(AuditHead)
            .values(
                organization_id=organization_id,
                audit_head="0" * 64,
                sequence_number=0,
                updated_at=now(),
            )
            .on_conflict_do_nothing()
        )
    else:
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        db.execute(
            sqlite_insert(AuditHead)
            .values(
                organization_id=organization_id,
                audit_head="0" * 64,
                sequence_number=0,
                updated_at=now(),
            )
            .on_conflict_do_nothing()
        )

    # The tenant gate remains held through the caller's commit/rollback.
    org = db.scalar(
        select(Organization)
        .where(Organization.id == organization_id)
        .with_for_update()
    )

    head = db.scalar(
        select(AuditHead)
        .where(AuditHead.organization_id == organization_id)
        .with_for_update()
    )
    if not head:
        head = db.get(AuditHead, organization_id)

    prev_head = head.audit_head
    data = dict(details or {})
    if request:
        data.update(
            source_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "")[:300],
            request_id=getattr(request.state, "request_id", "unknown"),
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
        previous_hash=prev_head,
        key_version=getattr(settings, "audit_key_version", 1),
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
            "previous": prev_head,
        }
    )
    key_ver = getattr(settings, "audit_key_version", 1)
    audit_key = derive_audit_key(settings.audit_secret.get_secret_value(), key_ver)
    record.entry_hash = hmac.new(
        audit_key, message.encode(), hashlib.sha256
    ).hexdigest()
    head.audit_head = record.entry_hash
    head.sequence_number += 1
    head.updated_at = record.created_at
    db.add(record)

    # Sync organization audit_head (org was locked at start of audit)
    if not org:
        org = db.get(Organization, organization_id)
    if org:
        org.audit_head = record.entry_hash
    db.flush()
    return record


def derive_audit_key(secret: str, version: int = 1) -> bytes:
    if version <= 1:
        return secret.encode()
    from aegis.crypto import hkdf_derive_key
    return hkdf_derive_key(secret.encode(), f"aegis-audit-key-v{version}".encode(), length=32)


def verify_audit(db, settings, organization_id: str) -> bool:
    records = list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == organization_id)
            .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        )
    )
    # Even an empty chain must agree with its durable heads. Otherwise deleting
    # every audit row makes a previously nonempty history appear valid.
    head = db.get(AuditHead, organization_id)
    org = db.get(Organization, organization_id)
    if not org:
        return False
    if not head:
        if records or org.audit_head != "0" * 64:
            return False
    elif head.sequence_number != len(records) or head.audit_head != org.audit_head:
        return False
    if not records:
        return org.audit_head == "0" * 64 and (
            head is None or (head.sequence_number == 0 and head.audit_head == "0" * 64)
        )
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
        key_ver = getattr(record, "key_version", 1) or 1
        audit_key = derive_audit_key(settings.audit_secret.get_secret_value(), key_ver)
        expected = hmac.new(
            audit_key, message.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, record.entry_hash):
            return False
        previous = record.entry_hash
        visited += 1

    expected_head = head.audit_head if head else (org.audit_head if org else "")
    return visited == len(records) and previous == expected_head


def create_audit_checkpoint(db, settings, organization_id: str) -> AuditCheckpoint:
    head = db.get(AuditHead, organization_id)
    if not head:
        head = AuditHead(
            organization_id=organization_id,
            audit_head="0" * 64,
            sequence_number=0,
            updated_at=now(),
        )
        db.add(head)
        db.flush()

    stamp = now()
    checkpoint_payload = {
        "organization_id": organization_id,
        "sequence_number": head.sequence_number,
        "head_entry_hash": head.audit_head,
        "timestamp": stamp.isoformat(),
    }
    from aegis.crypto import ed25519_sign_canonical, get_controller_signing_key
    ctrl_priv = get_controller_signing_key(settings)
    signature = ed25519_sign_canonical(ctrl_priv, checkpoint_payload)
    checkpoint_hash = hashlib.sha256(canonical(checkpoint_payload).encode()).hexdigest()
    checkpoint = AuditCheckpoint(
        id=uid(),
        organization_id=organization_id,
        created_at=stamp,
        sequence_number=head.sequence_number,
        head_entry_hash=head.audit_head,
        checkpoint_hash=checkpoint_hash,
        signature=signature,
        key_version=getattr(settings, "audit_key_version", 1),
    )
    db.add(checkpoint)
    db.flush()
    return checkpoint


def verify_audit_checkpoint(db, settings, checkpoint: AuditCheckpoint) -> bool:
    from datetime import UTC

    from aegis.crypto import ed25519_verify_canonical, get_controller_public_key_hex

    stamp = checkpoint.created_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)

    ctrl_pub = get_controller_public_key_hex(settings)
    payload = {
        "organization_id": checkpoint.organization_id,
        "sequence_number": checkpoint.sequence_number,
        "head_entry_hash": checkpoint.head_entry_hash,
        "timestamp": stamp.isoformat(),
    }
    expected_hash = hashlib.sha256(canonical(payload).encode()).hexdigest()
    if not hmac.compare_digest(expected_hash, checkpoint.checkpoint_hash):
        return False
    return ed25519_verify_canonical(ctrl_pub, checkpoint.signature, payload)


def rate_limit(request: Request, key: str, maximum: int, seconds: int = 60):
    sanitized_key = token_hash(str(key)[:256])
    bucket = f"aegis:rate:{sanitized_key}:{int(time.time()) // seconds}"
    redis = request.app.state.redis
    if redis:
        pipe = redis.pipeline()
        pipe.incr(bucket)
        pipe.expire(bucket, seconds * 2)
        count = pipe.execute()[0]
    else:
        # Atomic DB operation for counter creation and increment across PostgreSQL & SQLite
        now_ts = time.time()
        expires_ts = now_ts + seconds * 2
        with request.app.state.sessions.begin() as db:
            bind = db.get_bind()
            if bind.dialect.name == "postgresql":
                from sqlalchemy.dialects.postgresql import insert as pg_insert

                res = db.execute(
                    pg_insert(WindowState)
                    .values(key=bucket, data=[1], expires=expires_ts)
                    .on_conflict_do_nothing()
                )
            else:
                from sqlalchemy.dialects.sqlite import insert as sqlite_insert

                res = db.execute(
                    sqlite_insert(WindowState)
                    .values(key=bucket, data=[1], expires=expires_ts)
                    .on_conflict_do_nothing()
                )
            if res.rowcount > 0:
                count = 1
            else:
                row = db.scalar(
                    select(WindowState).where(WindowState.key == bucket).with_for_update()
                )
                if row:
                    count = (row.data[0] if row.data else 0) + 1
                    row.data = [count]
                    row.expires = expires_ts
                else:
                    count = 1
    if count > maximum:
        raise HTTPException(429, "Rate limit exceeded; retry later", headers={"Retry-After": str(seconds)})


@dataclass
class Principal:
    user: User
    permissions: set[str]
    session_id: str | None = None
    api_key_id: str | None = None
    agent: Agent | None = None

    @property
    def organization_id(self):
        if self.agent is not None:
            return self.agent.organization_id
        return self.user.organization_id


def authenticate(request: Request, db=Depends(db_session)) -> Principal:
    authorization = request.headers.get("authorization", "")
    bearer = authorization[7:] if authorization.startswith("Bearer ") else None
    token = bearer or request.cookies.get("aegis_session")
    if not token or len(token) > 200:
        raise HTTPException(401, "Authentication required")

    # 1. Endpoint Agent Authentication
    if token.startswith("aegis_agt_"):
        agent = db.scalar(
            select(Agent).where(
                Agent.auth_token_hash == token_hash(token),
                Agent.status == "ENROLLED",
            )
        )
        if not agent:
            raise HTTPException(401, "Agent authentication failed: token invalid or agent revoked")

        agent_user = User(
            id=f"agt-user-{agent.id}",
            organization_id=agent.organization_id,
            username=f"agent:{agent.name}",
            password_hash="",
            role="VIEWER",
            active=True,
        )
        agent_permissions = {"agents.heartbeat", "agents.poll", "agents.receipt"}
        principal = Principal(
            user=agent_user,
            permissions=agent_permissions,
            agent=agent,
        )
        request.state.principal = principal
        return principal

    # 2. Standard User Session or API Key Authentication
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
