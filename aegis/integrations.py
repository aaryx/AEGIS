"""Explicitly configured HTTPS integrations, bounded I/O and transactional delivery records."""

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field, model_validator
from sqlalchemy import exists, select

from aegis.db import IOC, Delivery, Integration, Notification, as_dict, uid
from aegis.investigation import owned
from aegis.parsers import canonical, digest
from aegis.schemas import IOCInput, StrictModel
from aegis.security import audit, db_session, rate_limit, require


class IntegrationInput(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str = Field(pattern=r"^(webhook|slack|teams|ioc_feed)$")
    endpoint: str = Field(min_length=1, max_length=2048)
    secret_env: str | None = Field(None, pattern=r"^AEGIS_INTEGRATION_[A-Z0-9_]{1,70}$")
    enabled: bool = True
    revision: int = Field(0, ge=0)

    @model_validator(mode="after")
    def signed_webhook(self):
        if self.kind == "webhook" and not self.secret_env:
            raise ValueError("Generic webhooks require a signing secret environment reference")
        return self


def validate_endpoint(settings, endpoint: str):
    parsed = urlsplit(endpoint)
    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        raise ValueError("Integration URL must not contain credentials or a fragment")
    if parsed.scheme != "https" and not (settings.environment == "testing" and parsed.scheme == "http"):
        raise ValueError("Integration endpoints require HTTPS")
    if parsed.hostname.casefold() not in {host.casefold() for host in settings.integration_allowed_hosts}:
        raise ValueError("Integration host is not in the operator-managed allowlist")
    if any(ord(char) < 32 for char in endpoint):
        raise ValueError("Control characters in URL")
    return parsed


def request_bytes(settings, endpoint, method="GET", body=None, headers=None):
    """Pin resolved addresses for this request; TLS validates the configured hostname.

    Private endpoints require an explicit operator host allowlist just like public
    endpoints. Link-local/metadata and multicast addresses are always rejected.
    """
    parsed = validate_endpoint(settings, endpoint)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Integration resolved to a prohibited address")
    if not addresses:
        raise ValueError("Integration host has no addresses")
    timeout = settings.integration_timeout_seconds
    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    sock = socket.create_connection((str(addresses[0][4][0]), port), timeout=timeout)
    try:
        if parsed.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
        connection.sock = sock
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError(f"Integration returned HTTP {response.status}")
        result = bytearray()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Integration response deadline exceeded")
            sock.settimeout(remaining)
            chunk = response.read1(min(65536, settings.integration_max_bytes + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > settings.integration_max_bytes:
                raise ValueError("Integration response is too large")
        return bytes(result)
    finally:
        connection.close()
        sock.close()


def secret_value(integration):
    if not integration.secret_env:
        return None
    secret = os.environ.get(integration.secret_env)
    if not secret or len(secret) < 24:
        raise ValueError("Configured integration secret is missing or shorter than 24 characters")
    return secret


def deliver(settings, integration, notification, delivery_id):
    payload = {
        "id": notification.id,
        "title": notification.title,
        "resource_id": notification.resource_id,
        "organization_id": notification.organization_id,
    }
    if integration.kind == "slack":
        payload = {
            "text": notification.title,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "plain_text",
                        "text": f"{notification.title}\nResource: {notification.resource_id}",
                    },
                }
            ],
        }
    elif integration.kind == "teams":
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": [
                            {"type": "TextBlock", "text": notification.title, "wrap": True},
                            {
                                "type": "TextBlock",
                                "text": "Resource: " + notification.resource_id,
                                "wrap": True,
                            },
                        ],
                    },
                }
            ],
        }
    encoded = canonical(payload).encode()
    headers = {"Content-Type": "application/json", "Idempotency-Key": delivery_id}
    secret = secret_value(integration)
    if integration.kind == "webhook":
        stamp = str(int(time.time()))
        signature = hmac.new(secret.encode(), stamp.encode() + b"." + encoded, hashlib.sha256).hexdigest()
        headers.update({"X-Aegis-Timestamp": stamp, "X-Aegis-Signature": "sha256=" + signature})
    request_bytes(settings, integration.endpoint, "POST", encoded, headers)


def dispatch_once(settings, sessions):
    """Discover undelivered notifications and retry independently of event processing."""
    with sessions.begin() as db:
        integrations = list(
            db.scalars(
                select(Integration)
                .where(Integration.enabled.is_(True), Integration.kind.in_(["webhook", "slack", "teams"]))
                .with_for_update(skip_locked=True)
                .limit(100)
            )
        )
        for integration in integrations:
            missing = select(Notification).where(
                Notification.organization_id == integration.organization_id,
                Notification.created_at >= integration.created_at,
                ~exists().where(
                    Delivery.notification_id == Notification.id, Delivery.integration_id == integration.id
                ),
            )
            for notification in db.scalars(
                missing.order_by(Notification.created_at, Notification.id).limit(100)
            ):
                db.add(
                    Delivery(
                        organization_id=integration.organization_id,
                        integration_id=integration.id,
                        notification_id=notification.id,
                    )
                )
    with sessions.begin() as db:
        jobs = list(
            db.scalars(
                select(Delivery)
                .where(Delivery.state.in_(["PENDING", "RETRY"]), Delivery.available_at <= time.time())
                .with_for_update(skip_locked=True)
                .limit(20)
            )
        )
        for job in jobs:
            integration = db.get(Integration, job.integration_id)
            if not integration.enabled:
                job.state = "CANCELLED"
                continue
            notification = db.get(Notification, job.notification_id)
            try:
                deliver(settings, integration, notification, job.id)
            except Exception as exc:
                job.attempts += 1
                job.last_error = type(exc).__name__
                job.state = "DEAD" if job.attempts >= settings.integration_max_attempts else "RETRY"
                job.available_at = time.time() + min(3600, 2**job.attempts)
                integration.status, integration.last_error = "DEGRADED", job.last_error
            else:
                job.state, job.delivered_at, job.last_error = "DELIVERED", time.time(), None
                integration.status, integration.last_success, integration.last_error = (
                    "HEALTHY",
                    time.time(),
                    None,
                )
            audit(
                db,
                settings,
                job.organization_id,
                "notification-worker",
                "notifications.delivery",
                job.id,
                result=job.state,
                details={"integration_id": integration.id, "attempts": job.attempts},
            )
        return len(jobs)


def sync_feed(db, settings, integration, actor, request=None):
    headers = {"Accept": "application/json"}
    secret = secret_value(integration)
    if secret:
        headers["Authorization"] = "Bearer " + secret
    payload = json.loads(request_bytes(settings, integration.endpoint, headers=headers))
    if not isinstance(payload, list) or len(payload) > 5000:
        raise ValueError("IOC feed must be an array of at most 5000 indicators")
    indicators = [IOCInput.model_validate(item) for item in payload]
    existing = {
        (row.type, row.value): row
        for row in db.scalars(select(IOC).where(IOC.organization_id == integration.organization_id))
    }
    added = 0
    for indicator in indicators:
        key = (indicator.type, indicator.value)
        if key in existing:
            continue  # A feed cannot silently replace an analyst's indicator or expiration.
        row = IOC(organization_id=integration.organization_id, **indicator.model_dump())
        db.add(row)
        existing[key] = row
        added += 1
    integration.status, integration.last_success, integration.last_error = "HEALTHY", time.time(), None
    audit(
        db,
        settings,
        integration.organization_id,
        actor,
        "iocs.feed_sync",
        integration.id,
        details={"added": added, "received": len(indicators), "feed_hash": digest(payload)},
        request=request,
    )
    return {"received": len(indicators), "added": added}


router = APIRouter(prefix="/api/v1", tags=["integrations"])


def public_integration(row):
    # Vendor webhook URLs may contain tokens; never return their path/query.
    result = as_dict(row)
    result["endpoint"] = urlsplit(row.endpoint).hostname
    return result


@router.get("/integrations")
def list_integrations(
    limit: int = Query(50, ge=1, le=200),
    cursor: str = "",
    principal=Depends(require("integrations.manage")),
    db=Depends(db_session),
):
    rows = list(
        db.scalars(
            select(Integration)
            .where(Integration.organization_id == principal.organization_id, Integration.id > cursor)
            .order_by(Integration.id)
            .limit(limit + 1)
        )
    )
    return {
        "items": [public_integration(row) for row in rows[:limit]],
        "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
    }


@router.put("/integrations/{integration_id}")
def save_integration(
    integration_id: str,
    data: IntegrationInput,
    request: Request,
    principal=Depends(require("integrations.manage")),
    db=Depends(db_session),
):
    settings = request.app.state.settings
    validate_endpoint(settings, data.endpoint)
    if integration_id == "new":
        if data.revision:
            raise HTTPException(409, "New integrations require revision zero")
        row = Integration(id=uid(), organization_id=principal.organization_id, revision=0)
        db.add(row)
    else:
        row = owned(db, Integration, integration_id, principal.organization_id)
        db.refresh(row, with_for_update=True)
        if row.revision != data.revision:
            raise HTTPException(409, "Integration changed; reload before saving")
    for field, value in data.model_dump(exclude={"revision"}).items():
        setattr(row, field, value)
    row.revision += 1
    row.status = "UNKNOWN"
    audit(
        db,
        settings,
        principal.organization_id,
        principal.user.id,
        "integrations.update",
        row.id,
        details={"kind": row.kind, "revision": row.revision},
        request=request,
    )
    db.commit()
    return public_integration(row)


@router.post("/integrations/{integration_id}/sync")
def sync_integration(
    integration_id: str,
    request: Request,
    principal=Depends(require("integrations.manage", "iocs.write")),
    db=Depends(db_session),
):
    rate_limit(request, "feed:" + principal.user.id, 5, 3600)
    row = owned(db, Integration, integration_id, principal.organization_id)
    if row.kind != "ioc_feed" or not row.enabled:
        raise HTTPException(409, "Integration is not an enabled IOC feed")
    result = sync_feed(db, request.app.state.settings, row, principal.user.id, request)
    db.commit()
    return result


@router.get("/deliveries")
def deliveries(
    limit: int = Query(50, ge=1, le=200),
    cursor: str = "",
    principal=Depends(require("integrations.manage")),
    db=Depends(db_session),
):
    rows = list(
        db.scalars(
            select(Delivery)
            .where(Delivery.organization_id == principal.organization_id, Delivery.id > cursor)
            .order_by(Delivery.id)
            .limit(limit + 1)
        )
    )
    return {
        "items": [as_dict(row) for row in rows[:limit]],
        "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
    }


@router.post("/deliveries/{delivery_id}/retry")
def retry_delivery(
    delivery_id: str,
    request: Request,
    principal=Depends(require("integrations.manage")),
    db=Depends(db_session),
):
    row = owned(db, Delivery, delivery_id, principal.organization_id)
    db.refresh(row, with_for_update=True)
    if row.state != "DEAD":
        raise HTTPException(409, "Only dead-lettered deliveries can be retried")
    row.state, row.available_at, row.attempts = "PENDING", 0, 0
    audit(
        db,
        request.app.state.settings,
        principal.organization_id,
        principal.user.id,
        "notifications.retry",
        row.id,
        request=request,
    )
    db.commit()
    return as_dict(row)
