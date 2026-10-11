import pytest
from sqlalchemy import select

from aegis.db import AuditLog, Entity, SessionToken, User
from aegis.security import ROLES, token_hash
from tests.test_pipeline import attack_chain


@pytest.mark.parametrize(
    "resource",
    [
        "alerts",
        "incidents",
        "cases",
        "entities",
        "rules",
        "iocs",
        "reports",
        "playbooks",
        "collectors",
        "audit",
        "users",
    ],
)
def test_unauthenticated_resources_denied(system, resource):
    client = system["client"]
    client.headers.pop("Authorization")
    assert client.get("/api/v1/" + resource).status_code == 401


@pytest.mark.parametrize("role", list(ROLES))
@pytest.mark.parametrize(
    "resource,permission",
    [
        ("alerts", "alerts.read"),
        ("rules", "rules.read"),
        ("users", "users.manage"),
        ("audit", "audit.read"),
        ("system/config", "system.read"),
        ("system/metrics", "system.manage"),
    ],
)
def test_rbac_read_matrix(system, role, resource, permission):
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"][role]
    assert client.get("/api/v1/" + resource).status_code == (200 if permission in ROLES[role] else 403)


@pytest.mark.parametrize("role", list(ROLES))
@pytest.mark.parametrize(
    "endpoint,permission,body",
    [
        ("events/ingest", "events.ingest", {"events": [{"source": "matrix", "raw_event": "message"}]}),
        ("iocs", "iocs.write", {"type": "ip", "value": "203.0.113.25"}),
        ("cases", "cases.write", {"title": "Matrix test case"}),
        (
            "users",
            "users.manage",
            {"username": "matrix-new-user", "password": "secure-matrix-password", "role": "VIEWER"},
        ),
    ],
)
def test_rbac_write_matrix(system, role, endpoint, permission, body):
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"][role]
    response = client.post("/api/v1/" + endpoint, json=body)
    assert (response.status_code < 300) if permission in ROLES[role] else response.status_code == 403, (
        response.text
    )


def test_login_csrf_rotation_logout_and_no_plaintext(system):
    client = system["client"]
    client.headers.pop("Authorization")
    response = client.post(
        "/api/v1/auth/login", json={"username": "super_admin", "password": "correct-test-password-123"}
    )
    assert response.status_code == 200, response.text
    assert "HttpOnly" in response.headers.get_list("set-cookie")[0]
    token = response.json()["access_token"]
    assert client.post("/api/v1/auth/logout").status_code == 403
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    client.headers["Origin"] = "https://evil.example"
    assert client.post("/api/v1/auth/refresh").status_code == 403
    client.headers["Origin"] = "http://localhost:3000"
    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    with system["app"].state.sessions() as db:
        assert db.scalar(select(SessionToken).where(SessionToken.token_hash == token_hash(token))) is None
        assert all(user.password_hash.startswith("$argon2id$") for user in db.scalars(select(User)))
    client.headers["X-CSRF-Token"] = refreshed.json()["csrf_token"]
    assert client.post("/api/v1/auth/logout").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_login_lockout(system):
    client = system["client"]
    client.headers.pop("Authorization")
    for _ in range(5):
        assert (
            client.post("/api/v1/auth/login", json={"username": "analyst", "password": "wrong"}).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "analyst", "password": "correct-test-password-123"}
        ).status_code
        == 401
    )


def test_cross_tenant_idor_and_audit_integrity(system):
    attack_chain(system)
    client = system["client"]
    alert = client.get("/api/v1/alerts").json()["items"][0]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
    assert client.get(f"/api/v1/alerts/{alert['id']}").status_code == 404
    assert client.get(f"/api/v1/investigations/{alert['id']}").status_code == 404
    assert (
        client.patch(
            f"/api/v1/alerts/{alert['id']}/status", json={"status": "CLOSED", "revision": 1}
        ).status_code
        == 404
    )
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    assert client.get("/api/v1/audit/verify").json()["valid"]
    with system["app"].state.sessions.begin() as db:
        row = db.scalar(select(AuditLog).where(AuditLog.organization_id == system["org"]))
        row.action = "tampered"
    assert client.get("/api/v1/audit/verify").json()["valid"] is False


def test_approval_requires_independent_human_and_execution_is_idempotent(system):
    attack_chain(system)
    client = system["client"]
    with system["app"].state.sessions() as db:
        entity = db.scalar(select(Entity).where(Entity.type == "host"))
    body = {"action": "isolate_host", "target": entity.id}
    response = client.post(
        "/api/v1/playbooks/request", json=body, headers={"Idempotency-Key": "test-response-request"}
    )
    assert response.status_code == 200, response.text
    identifier = response.json()["id"]
    assert response.json()["status"] == "APPROVAL_REQUIRED"
    assert client.post(f"/api/v1/playbooks/{identifier}/execute").status_code == 409
    assert client.post(f"/api/v1/playbooks/{identifier}/approve").status_code == 403
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SOC_MANAGER"]
    assert client.post(f"/api/v1/playbooks/{identifier}/approve").status_code == 200
    result = client.post(f"/api/v1/playbooks/{identifier}/execute")
    assert result.status_code == 200, result.text
    assert result.json()["result"]["enforced_externally"] is False
    assert client.post(f"/api/v1/playbooks/{identifier}/execute").json() == result.json()
    assert (
        client.post(
            "/api/v1/playbooks/request",
            json={"action": "shell", "target": "rm -rf /"},
            headers={"Idempotency-Key": "test-malicious-action"},
        ).status_code
        == 422
    )


def test_size_limits_invalid_iocs_and_injection(system):
    client = system["client"]
    response = client.post(
        "/api/v1/events/ingest", content=b"x" * 2000001, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert client.post("/api/v1/iocs", json={"type": "ip", "value": "127.0.0.1; whoami"}).status_code == 422
    assert client.post("/api/v1/iocs", json={"type": "url", "value": "file:///etc/passwd"}).status_code == 422
    response = client.get("/api/v1/alerts", params={"q": "' OR 1=1 --"})
    assert response.status_code == 200 and response.json()["items"] == []
    assert (
        client.post(
            "/api/v1/hunts/parse", json={"question": 'username = "admin"; DROP TABLE users'}
        ).status_code
        == 422
    )


def test_api_keys_scoped_hashed_and_revocable(system):
    client = system["client"]
    response = client.post(
        "/api/v1/auth/api-keys", json={"name": "ingestion", "permissions": ["events.ingest"], "days": 1}
    )
    assert response.status_code == 200
    key = response.json()
    client.headers["Authorization"] = "Bearer " + key["key"]
    assert client.get("/api/v1/alerts").status_code == 403
    assert (
        client.post(
            "/api/v1/events/ingest", json={"events": [{"source": "api-key", "raw_event": "example"}]}
        ).status_code
        == 202
    )
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]
    assert client.delete(f"/api/v1/auth/api-keys/{key['id']}").status_code == 200
    client.headers["Authorization"] = "Bearer " + key["key"]
    assert client.get("/api/v1/auth/me").status_code == 401


def test_reset_token_single_use(system):
    client = system["client"]
    target = system["users"]["ANALYST"].id
    issued = client.post(f"/api/v1/users/{target}/password-reset")
    assert issued.status_code == 200
    body = {"token": issued.json()["token"], "password": "replacement-strong-password"}
    assert client.post("/api/v1/auth/password-reset/complete", json=body).status_code == 200
    assert client.post("/api/v1/auth/password-reset/complete", json=body).status_code == 400
