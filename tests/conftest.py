import pytest
from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.config import Settings
from aegis.db import Organization, User
from aegis.pipeline import seed_rules
from aegis.security import PASSWORDS, issue_session
from aegis.worker import process_once


@pytest.fixture
def system(tmp_path):
    settings = Settings(
        environment="testing",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        audit_secret="test-audit-integrity-key-at-least-32-characters",
        _env_file=None,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.sessions.begin() as db:
            org = Organization(name="Test organization")
            other = Organization(name="Other organization")
            db.add_all([org, other])
            db.flush()
            users, tokens = {}, {}
            encoded = PASSWORDS.hash("correct-test-password-123")
            for role in (
                "SUPER_ADMIN",
                "SECURITY_ADMIN",
                "SOC_MANAGER",
                "SENIOR_ANALYST",
                "ANALYST",
                "VIEWER",
            ):
                user = User(organization_id=org.id, username=role.lower(), password_hash=encoded, role=role)
                db.add(user)
                db.flush()
                users[role] = user
                tokens[role], _ = issue_session(db, user, settings)
            outsider = User(
                organization_id=other.id, username="outsider", password_hash=encoded, role="SUPER_ADMIN"
            )
            db.add(outsider)
            db.flush()
            tokens["OUTSIDER"], _ = issue_session(db, outsider, settings)
            seed_rules(db, org.id)
        client.headers["Authorization"] = "Bearer " + tokens["SUPER_ADMIN"]
        yield {
            "app": app,
            "client": client,
            "tokens": tokens,
            "users": users,
            "org": org.id,
            "other": other.id,
            "settings": settings,
        }


def drain(system):
    app = system["app"]
    for _ in range(20):
        count = process_once(system["settings"], app.state.sessions, app.state.storage)
        if not count:
            return
    raise AssertionError("Worker failed to drain test queue")
