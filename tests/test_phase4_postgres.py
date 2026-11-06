"""Bounded real PostgreSQL schedules; explicitly unavailable without an isolated test URL."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from aegis.config import Settings
from aegis.db import AuditHead, Base, Organization
from aegis.db_safety import validate_test_database_url
from aegis.security import audit, verify_audit
from aegis.soar import lock_tenant
from tests.test_titan_phase4 import test_admission_waits_for_transaction_outcome as admission_schedule

pytestmark = pytest.mark.integration


@pytest.fixture
def phase4_pg():
    url = os.environ.get("AEGIS_POSTGRES_TEST_URL")
    if not url:
        pytest.skip("Requires AEGIS_POSTGRES_TEST_URL for isolated PostgreSQL")
    validate_test_database_url(url, environment="testing")
    engine = create_engine(
        url, connect_args={"connect_timeout": 3, "options": "-c lock_timeout=3000 -c statement_timeout=8000"}
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as db:
        org = Organization(name="phase4-" + uuid4().hex)
        db.add(org)
        db.flush()
        org_id = org.id
    settings = Settings(
        environment="testing",
        database_url=url,
        _env_file=None,
        audit_secret="phase4-pg-integrity-key-32-characters",
    )
    yield {
        "app": SimpleNamespace(state=SimpleNamespace(sessions=sessions)),
        "org": org_id,
        "settings": settings,
    }
    engine.dispose()


@pytest.mark.parametrize("rollback", [False, True])
def test_postgres_phase4_admission(phase4_pg, monkeypatch, rollback):
    admission_schedule(phase4_pg, monkeypatch, rollback)


def test_postgres_phase4_first_audit_head_gate(phase4_pg):
    sessions = phase4_pg["app"].state.sessions
    org, settings = phase4_pg["org"], phase4_pg["settings"]
    attempted = Event()
    engine = sessions.kw["bind"]

    def before_sql(conn, cursor, statement, parameters, context, executemany):
        if conn.info.get("contender") and statement.lower().startswith("update organizations"):
            attempted.set()

    def contender():
        with sessions.begin() as db:
            db.connection().info["contender"] = True
            try:
                audit(db, settings, org, "contender", "test.audit")
            finally:
                db.connection().info.pop("contender", None)

    event.listen(engine, "before_cursor_execute", before_sql)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with sessions.begin() as db:
                lock_tenant(db, org)
                future = pool.submit(contender)
                assert attempted.wait(5)
                audit(db, settings, org, "owner", "test.audit")
            future.result(timeout=8)
    finally:
        event.remove(engine, "before_cursor_execute", before_sql)
    with sessions() as db:
        assert db.scalar(select(AuditHead.sequence_number).where(AuditHead.organization_id == org)) == 2
        assert verify_audit(db, settings, org)
