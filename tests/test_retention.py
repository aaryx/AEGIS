from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from aegis.db import (
    IOC,
    Case,
    CaseEvidence,
    Entity,
    EntityRelationship,
    EventRecord,
    IOCMatch,
    Organization,
    PasswordReset,
    SearchJob,
    SessionToken,
    User,
    WindowState,
)
from aegis.retention import RetentionEngine
from aegis.security import verify_audit


def test_retention_dry_run_and_execution_with_legal_hold(system):
    sessions = system["app"].state.sessions
    settings = system["settings"]
    retention_engine = RetentionEngine(settings, sessions, system["app"].state.storage)

    with sessions.begin() as db:
        org = db.scalar(select(Organization).limit(1))
        user = db.scalar(select(User).where(User.organization_id == org.id).limit(1))

        now_utc = datetime.now(UTC)
        old_time = now_utc - timedelta(days=120)
        recent_time = now_utc - timedelta(days=10)

        # 1. Create an old event that should be pruned
        ev_old = EventRecord(
            id="ev-to-prune-01",
            organization_id=org.id,
            timestamp=old_time,
            evidence_hash="0" * 64,
            source="test",
            payload={"event_id": "ev-to-prune-01", "message": "Old expired event"},
            state="PROCESSED",
        )
        # 2. Create an old event that is protected under LEGAL HOLD (CaseEvidence)
        ev_held = EventRecord(
            id="ev-legal-hold-02",
            organization_id=org.id,
            timestamp=old_time,
            evidence_hash="1" * 64,
            source="test",
            payload={"event_id": "ev-legal-hold-02", "message": "Old event under legal hold"},
            state="PROCESSED",
        )
        # 3. Create a recent event that is within the retention window
        ev_recent = EventRecord(
            id="ev-recent-03",
            organization_id=org.id,
            timestamp=recent_time,
            evidence_hash="2" * 64,
            source="test",
            payload={"event_id": "ev-recent-03", "message": "Recent event"},
            state="PROCESSED",
        )

        db.add_all([ev_old, ev_held, ev_recent])
        db.flush()

        # Add related records for old event
        db.add(SearchJob(organization_id=org.id, event_id=ev_old.id, state="INDEXED"))
        ent_host = Entity(organization_id=org.id, type="host", value="HOST-01", risk_score=0)
        ent_ip = Entity(organization_id=org.id, type="ip", value="10.0.0.1", risk_score=0)
        db.add_all([ent_host, ent_ip])
        db.flush()
        db.add(
            EntityRelationship(
                organization_id=org.id,
                source_id=ent_host.id,
                target_id=ent_ip.id,
                event_id=ev_old.id,
            )
        )
        ioc = IOC(
            organization_id=org.id,
            type="ip",
            value="198.51.100.99",
            source="test",
            confidence=90,
            severity="high",
            description="malicious ip",
            expires=None,
        )
        db.add(ioc)
        db.flush()
        db.add(IOCMatch(ioc_id=ioc.id, event_id=ev_old.id))

        # Put ev_held under legal custody via CaseEvidence
        test_case = Case(organization_id=org.id, title="Active Investigation 2026", status="OPEN", assignee=user.id)
        db.add(test_case)
        db.flush()
        db.add(
            CaseEvidence(
                organization_id=org.id,
                case_id=test_case.id,
                resource_type="event",
                resource_id=ev_held.id,
                evidence_hash=ev_held.evidence_hash,
                attached_by=user.id,
            )
        )

        # Add transient states: expired session and window state
        past_epoch = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
        db.add(SessionToken(organization_id=org.id, user_id=user.id, token_hash="expired-tok-hash", csrf_hash="csrf-hash", expires=past_epoch))
        db.add(PasswordReset(organization_id=org.id, user_id=user.id, token_hash="expired-pr-hash", expires=past_epoch))
        db.add(WindowState(key="expired:key:01", data=[1], expires=past_epoch))

    # --- Phase 1: Dry Run Verification ---
    dry_summaries = retention_engine.run_cycle(dry_run=True, actor="operator.test")
    assert len(dry_summaries) >= 1
    org_dry = next(s for s in dry_summaries if s.organization_id == org.id)
    assert org_dry.dry_run is True
    assert org_dry.events_eligible == 2
    assert org_dry.events_held == 1
    assert org_dry.events_deleted == 0
    assert org_dry.sessions_deleted == 1
    assert org_dry.window_states_deleted == 1

    # Verify nothing was deleted in DB during dry-run
    with sessions() as db:
        assert db.get(EventRecord, ev_old.id) is not None
        assert db.get(EventRecord, ev_held.id) is not None
        assert db.get(EventRecord, ev_recent.id) is not None
        assert db.get(WindowState, "expired:key:01") is not None

    # --- Phase 2: Live Execution Verification ---
    live_summaries = retention_engine.run_cycle(dry_run=False, actor="operator.test")
    org_live = next(s for s in live_summaries if s.organization_id == org.id)
    assert org_live.dry_run is False
    assert org_live.events_deleted == 1
    assert org_live.events_held == 1

    with sessions() as db:
        # Expired non-held event was pruned
        assert db.get(EventRecord, ev_old.id) is None
        assert db.scalar(select(SearchJob).where(SearchJob.event_id == ev_old.id)) is None
        assert db.scalar(select(EntityRelationship).where(EntityRelationship.event_id == ev_old.id)) is None
        assert db.scalar(select(IOCMatch).where(IOCMatch.event_id == ev_old.id)) is None

        # Legal hold event was preserved!
        assert db.get(EventRecord, ev_held.id) is not None
        # Recent event was preserved!
        assert db.get(EventRecord, ev_recent.id) is not None

        # Expired transient records were deleted
        assert db.get(WindowState, "expired:key:01") is None
        assert db.scalar(select(SessionToken).where(SessionToken.token_hash == "expired-tok-hash")) is None
        assert db.scalar(select(PasswordReset).where(PasswordReset.token_hash == "expired-pr-hash")) is None

        # Audit chain remained valid and verifiable
        assert verify_audit(db, settings, org.id) is True


def test_retention_api_endpoint(system):
    client = system["client"]
    client.headers["Authorization"] = "Bearer " + system["tokens"]["SUPER_ADMIN"]

    # Call dry-run via API
    resp = client.post("/api/v1/system/retention?dry_run=true")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "ok"
    assert data["dry_run"] is True
    assert "results" in data

    # Ordinary ANALYST cannot trigger maintenance cleanup
    client.headers["Authorization"] = "Bearer " + system["tokens"]["ANALYST"]
    denied = client.post("/api/v1/system/retention")
    assert denied.status_code == 403
