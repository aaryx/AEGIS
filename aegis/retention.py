"""AEGIS Data Lifecycle and Automated Retention Engine.

Enforces tenant-scoped retention policies, protects evidence under legal hold,
performs bounded resumable deletions, cleans transient states, and provides
verifiable audit trails.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from aegis.config import Settings, get_settings
from aegis.db import (
    Alert,
    AlertEvent,
    CaseEvidence,
    EntityRelationship,
    EventRecord,
    IOCMatch,
    Organization,
    PasswordReset,
    SearchJob,
    SessionToken,
    WindowState,
    database,
)
from aegis.observability import configure_logging
from aegis.security import audit
from aegis.storage import LocalStorage, OpenSearchStorage

logger = logging.getLogger("aegis.retention")


@dataclass
class RetentionSummary:
    organization_id: str
    dry_run: bool
    events_eligible: int = 0
    events_held: int = 0
    events_deleted: int = 0
    search_jobs_deleted: int = 0
    relationships_deleted: int = 0
    ioc_matches_deleted: int = 0
    window_states_deleted: int = 0
    sessions_deleted: int = 0
    password_resets_deleted: int = 0
    opensearch_indices_deleted: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RetentionEngine:
    """Production data lifecycle engine with legal hold preservation and auditability."""

    def __init__(self, settings: Settings, sessions: Any, storage: Any = None) -> None:
        self.settings = settings
        self.sessions = sessions
        self.storage = storage

    def prune_transient_state(self, db: Session, now_ts: float | None = None, dry_run: bool = False) -> dict[str, int]:
        current = now_ts or time.time()
        ws_count = db.scalar(select(func.count()).select_from(WindowState).where(WindowState.expires < current)) or 0
        sess_count = db.scalar(select(func.count()).select_from(SessionToken).where(SessionToken.expires < current)) or 0
        pr_count = db.scalar(select(func.count()).select_from(PasswordReset).where(PasswordReset.expires < current)) or 0

        if not dry_run:
            if ws_count:
                db.execute(delete(WindowState).where(WindowState.expires < current))
            if sess_count:
                db.execute(delete(SessionToken).where(SessionToken.expires < current))
            if pr_count:
                db.execute(delete(PasswordReset).where(PasswordReset.expires < current))

        return {
            "window_states": ws_count,
            "sessions": sess_count,
            "password_resets": pr_count,
        }

    def get_legal_holds(self, db: Session, organization_id: str) -> set[str]:
        """Collects event IDs protected from deletion by legal custody or active investigation."""
        # 1. Events attached to cases as evidence (supporting both singular and plural forms)
        case_held = set(
            db.scalars(
                select(CaseEvidence.resource_id).where(
                    CaseEvidence.organization_id == organization_id,
                    CaseEvidence.resource_type.in_(["event", "events"]),
                )
            )
        )

        # 2. Events attached to open alerts (NEW, ACKNOWLEDGED, INVESTIGATING, ESCALATED)
        active_alert_events = set(
            db.scalars(
                select(AlertEvent.event_id)
                .join(Alert, Alert.id == AlertEvent.alert_id)
                .where(
                    Alert.organization_id == organization_id,
                    Alert.status.in_(["NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED"]),
                )
            )
        )

        return case_held | active_alert_events

    def prune_organization_events(
        self,
        db: Session,
        organization_id: str,
        cutoff: datetime,
        dry_run: bool = False,
        batch_size: int = 500,
    ) -> RetentionSummary:
        start_time = time.monotonic()
        summary = RetentionSummary(organization_id=organization_id, dry_run=dry_run)

        # Retrieve eligible event candidates older than retention cutoff
        candidate_ids = list(
            db.scalars(
                select(EventRecord.id)
                .where(
                    EventRecord.organization_id == organization_id,
                    EventRecord.timestamp < cutoff,
                )
                .order_by(EventRecord.timestamp.asc())
                .limit(batch_size * 10)  # Scan bounded window per run
            )
        )
        if not candidate_ids:
            summary.duration_seconds = time.monotonic() - start_time
            return summary

        summary.events_eligible = len(candidate_ids)
        protected_ids = self.get_legal_holds(db, organization_id)
        eligible_to_delete = [eid for eid in candidate_ids if eid not in protected_ids]
        summary.events_held = len(candidate_ids) - len(eligible_to_delete)

        if dry_run or not eligible_to_delete:
            summary.duration_seconds = time.monotonic() - start_time
            return summary

        # Perform bounded batch deletions
        for i in range(0, len(eligible_to_delete), batch_size):
            chunk = eligible_to_delete[i : i + batch_size]
            with db.begin_nested():
                # Delete auxiliary and relationship references with explicit tenant scoping
                db.execute(
                    delete(SearchJob).where(
                        SearchJob.event_id.in_(chunk),
                        SearchJob.organization_id == organization_id,
                    )
                )
                db.execute(delete(IOCMatch).where(IOCMatch.event_id.in_(chunk)))
                db.execute(
                    delete(EntityRelationship).where(
                        EntityRelationship.event_id.in_(chunk),
                        EntityRelationship.organization_id == organization_id,
                    )
                )
                db.execute(delete(AlertEvent).where(AlertEvent.event_id.in_(chunk)))

                db.execute(
                    delete(EventRecord).where(
                        EventRecord.id.in_(chunk),
                        EventRecord.organization_id == organization_id,
                    )
                )
                summary.events_deleted += len(chunk)

        summary.duration_seconds = time.monotonic() - start_time
        return summary

    def prune_opensearch_indices(self, retention_days: int, dry_run: bool = False) -> int:
        """Prunes dated OpenSearch daily indices exceeding the retention window."""
        if not self.storage or not isinstance(self.storage, OpenSearchStorage):
            return 0

        cutoff_date = (datetime.now(UTC) - timedelta(days=retention_days)).date()
        client = self.storage.client
        deleted_count = 0
        try:
            indices = client.indices.get(index="aegis-events-*")
            for index_name in indices.keys():
                # Format: aegis-events-YYYY.MM.DD
                parts = index_name.split("-")
                if len(parts) >= 3:
                    date_str = parts[-1]
                    try:
                        idx_date = datetime.strptime(date_str, "%Y.%m.%d").date()
                        if idx_date < cutoff_date:
                            if not dry_run:
                                client.indices.delete(index=index_name)
                                logger.info("Deleted expired OpenSearch index: %s", index_name)
                            deleted_count += 1
                    except ValueError:
                        continue
        except Exception as exc:
            logger.warning("Failed to query or prune OpenSearch indices: %s", exc)

        return deleted_count

    def run_cycle(
        self,
        dry_run: bool = False,
        actor: str = "system.retention",
        request: Any = None,
    ) -> list[RetentionSummary]:
        """Executes a complete data lifecycle retention pass across all organizations."""
        results: list[RetentionSummary] = []
        retention_days = self.settings.retention_days
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)

        with self.sessions.begin() as db:
            from aegis.soar import lock_tenant

            org_ids = list(db.scalars(select(Organization.id).order_by(Organization.id)))
            if not dry_run:
                for org_id in org_ids:
                    lock_tenant(db, org_id)
            # 1. Prune expired transient states globally
            transient = self.prune_transient_state(db, dry_run=dry_run)

            # 2. Iterate each organization for tenant-isolated data retention
            for org_id in org_ids:
                summary = self.prune_organization_events(
                    db,
                    org_id,
                    cutoff=cutoff,
                    dry_run=dry_run,
                    batch_size=getattr(self.settings, "retention_batch_size", 500),
                )
                summary.window_states_deleted = transient["window_states"]
                summary.sessions_deleted = transient["sessions"]
                summary.password_resets_deleted = transient["password_resets"]

                if not dry_run and (summary.events_deleted > 0 or transient["sessions"] > 0):
                    audit(
                        db,
                        self.settings,
                        org_id,
                        actor,
                        "system.retention",
                        resource_id=org_id,
                        details={
                            "retention_days": retention_days,
                            "cutoff": cutoff.isoformat(),
                            "events_deleted": summary.events_deleted,
                            "events_held": summary.events_held,
                            "dry_run": dry_run,
                        },
                        request=request,
                    )
                results.append(summary)

        # 3. OpenSearch index lifecycle pruning if storage provider available
        if self.storage:
            os_deleted = self.prune_opensearch_indices(retention_days, dry_run=dry_run)
            for r in results:
                r.opensearch_indices_deleted = os_deleted

        return results


def main() -> None:
    """Standalone daemon entrypoint for AEGIS retention worker."""
    configure_logging()
    settings = get_settings()
    maintenance_url = getattr(settings, "maintenance_database_url", None) or settings.database_url
    engine, sessions = database(maintenance_url)
    storage = (
        OpenSearchStorage(settings)
        if settings.opensearch_url
        else LocalStorage(sessions)
    )

    retention_engine = RetentionEngine(settings, sessions, storage)
    interval = getattr(settings, "retention_interval_seconds", 3600)
    stopped = threading.Event()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())

    logger.info("Starting AEGIS Retention Worker (retention_days=%d, interval=%ds)", settings.retention_days, interval)
    try:
        while not stopped.is_set():
            try:
                summaries = retention_engine.run_cycle(dry_run=False)
                for s in summaries:
                    logger.info(
                        "Retention cycle completed for org %s: deleted=%d, held=%d, duration=%.2fs",
                        s.organization_id,
                        s.events_deleted,
                        s.events_held,
                        s.duration_seconds,
                    )
            except Exception as exc:
                logger.error("Retention worker cycle error: %s", exc)

            stopped.wait(interval)
    finally:
        engine.dispose()
        logger.info("AEGIS Retention Worker terminated cleanly")


if __name__ == "__main__":
    main()
