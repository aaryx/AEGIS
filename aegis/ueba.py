"""Deterministic UTC-day behavioral analytics. No external enrichment or response actions."""

import hashlib
import ipaddress
import json
import time
from collections import Counter, defaultdict, deque
from datetime import UTC, timedelta
from statistics import median

from sqlalchemy import select

from aegis.db import BehaviorEvidence, BehaviorFinding, BehaviorJob, BehaviorProfile, EventRecord, now
from aegis.soar import lock_tenant

VERSION = 1
DETECTORS = {
    "failure_burst": {"impact": 65, "feature": "authentication failures per UTC day"},
    "new_source_ip": {"impact": 35, "feature": "identity source IP novelty"},
    "new_host": {"impact": 35, "feature": "identity host novelty"},
    "unusual_hour": {"impact": 30, "feature": "authentication UTC hour novelty"},
    "activity_volume": {"impact": 45, "feature": "events per UTC day"},
    "failure_then_success": {"impact": 75, "feature": "5 failures then success within 15 minutes"},
}


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def key(*parts):
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def config(settings):
    return {
        "days": settings.ueba_baseline_days,
        "minimum": settings.ueba_min_observations,
        "minimum_days": settings.ueba_min_active_days,
        "event_limit": settings.ueba_event_limit,
        "version": VERSION,
    }


def clean(value):
    return (
        value
        if isinstance(value, str) and 0 < len(value) <= 254 and not any(ord(c) < 32 for c in value)
        else None
    )


def features(record):
    p = record.payload
    if not isinstance(p, dict):
        return None
    tags = p.get("tags", [])
    metadata = p.get("metadata", {})
    if (
        p.get("collector") == "synthetic"
        or isinstance(tags, list)
        and any(t in tags for t in ("synthetic", "test", "simulation", "replay"))
        or isinstance(metadata, dict)
        and any(metadata.get(t) for t in ("synthetic", "test", "replay"))
    ):
        return None
    user = clean(p.get("username")) or clean(p.get("user_id"))
    host = clean(p.get("host")) or clean(p.get("hostname"))
    ip = clean(p.get("source_ip"))
    try:
        ip = str(ipaddress.ip_address(ip)) if ip else None
    except ValueError:
        ip = None
    entities = [(kind, value) for kind, value in (("user", user), ("host", host), ("ip", ip)) if value]
    return {
        "id": record.id,
        "hash": record.evidence_hash,
        "time": utc(record.timestamp),
        "entities": entities,
        "ip": ip,
        "host": host,
        "auth": p.get("event_category") == "authentication",
        "outcome": p.get("outcome") if p.get("outcome") in ("success", "failure") else "unknown",
    }


def score(impact, deviation, confidence):
    """Priority, never a compromise probability. Max across overlapping detectors."""
    return max(0, min(100, round(impact * (0.5 + 0.5 * confidence) * (0.5 + 0.5 * min(1, deviation / 6)))))


def severity(value):
    return "critical" if value >= 85 else "high" if value >= 65 else "medium" if value >= 40 else "low"


def baseline(rows, start, days, minimum, minimum_days):
    counts = Counter(r["time"].date() for r in rows)
    failures = Counter(r["time"].date() for r in rows if r["auth"] and r["outcome"] == "failure")
    daily = [counts[(start + timedelta(days=i)).date()] for i in range(days)]
    failed = [failures[(start + timedelta(days=i)).date()] for i in range(days)]
    center = median(daily)
    fail_center = median(failed)
    return {
        "start": start.isoformat(),
        "end": (start + timedelta(days=days)).isoformat(),
        "observations": len(rows),
        "active_days": len(counts),
        "sufficient": len(rows) >= minimum and len(counts) >= minimum_days,
        "daily_median": center,
        "daily_mad": median(abs(v - center) for v in daily),
        "failure_median": fail_center,
        "failure_mad": median(abs(v - fail_center) for v in failed),
        "source_ips": sorted({r["ip"] for r in rows if r["ip"]}),
        "hosts": sorted({r["host"] for r in rows if r["host"]}),
        "auth_hours": sorted({r["time"].hour for r in rows if r["auth"]}),
        "auth_observations": sum(r["auth"] for r in rows),
    }


def _builtin_detectors(kind, rows, base):
    """Yield detector, observed, expected, deviation, and exact supporting observations."""
    if not base["sufficient"] or not rows:
        return
    for detector, selected, center, mad, floor in [
        ("activity_volume", rows, base["daily_median"], base["daily_mad"], 10),
        (
            "failure_burst",
            [r for r in rows if r["auth"] and r["outcome"] == "failure"],
            base["failure_median"],
            base["failure_mad"],
            5,
        ),
    ]:
        deviation = (len(selected) - center) / max(1, 1.4826 * mad)
        if len(selected) >= floor and deviation >= 6 and len(selected) > center * 2:
            yield detector, len(selected), center, deviation, selected
    if kind != "user":
        return
    for detector, field, known in [
        ("new_source_ip", "ip", base["source_ips"]),
        ("new_host", "host", base["hosts"]),
    ]:
        selected = [r for r in rows if r[field] and r[field] not in known]
        if known and selected:
            yield detector, sorted({r[field] for r in selected}), known, 3, selected
    auth = [r for r in rows if r["auth"]]
    unusual = [r for r in auth if r["time"].hour not in base["auth_hours"]]
    if base["auth_observations"] >= 20 and len(unusual) >= 3:
        yield "unusual_hour", sorted({r["time"].hour for r in unusual}), base["auth_hours"], 3, unusual
    failures: deque[dict] = deque()
    for row in auth:
        while failures and row["time"] - failures[0]["time"] > timedelta(minutes=15):
            failures.popleft()
        if row["outcome"] == "failure":
            failures.append(row)
        elif row["outcome"] == "success":
            if len(failures) >= 5:
                yield (
                    "failure_then_success",
                    len(failures),
                    "5 failures within 15 minutes before success",
                    6,
                    [*failures, row],
                )
                break
            failures.clear()


# Code-owned extension point: plugins yield the same explainable finding tuple.
# Detector metadata/versions must be registered in DETECTORS; no user code is loaded.
DETECTOR_PLUGINS = (_builtin_detectors,)


def detect(kind, rows, base):
    if not base["sufficient"]:
        return
    ordered = sorted(rows, key=lambda row: (row["time"], row["id"]))
    for plugin in DETECTOR_PLUGINS:
        yield from plugin(kind, ordered, base)


def analyze(db, org, end, cfg, refresh_only=False):
    end = utc(end)
    if end != end.replace(hour=0, minute=0, second=0, microsecond=0):
        raise ValueError("Window end must be UTC midnight")
    current = end - timedelta(days=1)
    start = current - timedelta(days=cfg["days"])
    lock_tenant(db, org)
    records = list(
        db.scalars(
            select(EventRecord)
            .where(
                EventRecord.organization_id == org,
                EventRecord.timestamp >= start,
                EventRecord.timestamp < end,
            )
            .order_by(EventRecord.timestamp, EventRecord.id)
            .limit(cfg["event_limit"] + 1)
        )
    )
    if len(records) > cfg["event_limit"]:
        raise ValueError("Event limit exceeded; no partial baseline was saved")
    groups = defaultdict(list)
    seen = set()
    for record in records:
        row = features(record)
        # evidence_hash covers raw_event only. Identical raw messages at different
        # timestamps are distinct observations, especially syslog/auth telemetry.
        fingerprint = (record.evidence_hash, utc(record.timestamp), record.source)
        if row is None or fingerprint in seen:
            continue
        seen.add(fingerprint)
        for entity in row["entities"]:
            groups[entity].append(row)
    found = 0
    for (kind, entity), rows in sorted(groups.items()):
        history = [r for r in rows if r["time"] < current]
        observed = [r for r in rows if r["time"] >= current]
        base = baseline(history, start, cfg["days"], cfg["minimum"], cfg["minimum_days"])
        pid = key(org, kind, entity)
        profile = db.scalar(
            select(BehaviorProfile).where(BehaviorProfile.organization_id == org, BehaviorProfile.id == pid)
        )
        if not profile:
            profile = BehaviorProfile(
                id=pid,
                organization_id=org,
                entity_type=kind,
                entity=entity,
                window_end=end,
                baseline=base,
                risk_score=0,
            )
            db.add(profile)
            db.flush()
        confidence = round(
            min(1, len(history) / (cfg["minimum"] * 3)) * min(1, base["active_days"] / cfg["days"]), 4
        )
        risks = []
        for detector, value, expected, deviation, evidence in (
            [] if refresh_only else detect(kind, observed, base)
        ):
            fid = key(org, pid, detector, VERSION, end.isoformat())
            finding = db.scalar(
                select(BehaviorFinding).where(
                    BehaviorFinding.organization_id == org, BehaviorFinding.id == fid
                )
            )
            risk = score(DETECTORS[detector]["impact"], deviation, confidence)
            risks.append(risk)
            if finding:
                continue  # Immutable assessment/evidence snapshot; retries never change analyst decisions.
            found += 1
            finding = BehaviorFinding(
                id=fid,
                organization_id=org,
                profile_id=pid,
                detector=detector,
                version=VERSION,
                first_seen=min(r["time"] for r in evidence),
                last_seen=max(r["time"] for r in evidence),
                window_end=end,
                risk_score=risk,
                severity=severity(risk),
                confidence=confidence,
                comparison={
                    "observed": value,
                    "expected": expected,
                    "deviation": deviation,
                    "impact": DETECTORS[detector]["impact"],
                    "baseline": base,
                    "config": cfg,
                    "evidence_count": len(evidence),
                },
                explanation=f"{DETECTORS[detector]['feature']} deviated from the prior {cfg['days']} days. "
                "Review supporting events and related investigations; this does not confirm an attack.",
                status="NEW",
                lifecycle=[],
            )
            db.add(finding)
            db.flush()
            seen_evidence_ids: set[str] = set()
            for row in evidence:
                if row["id"] in seen_evidence_ids:
                    continue
                seen_evidence_ids.add(row["id"])
                db.add(
                    BehaviorEvidence(
                        organization_id=org, finding_id=fid, event_id=row["id"], evidence_hash=row["hash"]
                    )
                )
        if end >= utc(profile.window_end):
            profile.window_end, profile.baseline = end, base
            if not refresh_only:
                profile.risk_score = max(risks, default=0)
    return {
        "events": len(records),
        "unique_observations": len(seen),
        "profiles": len(groups),
        "new_findings": found,
    }


def process_jobs(settings, sessions):
    """One durable bounded job per iteration. Transaction rollback precedes retry."""
    with sessions.begin() as db:
        job = db.scalar(
            select(BehaviorJob)
            .where(BehaviorJob.state.in_(["PENDING", "RETRY"]), BehaviorJob.available_at <= time.time())
            .order_by(BehaviorJob.created_at, BehaviorJob.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if not job:
            return 0
        try:
            with db.begin_nested():
                result = analyze(db, job.organization_id, job.window_end, job.config, job.refresh_only)
        except Exception as exc:
            job.attempts += 1
            job.state = (
                "FAILED"
                if isinstance(exc, ValueError) or job.attempts >= settings.worker_max_attempts
                else "RETRY"
            )
            job.available_at = time.time() + min(300, 2**job.attempts)
            job.result = {"error": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
        else:
            job.state, job.result = "COMPLETED", {**result, "completed_at": now().isoformat()}
        return 1
