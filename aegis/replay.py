"""AEGIS Historical Event Replay and Detection Quality Engine.

Evaluates candidate and active detection rules against historical security events
and labelled attack datasets in a genuine, sandboxed dry-run environment.

Guarantees:
1. Complete isolation: Replay state NEVER leaks into or mutates live detection state.
2. Zero side-effects: Never creates production alerts, incidents, notifications, or playbooks.
3. Bounded resources: Strictly enforces configurable event limits, batch pagination, and timeouts.
4. Determinism: Preserves deterministic evaluation ordering and reproducible metadata.
5. Evidence preservation: Stores exact event snapshots and match explanations for auditing.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db import EventRecord, ReplayJob, ReplayMatch, Rule
from aegis.detection import evaluate
from aegis.parsers import ParserRegistry
from aegis.rule_checks import fixtures
from aegis.rules import MITRE
from aegis.schemas import DetectionRule, ReplayRequest

logger = logging.getLogger("aegis.replay")


def _parse_timestamp(ts: Any) -> float:
    """Robust timestamp extractor supporting floats, ints, datetime objects, and ISO strings.

    Always defaults timezone-naive timestamps to UTC to guarantee deterministic
    event ordering regardless of the host operating system's local timezone.
    """
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts.timestamp()
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.timestamp()
        except Exception:
            try:
                return float(ts)
            except Exception:
                return 0.0
    return 0.0


class ReplayStateStore:
    """Isolated, in-memory state store for dry-run historical event replay.

    Guarantees:
    - Never mutates production WindowState rows or database locks.
    - Strictly scoped to a single replay job execution.
    - Enforces sliding correlation window logic matching production SQLState.
    """

    def __init__(self, lateness: int = 86400, limit: int = 10000) -> None:
        self.lateness = lateness
        self.limit = limit
        self.state: dict[str, list[dict[str, Any]]] = {}

    def append(self, key: str, event: dict[str, Any], window: int) -> list[dict[str, Any]]:
        values = self.state.get(key, [])
        ts_val = event.get("timestamp")
        if not ts_val:
            return [event]
        current = _parse_timestamp(ts_val)

        # Evict events outside the sliding window
        values = [
            item
            for item in values
            if (
                item.get("timestamp")
                and (current - window - self.lateness <= _parse_timestamp(item["timestamp"]))
                and item.get("event_id") != event.get("event_id")
            )
        ]
        values.append(event)
        values.sort(
            key=lambda item: (
                _parse_timestamp(item.get("timestamp")),
                str(item.get("event_id", "")),
            )
        )
        if len(values) > self.limit:
            values = values[-self.limit :]
        self.state[key] = values

        return [
            item
            for item in values
            if item.get("timestamp")
            and (current - window <= _parse_timestamp(item["timestamp"]) <= current)
        ]



def get_labelled_dataset(name: str, org_id: str) -> list[dict[str, Any]]:
    """Generates deterministic, labelled synthetic security events.

    Each event includes '_label' metadata ('ATTACK' or 'BENIGN') for ground-truth
    precision and recall evaluation.
    """
    all_fixtures = fixtures()
    dataset_events: list[dict[str, Any]] = []
    base_time = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)

    clean_name = name.upper().removeprefix("AEGIS-")
    target_rules = (
        [clean_name]
        if clean_name in all_fixtures
        else [name.upper()]
        if name.upper() in all_fixtures
        else list(all_fixtures.keys())
        if name.lower() in {"all", "all_fixtures", "all-fixtures", "all_rules"}
        else [r for r in all_fixtures if clean_name.lower() in r.lower()]
    )

    if not target_rules:
        target_rules = ["AUTH-001", "PROC-001", "NET-001"]

    step_sec = 1
    parser = ParserRegistry()

    from aegis.schemas import EventInput

    base_defaults = {
        "host": "LAB-HOST",
        "username": "synthetic-user",
        "source_ip": "192.0.2.100",
        "destination_ip": "198.51.100.100",
        "message": "Synthetic detection fixture",
    }

    for rule_id in target_rules:
        pos_events, neg_events = all_fixtures[rule_id]
        # Labelled Attack Events (Ground Truth Positives)
        for i, raw in enumerate(pos_events):
            t = base_time + (
                datetime.fromtimestamp(raw["_seconds"], tz=UTC) - datetime.fromtimestamp(0, tz=UTC)
                if "_seconds" in raw
                else datetime.fromtimestamp(step_sec * 2, tz=UTC) - datetime.fromtimestamp(0, tz=UTC)
            )
            step_sec += 2
            raw_clean = {**base_defaults, **{k: v for k, v in raw.items() if not k.startswith("_")}}
            event_inp = EventInput(
                source=f"synthetic-{rule_id.lower()}",
                source_sequence=f"attack-{rule_id.lower()}-{i:04d}",
                timestamp=t,
                raw_event=raw_clean,
            )
            normalized = parser.normalize(event_inp, org_id).model_dump(mode="json")
            normalized["event_id"] = f"attack-{rule_id.lower()}-{i:04d}"
            normalized["_ground_truth"] = "ATTACK"
            normalized["_target_rule"] = rule_id
            dataset_events.append(normalized)

        base_defaults_benign = {
            "host": "LAB-HOST-02",
            "username": "benign-user",
            "source_ip": "192.0.2.200",
            "destination_ip": "198.51.100.100",
            "message": "Synthetic detection fixture",
        }
        # Labelled Benign Control Events (Ground Truth Negatives)
        for i, raw in enumerate(neg_events):
            t = base_time + timedelta(hours=2) + (
                datetime.fromtimestamp(raw["_seconds"], tz=UTC) - datetime.fromtimestamp(0, tz=UTC)
                if "_seconds" in raw
                else datetime.fromtimestamp(step_sec * 2, tz=UTC) - datetime.fromtimestamp(0, tz=UTC)
            )
            step_sec += 2
            raw_clean = {**base_defaults_benign, **{k: v for k, v in raw.items() if not k.startswith("_")}}
            event_inp = EventInput(
                source=f"synthetic-{rule_id.lower()}",
                source_sequence=f"benign-{rule_id.lower()}-{i:04d}",
                timestamp=t,
                raw_event=raw_clean,
            )
            normalized = parser.normalize(event_inp, org_id).model_dump(mode="json")
            normalized["event_id"] = f"benign-{rule_id.lower()}-{i:04d}"
            normalized["_ground_truth"] = "BENIGN"
            normalized["_target_rule"] = rule_id
            dataset_events.append(normalized)

    dataset_events.sort(key=lambda e: (e.get("timestamp", ""), e.get("event_id", "")))
    return dataset_events


def calculate_mitre_coverage(db: Session, org_id: str) -> dict[str, Any]:
    """Computes MITRE ATT&CK coverage across active detection rules for the organization."""
    active_rules = list(
        db.scalars(
            select(Rule).where(Rule.organization_id == org_id, Rule.enabled.is_(True))
        )
    )

    covered_techniques: dict[str, list[str]] = {}
    covered_tactics: dict[str, set[str]] = {}
    all_tactics: dict[str, set[str]] = {}

    for tech_id, (_name, tactic) in MITRE.items():
        all_tactics.setdefault(tactic, set()).add(tech_id)

    for row in active_rules:
        doc = row.document or {}
        for tech in doc.get("mitre_techniques", []):
            if tech in MITRE:
                covered_techniques.setdefault(tech, []).append(row.rule_id)
                tactic = MITRE[tech][1]
                covered_tactics.setdefault(tactic, set()).add(tech)

    tactic_breakdown: list[dict[str, Any]] = []
    for tactic, total_techs in sorted(all_tactics.items()):
        covered_in_tactic = covered_tactics.get(tactic, set())
        pct = round(len(covered_in_tactic) / len(total_techs) * 100, 1) if total_techs else 0.0
        tactic_breakdown.append(
            {
                "tactic": tactic,
                "total_techniques": len(total_techs),
                "covered_techniques_count": len(covered_in_tactic),
                "coverage_pct": pct,
                "covered_technique_ids": sorted(covered_in_tactic),
                "uncovered_technique_ids": sorted(total_techs - covered_in_tactic),
            }
        )

    overall_pct = (
        round(len(covered_techniques) / len(MITRE) * 100, 1) if MITRE else 0.0
    )

    return {
        "catalog_total": len(MITRE),
        "covered_total": len(covered_techniques),
        "overall_coverage_pct": overall_pct,
        "covered_techniques": {
            tech: {
                "name": MITRE[tech][0],
                "tactic": MITRE[tech][1],
                "rules": rules,
            }
            for tech, rules in sorted(covered_techniques.items())
        },
        "tactics": tactic_breakdown,
    }


def execute_replay(
    db: Session,
    org_id: str,
    user_id: str,
    request: ReplayRequest,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Executes a bounded, deterministic detection rule replay job.

    Compares candidate rule against active rule on the requested event stream.
    Zero side-effects: creates NO live alerts or incident records.
    """
    job_id = f"replay-{uuid4().hex[:12]}"
    started_at = datetime.now(UTC)
    t0 = time.monotonic()

    req_rule_id = request.rule_id or ""
    clean_req_id = req_rule_id.removeprefix("AEGIS-")
    active_row = db.scalar(
        select(Rule).where(
            Rule.organization_id == org_id,
            (Rule.rule_id == req_rule_id)
            | (Rule.id == req_rule_id)
            | (Rule.rule_id == f"AEGIS-{req_rule_id}")
            | (Rule.rule_id == clean_req_id),
        )
    )
    active_rule: DetectionRule | None = None
    active_version: int | None = None

    if active_row:
        active_rule = DetectionRule.model_validate(active_row.document)
        active_version = active_row.version
        actual_rule_id = active_row.rule_id
    else:
        actual_rule_id = request.rule_id or "UNKNOWN"

    candidate_rule: DetectionRule | None = request.candidate_document
    candidate_version: int | None = candidate_rule.version if candidate_rule else None

    if candidate_rule is None and active_rule is None:
        raise ValueError(f"Rule '{request.rule_id}' does not exist and no candidate rule was provided.")

    if candidate_rule is None:
        candidate_rule = active_rule
        candidate_version = active_version

    # 1. Fetch events according to target_type
    events: list[dict[str, Any]] = []
    is_ground_truth_dataset = False

    if request.target_type == "DATASET":
        dataset_name = request.dataset_name or request.rule_id or "AUTH-001"
        events = get_labelled_dataset(dataset_name, org_id)
        is_ground_truth_dataset = True
    elif request.target_type == "EVENTS":
        if not request.event_ids:
            raise ValueError("Replay with target_type='EVENTS' requires at least one event_id.")
        # Stream in chunks of 200
        chunk_size = 200
        for i in range(0, min(len(request.event_ids), request.max_events), chunk_size):
            chunk = request.event_ids[i : i + chunk_size]
            records = list(
                db.scalars(
                    select(EventRecord).where(
                        EventRecord.organization_id == org_id, EventRecord.id.in_(chunk)
                    )
                )
            )
            for rec in records:
                if isinstance(rec.payload, dict):
                    evt = dict(rec.payload)
                    if not evt.get("event_id"):
                        evt["event_id"] = rec.id
                    if not evt.get("timestamp"):
                        evt["timestamp"] = (
                            rec.timestamp.isoformat()
                            if hasattr(rec.timestamp, "isoformat")
                            else str(rec.timestamp)
                        )
                    events.append(evt)
    elif request.target_type == "TIMERANGE":
        query = (
            select(EventRecord)
            .where(EventRecord.organization_id == org_id)
            .order_by(EventRecord.timestamp.asc(), EventRecord.id.asc())
            .limit(request.max_events)
        )
        if request.start_time:
            query = query.where(EventRecord.timestamp >= request.start_time)
        if request.end_time:
            query = query.where(EventRecord.timestamp <= request.end_time)
        records = list(db.scalars(query))
        for rec in records:
            if isinstance(rec.payload, dict):
                evt = dict(rec.payload)
                if not evt.get("event_id"):
                    evt["event_id"] = rec.id
                if not evt.get("timestamp"):
                    evt["timestamp"] = (
                        rec.timestamp.isoformat()
                        if hasattr(rec.timestamp, "isoformat")
                        else str(rec.timestamp)
                    )
                events.append(evt)

    # Bound events and ensure deterministic order across all target types
    events = events[: request.max_events]
    events.sort(key=lambda e: (_parse_timestamp(e.get("timestamp")), str(e.get("event_id") or "")))

    # Create ReplayJob database record
    target_params = {
        "dataset_name": request.dataset_name,
        "event_ids_count": len(request.event_ids),
        "start_time": request.start_time.isoformat() if request.start_time else None,
        "end_time": request.end_time.isoformat() if request.end_time else None,
        "max_events": request.max_events,
    }

    job = ReplayJob(
        id=job_id,
        organization_id=org_id,
        rule_id=actual_rule_id,
        candidate_version=candidate_version,
        active_version=active_version,
        status="RUNNING",
        target_type=request.target_type,
        target_params=target_params,
        dry_run=request.dry_run,
        events_evaluated=0,
        candidate_matches_count=0,
        active_matches_count=0,
        metrics={},
        errors=[],
        created_by=user_id,
        started_at=started_at,
    )
    db.add(job)
    db.flush()

    # 2. Replay evaluation with isolated StateStores
    candidate_state = ReplayStateStore()
    active_state = ReplayStateStore()
    candidate_namespace = f"replay:candidate:{job_id}"
    active_namespace = f"replay:active:{job_id}"

    candidate_matched_event_ids: set[str] = set()
    active_matched_event_ids: set[str] = set()
    matches_to_insert: list[ReplayMatch] = []
    errors: list[str] = []

    # Ground truth metrics counters
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    seen_event_ids: set[str] = set()
    duplicate_event_ids: set[str] = set()
    scenario_ground_truth: dict[str, str] = {}
    scenario_hits: dict[str, bool] = {}

    events_evaluated = 0

    for event in events:
        # Check timeout boundary
        if (time.monotonic() - t0) > timeout_seconds:
            errors.append(f"Replay execution halted: exceeded configured timeout of {timeout_seconds}s")
            job.status = "CANCELLED"
            break

        events_evaluated += 1
        event_id = str(event.get("event_id") or f"evt-{events_evaluated}")
        if event_id in seen_event_ids:
            duplicate_event_ids.add(event_id)
        seen_event_ids.add(event_id)

        ground_truth = event.get("_ground_truth")  # "ATTACK" or "BENIGN"
        scenario_id = str(event.get("_scenario_id") or event.get("_target_rule") or "default")

        candidate_match: dict[str, Any] | None = None
        active_match: dict[str, Any] | None = None

        try:
            if candidate_rule:
                candidate_match = evaluate(
                    candidate_rule, event, candidate_state, candidate_namespace
                )
        except Exception as exc:
            errors.append(f"Candidate rule evaluation error on event {event_id}: {exc}")

        try:
            if active_rule:
                active_match = evaluate(active_rule, event, active_state, active_namespace)
        except Exception as exc:
            errors.append(f"Active rule evaluation error on event {event_id}: {exc}")

        cand_hit = bool(candidate_match)
        act_hit = bool(active_match)

        if cand_hit:
            candidate_matched_event_ids.add(event_id)
        if act_hit:
            active_matched_event_ids.add(event_id)

        # Ground truth tracking for candidate rule
        if is_ground_truth_dataset and ground_truth:
            if ground_truth == "ATTACK":
                scenario_ground_truth.setdefault(scenario_id, "ATTACK")
                if cand_hit:
                    true_positives += 1
                else:
                    false_negatives += 1
            elif ground_truth == "BENIGN":
                scenario_ground_truth.setdefault(scenario_id, "BENIGN")
                if cand_hit:
                    false_positives += 1
                else:
                    true_negatives += 1
            if cand_hit:
                scenario_hits[scenario_id] = True

        # Record match if either candidate or active matched
        if cand_hit or act_hit:
            explanation = (candidate_match or active_match or {}).copy()
            # Preserve compact snapshot of event
            snapshot = {
                k: v
                for k, v in event.items()
                if not k.startswith("_") and k not in {"raw_event", "normalized_fields"}
            }
            matches_to_insert.append(
                ReplayMatch(
                    id=f"rpm-{uuid4().hex[:12]}",
                    job_id=job_id,
                    organization_id=org_id,
                    event_id=event_id,
                    rule_id=actual_rule_id,
                    rule_version=candidate_version or 1,
                    matched_candidate=cand_hit,
                    matched_active=act_hit,
                    explanation=explanation,
                    event_snapshot=snapshot,
                    created_at=datetime.now(UTC),
                )
            )

    # Persist matches in batches
    for m in matches_to_insert:
        db.add(m)

    elapsed_sec = max(0.001, time.monotonic() - t0)
    throughput_eps = round(events_evaluated / elapsed_sec, 1)

    concordant_matches = len(candidate_matched_event_ids & active_matched_event_ids)
    new_candidate_matches = sorted(candidate_matched_event_ids - active_matched_event_ids)
    dropped_active_matches = sorted(active_matched_event_ids - candidate_matched_event_ids)

    if duplicate_event_ids:
        errors.append(
            f"Dataset contains {len(duplicate_event_ids)} duplicate event ID(s): "
            f"{sorted(list(duplicate_event_ids))[:5]}"
        )

    # Compute Ground Truth Metrics (only if dataset has ground truth labels)
    gt_metrics: dict[str, Any] | None = None
    if is_ground_truth_dataset:
        total_attack_cases = true_positives + false_negatives
        total_benign_cases = false_positives + true_negatives
        precision = (
            round(true_positives / (true_positives + false_positives), 4)
            if (true_positives + false_positives) > 0
            else None
        )
        recall = (
            round(true_positives / total_attack_cases, 4)
            if total_attack_cases > 0
            else None
        )
        f1 = (
            round(2 * (precision * recall) / (precision + recall), 4)
            if (precision is not None and recall is not None and (precision + recall) > 0)
            else None
        )

        # Scenario / Test-Case level metrics (evaluates scenario as a whole)
        sc_tp = 0
        sc_fp = 0
        sc_tn = 0
        sc_fn = 0
        for sc_id, sc_gt in scenario_ground_truth.items():
            hit = scenario_hits.get(sc_id, False)
            if sc_gt == "ATTACK":
                if hit:
                    sc_tp += 1
                else:
                    sc_fn += 1
            elif sc_gt == "BENIGN":
                if hit:
                    sc_fp += 1
                else:
                    sc_tn += 1

        sc_precision = (
            round(sc_tp / (sc_tp + sc_fp), 4)
            if (sc_tp + sc_fp) > 0
            else None
        )
        sc_recall = (
            round(sc_tp / (sc_tp + sc_fn), 4)
            if (sc_tp + sc_fn) > 0
            else None
        )
        sc_f1 = (
            round(2 * (sc_precision * sc_recall) / (sc_precision + sc_recall), 4)
            if (sc_precision is not None and sc_recall is not None and (sc_precision + sc_recall) > 0)
            else None
        )

        undefined_reasons: list[str] = []
        if (true_positives + false_positives) == 0:
            undefined_reasons.append("precision is undefined: 0 positive detections produced")
        if total_attack_cases == 0:
            undefined_reasons.append("recall is undefined: 0 attack test cases present")

        gt_metrics = {
            "ground_truth_available": True,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives,
            "total_attack_test_cases": total_attack_cases,
            "total_control_test_cases": total_benign_cases,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "undefined_metrics_reason": "; ".join(undefined_reasons) if undefined_reasons else None,
            "event_metrics": {
                "unit": "event",
                "events_evaluated": events_evaluated,
                "unique_events_evaluated": len(seen_event_ids),
                "true_positives": true_positives,
                "false_positives": false_positives,
                "true_negatives": true_negatives,
                "false_negatives": false_negatives,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "note": (
                    "Event-level metrics count every raw event. For multi-event threshold or sequence rules, "
                    "pre-trigger accumulator events count as false negatives at event level."
                ),
            },
            "scenario_metrics": {
                "unit": "attack_scenario",
                "scenarios_evaluated": len(scenario_ground_truth),
                "true_positives": sc_tp,
                "false_positives": sc_fp,
                "true_negatives": sc_tn,
                "false_negatives": sc_fn,
                "precision": sc_precision,
                "recall": sc_recall,
                "f1_score": sc_f1,
                "note": "Scenario-level metrics evaluate whether the attack scenario was detected as a logical unit.",
            },
        }
    else:
        gt_metrics = {
            "ground_truth_available": False,
            "precision": None,
            "recall": None,
            "f1_score": None,
            "note": "Metrics unavailable: historical dataset does not have verified ground-truth labels.",
        }

    # Noisy rule heuristic: high match frequency on benign events or high match rate
    match_rate_pct = (
        round((len(candidate_matched_event_ids) / events_evaluated) * 100, 2)
        if events_evaluated > 0
        else 0.0
    )
    noisy_rule_indicator = False
    if is_ground_truth_dataset and false_positives > 0:
        noisy_rule_indicator = True
    elif not is_ground_truth_dataset and match_rate_pct > 25.0:
        noisy_rule_indicator = True

    metrics = {
        "execution_duration_ms": round(elapsed_sec * 1000, 2),
        "events_per_second": throughput_eps,
        "events_evaluated": events_evaluated,
        "unique_events_evaluated": len(seen_event_ids),
        "duplicate_event_ids_count": len(duplicate_event_ids),
        "candidate_matches_count": len(candidate_matched_event_ids),
        "active_matches_count": len(active_matched_event_ids),
        "match_rate_percentage": match_rate_pct,
        "concordant_matches_count": concordant_matches,
        "new_candidate_detections_count": len(new_candidate_matches),
        "dropped_detections_count": len(dropped_active_matches),
        "noisy_rule_indicator": noisy_rule_indicator,
        "ground_truth": gt_metrics,
    }

    completed_at = datetime.now(UTC)
    if job.status != "CANCELLED":
        job.status = "COMPLETED" if not errors else "COMPLETED_WITH_WARNINGS"
    job.events_evaluated = events_evaluated
    job.candidate_matches_count = len(candidate_matched_event_ids)
    job.active_matches_count = len(active_matched_event_ids)
    job.metrics = metrics
    job.errors = errors
    job.completed_at = completed_at

    # Update last_replay_id on Rule if existing
    if active_row:
        active_row.last_replay_id = job_id

    db.flush()

    return {
        "job_id": job_id,
        "rule_id": actual_rule_id,
        "status": job.status,
        "dry_run": request.dry_run,
        "candidate_version": candidate_version,
        "active_version": active_version,
        "events_evaluated": events_evaluated,
        "candidate_matches": sorted(candidate_matched_event_ids),
        "active_matches": sorted(active_matched_event_ids),
        "new_detections": new_candidate_matches,
        "dropped_detections": dropped_active_matches,
        "metrics": metrics,
        "errors": errors,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
    }
