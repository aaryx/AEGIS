"""Offline detection evaluation; no sessions, ingestion or response execution."""

import time
from datetime import UTC
from typing import Any

from aegis.detection import evaluate
from aegis.parsers import ParserRegistry
from aegis.replay import ReplayStateStore
from aegis.schemas import DetectionRule, Event, EventInput


def run_simulation(
    records: list[Any], rules: list[DetectionRule], tenant: str,
    *, labelled_fixture: bool = False,
) -> dict:
    """Evaluate a bounded export or one trusted bundled fixture in event-time order.

    Labels are trusted only when the caller supplies a bundled fixture. Its positive
    and negative sequences have separate state, and each is one scenario.
    """
    tenant = tenant.strip()
    if not tenant:
        raise ValueError("Tenant must not be empty")
    if len(records) > 10000:
        raise ValueError("Simulation accepts at most 10000 events")
    started = time.perf_counter()
    parser = ParserRegistry()
    events = []
    errors = []
    seen = set()
    for index, record in enumerate(records, 1):
        try:
            if not isinstance(record, dict):
                raise ValueError("Expected an event object")
            doc = dict(record)
            if doc.pop("organization_id", tenant) != tenant:
                raise ValueError("Event belongs to another tenant")
            label = doc.pop("_ground_truth", None) if labelled_fixture else None
            target_rule = doc.pop("_target_rule", None) if labelled_fixture else None
            if "event_id" in doc:
                event = Event.model_validate(doc)
            else:
                incoming = EventInput.model_validate(doc)
                if incoming.timestamp is None:
                    raise ValueError("Offline events require an explicit timestamp")
                event = parser.normalize(incoming, tenant)
                if isinstance(incoming.raw_event, dict) and isinstance(incoming.raw_event.get("metadata"), dict):
                    for k, v in incoming.raw_event["metadata"].items():
                        if k not in {"parser", "classification", "tenant", "organization_id", "source"}:
                            event.metadata[k] = v
            if not event.event_id or not event.event_id.strip() or event.timestamp.tzinfo is None:
                raise ValueError("Event requires an ID and timezone-aware timestamp")
            if event.event_id in seen:
                raise ValueError("Duplicate event ID")
            seen.add(event.event_id)
            event.timestamp = event.timestamp.astimezone(UTC)
            events.append((event, label, target_rule))
        except Exception as exc:
            errors.append({"record": index, "error": str(exc)})

    events.sort(key=lambda item: (item[0].timestamp, item[0].event_id))
    state = ReplayStateStore(limit=10000)
    counts = {rule.id: 0 for rule in rules}
    matches = []
    attack_hits = set()
    false_positive_candidates = []
    for event, label, target_rule in events:
        event_dict = event.model_dump(mode="json")
        for rule in rules:
            rule_short_id = rule.id.removeprefix("AEGIS-")
            namespace = f"offline:{tenant}:{target_rule or 'scenario'}:{label or 'unlabelled'}"
            try:
                match = evaluate(rule, event_dict, state, namespace)
            except Exception as exc:
                errors.append({"event_id": event.event_id, "rule_id": rule.id, "error": str(exc)})
                continue
            if match:
                counts[rule.id] += 1
                item = {"rule_id": rule.id, "event_id": event.event_id, "evidence": match}
                matches.append(item)
                if label == "ATTACK":
                    if target_rule is None or target_rule == rule_short_id:
                        attack_hits.add(rule.id)
                elif label == "BENIGN":
                    if target_rule is None or target_rule == rule_short_id:
                        false_positive_candidates.append({"rule_id": rule.id, "event_id": event.event_id})
    # Do not score incomplete runs or unlabelled exports as ground truth.
    quality = None
    if labelled_fixture and not errors and events:
        scenarios_evaluated = sorted({tr for _, _, tr in events if tr})
        applicable_rules = [
            rule for rule in rules
            if not scenarios_evaluated or rule.id.removeprefix("AEGIS-") in scenarios_evaluated
        ]
        quality = {
            "unit": "bundled scenario per rule; not a production false-positive rate",
            "scenarios_evaluated": scenarios_evaluated if scenarios_evaluated else [r.id for r in rules],
            "false_positive_candidates": false_positive_candidates,
            "missed_attack_rules": [rule.id for rule in applicable_rules if rule.id not in attack_hits],
        }
    return {
        "mode": "offline", "tenant": tenant, "events_received": len(records),
        "events_processed": len(events), "detections_generated": len(matches),
        "rule_match_counts": counts, "matches": matches, "fixture_quality": quality,
        "processing_seconds": time.perf_counter() - started, "errors": errors,
    }
