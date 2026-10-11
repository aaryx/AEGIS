import json
import statistics
import time
from datetime import datetime
from typing import Protocol

from sqlalchemy.orm import Session

from aegis.db import WindowState
from aegis.parsers import digest
from aegis.schemas import DetectionRule, get_field


class StateStore(Protocol):
    def append(self, key: str, event: dict, window: int) -> list[dict]: ...


class SQLState:
    """Transactional correlation state; committed atomically with alerts and evidence links."""

    def __init__(self, db: Session, lateness: int = 120, limit: int = 10000):
        self.db = db
        self.lateness = lateness
        self.limit = limit
        self.cache: dict[str, WindowState] = {}

    def append(self, key, event, window):
        row = self.cache.get(key) or self.db.get(WindowState, key)
        values = row.data if row else []
        current = datetime.fromisoformat(event["timestamp"]).timestamp()
        watermark = max(
            [current, *(datetime.fromisoformat(item["timestamp"]).timestamp() for item in values)]
        )
        if current < watermark - self.lateness:
            raise ValueError("Event is older than the correlation lateness budget")
        values = [
            item
            for item in values
            if watermark - window - self.lateness <= datetime.fromisoformat(item["timestamp"]).timestamp()
            and item["event_id"] != event["event_id"]
        ]
        values.append(event)
        values.sort(
            key=lambda item: (datetime.fromisoformat(item["timestamp"]).timestamp(), item["event_id"])
        )
        if len(values) > self.limit:
            raise ValueError("Correlation window capacity exceeded; tune rule or increase configured limit")
        if row:
            row.data, row.expires = values, time.time() + window + self.lateness
        else:
            row = WindowState(key=key, data=values, expires=time.time() + window + self.lateness)
            self.db.add(row)
        self.cache[key] = row
        return [
            item
            for item in values
            if current - window <= datetime.fromisoformat(item["timestamp"]).timestamp() <= current
        ]


def evaluate(rule: DetectionRule, event: dict, state: StateStore, namespace: str) -> dict | None:
    if not all(predicate.matches(event) for predicate in rule.selection):
        return None
    if any(
        all(predicate.matches(event) for predicate in exception.predicates) for exception in rule.exceptions
    ):
        return None
    condition = rule.condition
    grouping = {field: get_field(event, field) for field in condition.group_by}
    if any(value is None for value in grouping.values()):
        return None  # Never correlate unrelated events by an absent identity.
    key = digest([namespace, rule.model_dump(), grouping])
    compact = {k: v for k, v in event.items() if k not in {"raw_event", "normalized_fields", "message"}}
    compact["message"] = event.get("message", "")[:1000]
    values = [compact] if condition.type == "match" else state.append(key, compact, condition.window_seconds)
    matched = values
    measured: float = len(values)
    trigger = condition.type == "match"
    if condition.type == "threshold":
        trigger = len(values) >= condition.count
    elif condition.type == "aggregation":
        if condition.distinct_field:
            measured = len(
                {
                    json.dumps(get_field(item, condition.distinct_field), sort_keys=True)
                    for item in values
                    if get_field(item, condition.distinct_field) is not None
                }
            )
            trigger = measured >= condition.count
        else:
            measured = sum(
                float(value)
                for item in values
                if isinstance(value := get_field(item, condition.sum_field or ""), (int, float))
                and not isinstance(value, bool)
            )
            trigger = measured >= condition.sum_threshold
    elif condition.type == "sequence":
        # Anchor on the current terminal event and walk backwards. An earlier completed
        # sequence must not suppress subsequent chains in the same window.
        matched = [compact] if all(p.matches(event) for p in condition.sequence[-1]) else []
        step = len(condition.sequence) - 2
        for item in reversed(values):
            if not matched or item["event_id"] == event["event_id"]:
                continue
            if all(predicate.matches(item) for predicate in condition.sequence[step]):
                matched.append(item)
                step -= 1
                if step < 0:
                    break
        matched.reverse()
        trigger = step < 0
    elif condition.type == "beacon" and len(values) >= condition.count:
        matched = values[-condition.count :]
        times = [datetime.fromisoformat(item["timestamp"]).timestamp() for item in matched]
        gaps = [later - earlier for earlier, later in zip(times, times[1:], strict=False)]
        measured = statistics.pstdev(gaps) / statistics.mean(gaps) if statistics.mean(gaps) > 0 else 1
        trigger = measured <= condition.tolerance and min(gaps) >= 1
    elif condition.type == "anomaly":
        samples = [get_field(item, condition.sum_field or "") for item in values[:-1]]
        samples = [
            value for value in samples if isinstance(value, (int, float)) and not isinstance(value, bool)
        ][-condition.baseline_count :]
        value = get_field(event, condition.sum_field or "")
        if (
            len(samples) >= condition.baseline_count
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
        ):
            mean, deviation = statistics.mean(samples), statistics.pstdev(samples)
            measured = (value - mean) / max(deviation, 1)
            trigger = measured > condition.deviation and value > mean
    if not trigger:
        return None
    return {
        "why": rule.description,
        "condition": condition.model_dump(),
        "matched_fields": [p.model_dump() for p in rule.selection],
        "group": grouping,
        "measured": measured,
        "event_ids": [item["event_id"] for item in matched],
        "recommended_actions": rule.recommended_actions,
        "state_key": key,
    }


def risk(rule: DetectionRule, event: dict, count: int, weights: dict | None = None) -> tuple[int, dict]:
    weights = weights or {
        "severity": {"informational": 5, "low": 10, "medium": 25, "high": 40, "critical": 55},
        "privilege": 10,
        "asset": 10,
        "ioc": 15,
        "correlation": 10,
        "frequency": 10,
    }
    factors = {
        "severity_adjusted_for_confidence": round(weights["severity"][rule.severity] * rule.confidence / 100),
        "privileged_identity": weights["privilege"] if get_field(event, "authentication.privileged") else 0,
        "critical_asset": weights["asset"]
        if get_field(event, "metadata.asset_criticality") == "critical"
        else 0,
        "threat_intelligence_match": weights["ioc"] if get_field(event, "metadata.ioc_match") else 0,
        "multi_stage_sequence": weights["correlation"] if rule.condition.type == "sequence" else 0,
        "event_frequency": min(weights["frequency"], max(0, count - 1)),
    }
    return min(100, sum(factors.values())), factors
