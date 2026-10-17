import base64
import json
import math
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from opensearchpy import OpenSearch, helpers
from sqlalchemy import select

from aegis.db import EventRecord
from aegis.schemas import SearchQuery, get_field


class StorageProvider(Protocol):
    def index(self, organization_id: str, events: list[dict]) -> None: ...
    def search(self, organization_id: str, query: SearchQuery) -> dict: ...
    def health(self) -> str: ...


def encode_cursor(values: list) -> str:
    return base64.urlsafe_b64encode(json.dumps(values).encode()).decode()


def decode_cursor(cursor: str | None) -> list | None:
    if not cursor:
        return None
    try:
        value = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
        if (
            not isinstance(value, list)
            or len(value) != 2
            or isinstance(value[0], bool)
            or not isinstance(value[0], (int, float))
            or not math.isfinite(value[0])
            or not isinstance(value[1], str)
            or not value[1]
        ):
            raise ValueError("Invalid cursor")
        return value
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid pagination cursor") from exc


class LocalStorage:
    def __init__(self, sessions):
        self.sessions = sessions

    def index(self, organization_id, events):
        return None  # Local search reads the durable event table directly.

    def health(self):
        return "HEALTHY"

    def search(self, organization_id, query):
        cursor = decode_cursor(query.cursor)
        with self.sessions() as db:
            statement = select(EventRecord).where(
                EventRecord.organization_id == organization_id,
                EventRecord.timestamp >= query.start,
                EventRecord.timestamp <= query.end,
                EventRecord.state == "PROCESSED",
            )
            # ponytail: local search scans a bounded 50k window; OpenSearch is required above local scale.
            rows = list(db.scalars(statement.order_by(EventRecord.timestamp, EventRecord.id).limit(50001)))
            if len(rows) > 50000:
                raise ValueError(
                    "Local search window exceeds 50,000 events; narrow the range or enable OpenSearch"
                )
            events = [
                row.payload
                for row in rows
                if all(p.matches(row.payload) for p in query.filters)
                and (not query.text or query.text.casefold() in row.payload.get("message", "").casefold())
            ]
        events.sort(
            key=lambda item: (datetime.fromisoformat(item["timestamp"]).timestamp(), item["event_id"]),
            reverse=query.sort == "desc",
        )
        buckets: dict[str, int] = {}
        if query.aggregate:
            for item in events:
                key = str(get_field(item, query.aggregate))
                buckets[key] = buckets.get(key, 0) + 1
        total = len(events)
        if cursor:
            events = [
                item
                for item in events
                if ((datetime.fromisoformat(item["timestamp"]).timestamp(), item["event_id"]) > tuple(cursor))
                == (query.sort == "asc")
                and (datetime.fromisoformat(item["timestamp"]).timestamp(), item["event_id"]) != tuple(cursor)
            ]
        page = events[: query.limit]
        next_cursor = (
            encode_cursor([datetime.fromisoformat(page[-1]["timestamp"]).timestamp(), page[-1]["event_id"]])
            if len(events) > query.limit
            else None
        )
        return {
            "items": page,
            "total": total,
            "next_cursor": next_cursor,
            "aggregations": dict(sorted(buckets.items(), key=lambda pair: -pair[1])[:50]),
        }


class OpenSearchStorage:
    def __init__(self, settings):
        self.settings = settings
        self.client = OpenSearch(
            settings.opensearch_url,
            http_auth=(settings.opensearch_username, settings.opensearch_password.get_secret_value()),
            verify_certs=True,
            ca_certs=settings.opensearch_ca,
            timeout=10,
            max_retries=2,
            retry_on_timeout=True,
        )

    def setup(self):
        keywords = [
            "event_id",
            "organization_id",
            "source",
            "source_type",
            "host",
            "hostname",
            "username",
            "user_id",
            "event_type",
            "event_category",
            "action",
            "outcome",
            "severity",
            "tags",
            "protocol",
            "parent_process",
        ]
        properties = {name: {"type": "keyword", "ignore_above": 512} for name in keywords}
        properties.update(
            {
                "timestamp": {"type": "date"},
                "ingest_timestamp": {"type": "date"},
                "message": {"type": "text"},
                "command_line": {"type": "wildcard"},
                "source_ip": {"type": "ip"},
                "destination_ip": {"type": "ip"},
                "raw_event": {"type": "object", "enabled": False},
                "normalized_fields": {"type": "object", "enabled": False},
                "metadata": {
                    "properties": {
                        "ioc_match": {"type": "boolean"},
                        "asset_criticality": {"type": "keyword"},
                    },
                    "dynamic": False,
                },
                "http": {
                    "properties": {
                        "status": {"type": "integer"},
                        "path": {"type": "wildcard"},
                        "user_agent": {"type": "wildcard"},
                    }
                },
                "network": {"properties": {"bytes": {"type": "long"}}},
                "file": {"properties": {"path": {"type": "wildcard"}, "hash": {"type": "keyword"}}},
                "process": {"properties": {"name": {"type": "keyword"}}},
                "authentication": {"properties": {"privileged": {"type": "boolean"}}},
                "cloud": {"properties": {"action": {"type": "keyword"}, "resource": {"type": "keyword"}}},
                "source_port": {"type": "integer"},
                "destination_port": {"type": "integer"},
                "process_id": {"type": "long"},
            }
        )
        replicas = getattr(self.settings, "opensearch_replicas", 0)
        self.client.indices.put_index_template(
            name="aegis-events",
            body={
                "index_patterns": ["aegis-events-*"],
                "template": {
                    "settings": {"number_of_shards": 1, "number_of_replicas": replicas, "refresh_interval": "5s"},
                    "mappings": {"dynamic": False, "properties": properties},
                    "aliases": {"aegis-events": {}},
                },
            },
        )

    def index(self, organization_id, events):
        actions = []
        for event in events:
            raw_val = event.get("raw_event")
            if isinstance(raw_val, dict) and "original" in raw_val:
                raw_event_doc = raw_val
            else:
                raw_event_doc = {"original": str(raw_val if raw_val is not None else event.get("message", ""))}
            document = event | {
                "organization_id": organization_id,
                "raw_event": raw_event_doc,
            }
            ts = event.get("timestamp")
            if isinstance(ts, datetime):
                dt = ts.astimezone(UTC) if ts.tzinfo else ts.replace(tzinfo=UTC)
            elif isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts).astimezone(UTC)
                except (ValueError, TypeError):
                    dt = datetime.now(UTC)
            else:
                dt = datetime.now(UTC)
            event_id = event.get("event_id") or f"evt-{dt.timestamp()}"
            actions.append(
                {
                    "_index": "aegis-events-" + dt.strftime("%Y.%m.%d"),
                    "_id": event_id,
                    "_source": document,
                }
            )
        helpers.bulk(self.client, actions, chunk_size=500, max_retries=2, request_timeout=15)

    def health(self):
        status = self.client.cluster.health(request_timeout=3)["status"]
        return "DOWN" if status == "red" else "HEALTHY"

    def build_body(self, organization_id: str, query: SearchQuery) -> dict:
        filters: list[dict[str, Any]] = [
            {"term": {"organization_id": organization_id}},
            {"range": {"timestamp": {"gte": query.start.isoformat(), "lte": query.end.isoformat()}}},
        ]
        wildcard_indexed_fields = {"command_line", "http.path", "http.user_agent", "file.path"}
        for predicate in query.filters:
            field, value = predicate.field, predicate.value
            clause: dict[str, Any]
            match predicate.op:
                case "eq":
                    clause = {"term": {field: value}}
                case "ne":
                    clause = {
                        "bool": {
                            "must_not": [{"term": {field: value}}],
                            "filter": [{"exists": {"field": field}}],
                        }
                    }
                case "in":
                    clause = {"terms": {field: value}}
                case "contains":
                    val_str = str(value)[:200]
                    if not val_str:
                        continue
                    if field in {"message", "raw_event"}:
                        clause = {"match_phrase": {field: val_str}}
                    elif field in wildcard_indexed_fields:
                        escaped = val_str.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
                        clause = {"wildcard": {field: {"value": f"*{escaped}*", "case_insensitive": True}}}
                    else:
                        escaped = val_str.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
                        clause = {"wildcard": {field: {"value": f"*{escaped}*", "case_insensitive": True}}}
                case "gte" | "lte":
                    clause = {"range": {field: {predicate.op: value}}}
                case "exists":
                    clause = (
                        {"exists": {"field": field}}
                        if value is not False
                        else {"bool": {"must_not": [{"exists": {"field": field}}]}}
                    )
            filters.append(clause)
        body = {
            "query": {
                "bool": {
                    "filter": filters,
                    "must": [{"match_phrase": {"message": query.text}}] if query.text else [],
                }
            },
            "size": query.limit + 1,
            "sort": [{"timestamp": query.sort}, {"event_id": query.sort}],
            "track_total_hits": min(query.limit * 10, 10000),
            "timeout": "5s",
        }
        if query.cursor:
            body["search_after"] = decode_cursor(query.cursor)
        if query.aggregate:
            body["aggs"] = {"values": {"terms": {"field": query.aggregate, "size": min(50, query.limit)}}}
        return body

    def search(self, organization_id, query):
        body = self.build_body(organization_id, query)
        dates = []
        current = query.start.astimezone(UTC).date()
        while current <= query.end.astimezone(UTC).date():
            dates.append("aegis-events-" + current.strftime("%Y.%m.%d"))
            current += timedelta(days=1)
        result = self.client.search(
            index=",".join(dates), body=body, ignore_unavailable=True, allow_no_indices=True
        )
        if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
            raise RuntimeError("Search was incomplete")
        hits = result["hits"]["hits"]
        items = []
        for hit in hits[: query.limit]:
            source = hit["_source"]
            source.pop("organization_id", None)
            source["raw_event"] = source["raw_event"]["original"]
            items.append(source)
        return {
            "items": items,
            "total": result["hits"]["total"]["value"],
            "next_cursor": encode_cursor(hits[query.limit - 1]["sort"]) if len(hits) > query.limit else None,
            "aggregations": {
                bucket["key"]: bucket["doc_count"]
                for bucket in result.get("aggregations", {}).get("values", {}).get("buckets", [])
            },
        }
