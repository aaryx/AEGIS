import json
import logging
from datetime import UTC, datetime

from prometheus_client import Counter, Histogram

API_LATENCY = Histogram("aegis_api_latency_seconds", "API latency", ["method", "route"])
SEARCH_LATENCY = Histogram("aegis_search_latency_seconds", "Search latency")
API_REQUESTS = Counter("aegis_api_requests_total", "API requests", ["method", "status"])


class JSONFormatter(logging.Formatter):
    def format(self, record):
        fields = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "service": record.name,
            "event": record.getMessage(),
        }
        for key in ("request_id", "error_type", "event_count", "duration_ms", "rule_id"):
            if hasattr(record, key):
                fields[key] = getattr(record, key)
        return json.dumps(fields)


def configure_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)
