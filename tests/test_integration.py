import os

import pytest
from redis import Redis
from sqlalchemy import text

from aegis.config import Settings
from aegis.db import database
from aegis.storage import OpenSearchStorage


@pytest.mark.integration
def test_real_dependency_connectivity():
    if not os.environ.get("AEGIS_INTEGRATION"):
        pytest.skip("Set AEGIS_INTEGRATION=1 with PostgreSQL, Redis and OpenSearch configured")
    settings = Settings()
    assert settings.database_url.startswith("postgresql") and settings.redis_url and settings.opensearch_url
    engine, _ = database(settings.database_url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar() == 1
    redis = Redis.from_url(settings.redis_url, socket_timeout=3)
    assert redis.ping()
    storage = OpenSearchStorage(settings)
    storage.setup()
    assert storage.health() == "HEALTHY"
