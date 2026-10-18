"""Unit tests verifying OpenSearch query building safeguards, wildcard handling, and tenant scoping (P1).
"""

from aegis.config import Settings
from aegis.schemas import Predicate, SearchQuery
from aegis.storage import OpenSearchStorage


def test_opensearch_query_builder_enforces_tenant_and_optimizes_wildcards():
    """Verify that build_body always enforces tenant scoping, distinguishes text vs wildcard fields, and bounds total hits."""
    settings = Settings(opensearch_url="http://localhost:9200")
    storage = object.__new__(OpenSearchStorage)
    storage.settings = settings

    query = SearchQuery(
        text="malware payload",
        filters=[
            Predicate(field="message", op="contains", value="suspicious PowerShell execution"),
            Predicate(field="command_line", op="contains", value="-enc AAAA"),
            Predicate(field="host", op="contains", value="WEB01"),
            Predicate(field="source_type", op="eq", value="linux"),
        ],
        limit=100,
        aggregate="event_category",
    )

    org_id = "tenant-prod-xyz-123"
    body = storage.build_body(org_id, query)

    # 1. Enforces tenant scope
    filter_clauses = body["query"]["bool"]["filter"]
    assert {"term": {"organization_id": org_id}} in filter_clauses

    # 2. Message field uses match_phrase rather than expensive unindexed wildcard
    assert {"match_phrase": {"message": "suspicious PowerShell execution"}} in filter_clauses

    # 3. Dedicated wildcard field command_line uses wildcard query
    assert {"wildcard": {"command_line": {"value": "*-enc AAAA*", "case_insensitive": True}}} in filter_clauses

    # 4. Keyword field uses case-insensitive wildcard
    assert {"wildcard": {"host": {"value": "*WEB01*", "case_insensitive": True}}} in filter_clauses

    # 5. Exact match uses term query
    assert {"term": {"source_type": "linux"}} in filter_clauses

    # 6. Full-text must clause
    assert {"match_phrase": {"message": "malware payload"}} in body["query"]["bool"]["must"]

    # 7. Total hits and timeout are bounded
    assert body["track_total_hits"] <= 10000
    assert body["timeout"] == "5s"

    # 8. Aggregation is bounded
    assert body["aggs"]["values"]["terms"]["field"] == "event_category"
    assert body["aggs"]["values"]["terms"]["size"] == 50


def test_opensearch_production_enforces_https_and_ca():
    """Verify that production mode strictly enforces HTTPS and CA validation for OpenSearch."""
    import pytest
    from pydantic import ValidationError

    # 1. Plaintext HTTP in production must be rejected
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            environment="production",
            database_url="postgresql+psycopg://aegis:pass@127.0.0.1:5432/aegis?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.pem",
            redis_url="rediss://:pass@127.0.0.1:6379/0",
            opensearch_url="http://opensearch:9200",
            opensearch_ca="/etc/ssl/certs/ca.pem",
            audit_secret="super-secret-key-at-least-32chars-long-xxx",
            cookie_secure=True,
            public_origin="https://aegis.example.com",
            _env_file=None,
        )
    assert "Production requires HTTPS for OpenSearch" in str(exc_info.value)

    # 2. HTTPS without CA certificate in production must be rejected
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            environment="production",
            database_url="postgresql+psycopg://aegis:pass@127.0.0.1:5432/aegis?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.pem",
            redis_url="rediss://:pass@127.0.0.1:6379/0",
            opensearch_url="https://opensearch:9200",
            opensearch_ca=None,
            audit_secret="super-secret-key-at-least-32chars-long-xxx",
            cookie_secure=True,
            public_origin="https://aegis.example.com",
            _env_file=None,
        )
    assert "Production requires CA certificate validation" in str(exc_info.value)

    # 3. HTTPS with CA certificate in production must succeed
    valid_settings = Settings(
        environment="production",
        database_url="postgresql+psycopg://aegis:pass@127.0.0.1:5432/aegis?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.pem",
        redis_url="rediss://:pass@127.0.0.1:6379/0",
        opensearch_url="https://opensearch:9200",
        opensearch_ca="/etc/ssl/certs/ca.pem",
        audit_secret="super-secret-key-at-least-32chars-long-xxx",
        cookie_secure=True,
        public_origin="https://aegis.example.com",
        _env_file=None,
    )
    assert valid_settings.opensearch_url == "https://opensearch:9200"
    assert valid_settings.opensearch_ca == "/etc/ssl/certs/ca.pem"


def test_opensearch_client_enforces_certificate_verification(monkeypatch):
    """Verify OpenSearch client is instantiated with verify_certs=True and proper CA certs."""
    captured_kwargs = {}

    def mock_opensearch_init(self, hosts=None, **kwargs):
        captured_kwargs.update(kwargs)

    monkeypatch.setattr("aegis.storage.OpenSearch.__init__", mock_opensearch_init)

    settings = Settings(
        environment="development",
        opensearch_url="https://opensearch:9200",
        opensearch_ca="/path/to/custom_ca.pem",
        _env_file=None,
    )
    storage = OpenSearchStorage(settings)
    assert storage is not None

    # Certificate verification must NEVER be disabled
    assert captured_kwargs.get("verify_certs") is True
    assert captured_kwargs.get("ca_certs") == "/path/to/custom_ca.pem"
