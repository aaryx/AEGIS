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
