"""Tests for AI evidence-grounding controls, citation validation, and deterministic fallbacks (P1).
"""

from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from aegis.ai import (
    Analysis,
    Claim,
    OpenAIProvider,
    analyze_with_fallback,
)
from aegis.config import Settings


def test_ai_rejects_fabricated_and_cross_tenant_evidence():
    """AI analysis must reject any claim that cites event IDs not present in the supplied evidence."""
    settings = Settings(
        ai_provider="openai",
        ai_api_key=SecretStr("mock-key"),
        audit_secret=SecretStr("0" * 32),
    )
    provider = OpenAIProvider(settings)

    # Legitimate evidence from tenant A
    evidence = {
        "events": [
            {"event_id": "EVT-TENANT-A-01", "timestamp": "2026-01-01T00:00:00Z"},
            {"event_id": "EVT-TENANT-A-02", "timestamp": "2026-01-01T00:01:00Z"},
        ],
        "alerts": [],
    }

    # Mock response where AI hallucinated or cited cross-tenant event EVT-CROSS-TENANT-B
    mock_bad_analysis = Analysis(
        provider="openai",
        generated=True,
        claims=[
            Claim(
                category="Observed",
                text="Observed cross-tenant activity",
                event_ids=["EVT-TENANT-A-01", "EVT-CROSS-TENANT-B"],
            )
        ],
        recommended_steps=["Isolate host"],
    )
    setattr(provider, "complete", MagicMock(return_value=mock_bad_analysis))  # noqa: B010

    with pytest.raises(ValueError, match="AI cited unsupported evidence"):
        provider.analyze(evidence)


def test_ai_rejects_observed_claim_without_citations():
    """Any claim marked 'Observed' must include citation event IDs."""
    settings = Settings(
        ai_provider="openai",
        ai_api_key=SecretStr("mock-key"),
        audit_secret=SecretStr("0" * 32),
    )
    provider = OpenAIProvider(settings)

    evidence = {
        "events": [{"event_id": "EVT-01", "timestamp": "2026-01-01T00:00:00Z"}],
        "alerts": [],
    }

    # Mock response where 'Observed' claim has no citations
    mock_uncited = Analysis(
        provider="openai",
        generated=True,
        claims=[
            Claim(
                category="Observed",
                text="Malicious execution observed on host without event citations",
                event_ids=[],
            )
        ],
        recommended_steps=["Isolate host"],
    )
    setattr(provider, "complete", MagicMock(return_value=mock_uncited))  # noqa: B010

    with pytest.raises(ValueError, match="Observed AI claim lacks required evidence citations"):
        provider.analyze(evidence)


def test_ai_limitations_and_fallback_on_failure():
    """When an external AI fails or produces bad citations, fallback to LocalProvider is automatic."""
    settings = Settings(
        ai_provider="openai",
        ai_api_key=SecretStr("mock-key"),
        audit_secret=SecretStr("0" * 32),
    )

    investigation = {
        "alerts": [{"id": "ALT-1", "rule_id": "RULE-1", "severity": "high", "risk_score": 80}],
        "evidence": [
            {
                "event": {
                    "event_id": "EVT-01",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "event_category": "authentication",
                    "action": "login",
                    "outcome": "failure",
                }
            }
        ],
    }

    # analyze_with_fallback will attempt OpenAIProvider, which fails without network, falling back to LocalProvider
    result = analyze_with_fallback(settings, investigation)
    assert result.provider == "local-deterministic"
    assert not result.generated
    assert any("fallback" in limit.lower() for limit in result.limitations)
