"""Optional read-only intelligence providers; fixed endpoints, bounded transport."""

import json
import time
from typing import Literal, Protocol
from urllib.parse import quote

from pydantic import Field

from aegis.integrations import request_bytes
from aegis.schemas import StrictModel


class ProviderResult(StrictModel):
    status: Literal["COMPLETE", "UNKNOWN", "UNAVAILABLE", "FAILED"]
    verdict: Literal["unknown", "malicious", "suspicious", "undetected"] = "unknown"
    confidence: int | None = Field(default=None, ge=0, le=100)
    assessment_origin: Literal["provider", "aegis-derived", "mock", "none"] = "none"
    provider_reference: str | None = None
    evidence: dict = Field(default_factory=dict)
    first_seen: int | None = None
    last_seen: int | None = None
    reason: str
    retryable: bool = False


class Provider(Protocol):
    def lookup(self, settings, observable) -> ProviderResult: ...


class MockProvider:
    def lookup(self, settings, observable):
        if not settings.intel_mock_enabled:
            return ProviderResult(status="UNAVAILABLE", reason="mock_disabled")
        verdict = "unknown"
        # Explicit fixture only; private/reserved IPs never receive synthetic malicious scores.
        if observable.type == "domain" and observable.value == "malicious.example.test":
            verdict = "malicious"
        if observable.type == "sha256" and observable.value == "a" * 64:
            verdict = "suspicious"
        return ProviderResult(
            status="COMPLETE" if verdict != "unknown" else "UNKNOWN",
            verdict=verdict,
            assessment_origin="mock",
            confidence=90 if verdict != "unknown" else None,
            evidence={"fixture": True, "not_real_intelligence": True},
            reason="deterministic_test_fixture",
        )


class VirusTotalProvider:
    def lookup(self, settings, observable):
        if not settings.intel_vt_enabled or not settings.intel_vt_api_key.get_secret_value():
            return ProviderResult(status="UNAVAILABLE", reason="provider_not_configured")
        if not observable.external_allowed or observable.type == "url":
            return ProviderResult(status="UNAVAILABLE", reason="external_lookup_policy")
        segment = {
            "ip": "ip_addresses",
            "domain": "domains",
            "md5": "files",
            "sha1": "files",
            "sha256": "files",
        }[observable.type]
        endpoint = "https://www.virustotal.com/api/v3/" + segment + "/" + quote(observable.value, safe="")
        # Reuse pinned-DNS, TLS-verified transport. No analyst-controlled endpoint or redirect.
        transport = settings.model_copy(
            update={
                "integration_allowed_hosts": ["www.virustotal.com"],
                "integration_timeout_seconds": settings.intel_timeout_seconds,
                "integration_max_bytes": 262144,
            }
        )
        try:
            raw = request_bytes(
                transport, endpoint, headers={"x-apikey": settings.intel_vt_api_key.get_secret_value()}
            )
            attributes = json.loads(raw)["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            counts = {k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}
            if not all(type(v) is int and 0 <= v <= 100000 for v in counts.values()):
                raise ValueError("Invalid provider counts")
            verdict = (
                "malicious"
                if counts["malicious"]
                else "suspicious"
                if counts["suspicious"]
                else "undetected"
                if sum(counts.values())
                else "unknown"
            )

            def timestamp(key):
                value = attributes.get(key)
                return value if type(value) is int and 0 <= value <= time.time() + 86400 else None

            return ProviderResult(
                status="COMPLETE" if verdict != "unknown" else "UNKNOWN",
                verdict=verdict,
                assessment_origin="aegis-derived",
                provider_reference=endpoint,
                evidence={
                    "provider_reported_analysis_counts": counts,
                    "method": "any_malicious_then_any_suspicious_else_undetected_v1",
                    "undetected_is_not_clean": True,
                },
                first_seen=timestamp("first_submission_date") or timestamp("first_seen_date"),
                last_seen=timestamp("last_analysis_date"),
                reason="provider_analysis_counts",
            )
        except ValueError as exc:
            if str(exc) == "Integration returned HTTP 404":
                return ProviderResult(status="UNKNOWN", reason="provider_has_no_record")
            if str(exc) in {"Integration returned HTTP 401", "Integration returned HTTP 403"}:
                return ProviderResult(status="UNAVAILABLE", reason="provider_authorization_failed")
            return ProviderResult(status="FAILED", reason="provider_response_failed", retryable=True)
        except Exception:
            return ProviderResult(status="FAILED", reason="provider_unavailable", retryable=True)


PROVIDERS: dict[str, Provider] = {"mock": MockProvider(), "virustotal": VirusTotalProvider()}
