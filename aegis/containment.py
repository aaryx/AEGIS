"""Containment interpretation; historical records are never rewritten."""

NETWORK_ACTIONS = {"isolate_host", "unisolate_host"}


def receipt_outcome(action, status, result):
    if status != "SUCCESS":
        return "FAILED"
    if result.get("mode") == "simulated":
        return "SIMULATED"
    evidence = result.get("evidence") or {}
    desired = "ENFORCED" if action == "isolate_host" else "RELEASED"
    if (
        action in NETWORK_ACTIONS
        and result.get("mode") == "live"
        and result.get("outcome") == desired
        and isinstance(evidence, dict)
        and evidence.get("backend") == "nftables-v1"
        and evidence.get("verified") is True
        and evidence.get("state") == desired
        and isinstance(evidence.get("policy_sha256"), str)
        and len(evidence["policy_sha256"]) == 64
        and evidence.get("observed_sha256") == evidence["policy_sha256"]
    ):
        return desired
    return "UNKNOWN"


def execution_containment_status(status, result):
    if result.get("semantics_version") == 2:
        return status if status in {"SIMULATED", "ENFORCED", "RELEASED", "FAILED", "UNKNOWN"} else "UNKNOWN"
    if status in {"REQUESTED", "APPROVAL_REQUIRED"}:
        return "REQUESTED"
    if status in {"APPROVED", "DISPATCHED", "FAILED"}:
        return status
    # VERIFIED predates mode-aware verification. Do not reinterpret stored history.
    return "UNKNOWN"
