"""AEGIS TITAN Phase 6: Containment Policy, Hash Verification & Receipt Logic.

Validates:
1. LinuxContainment policy generation, table naming, and rule structure.
2. Controller IP and port validation (rejects loopback, multicast, invalid IPv4).
3. Exact policy object hashing determinism.
4. receipt_outcome state machine: live vs simulated, ENFORCED vs RELEASED vs UNKNOWN vs FAILED.
5. Fail-closed behavior on tampered observed SHA-256 or invalid backend.
6. Ed25519 cryptographic receipt signing, verification, and tamper detection.
"""

import pytest

from aegis.containment import execution_containment_status, receipt_outcome
from aegis.crypto import ed25519_sign, ed25519_verify, generate_ed25519_keypair
from aegis.endpoint_firewall import LinuxContainment


def test_linux_containment_controller_address_validation():
    """Validates that LinuxContainment strictly enforces valid unicast non-loopback IPv4 controllers."""
    # Valid unicast IPv4
    c = LinuxContainment("agent-001", "10.0.1.5", 8443)
    assert c.address == "10.0.1.5"
    assert c.port == 8443
    assert c.table.startswith("aegis_")

    # Loopback IP rejected
    with pytest.raises(ValueError, match="Live policy requires a unicast, non-loopback IPv4 controller"):
        LinuxContainment("agent-001", "127.0.0.1", 8443)

    # Multicast IP rejected
    with pytest.raises(ValueError, match="Live policy requires a unicast, non-loopback IPv4 controller"):
        LinuxContainment("agent-001", "224.0.0.1", 8443)

    # Unspecified 0.0.0.0 rejected
    with pytest.raises(ValueError, match="Live policy requires a unicast, non-loopback IPv4 controller"):
        LinuxContainment("agent-001", "0.0.0.0", 8443)  # noqa: S104

    # Invalid ports rejected
    with pytest.raises(ValueError, match="Invalid controller port"):
        LinuxContainment("agent-001", "10.0.1.5", 0)

    with pytest.raises(ValueError, match="Invalid controller port"):
        LinuxContainment("agent-001", "10.0.1.5", 65536)


def test_linux_containment_policy_objects_structure_and_hashing():
    """Validates that policy objects generate filter chains with default DROP and explicit whitelists."""
    c = LinuxContainment("agent-prod-99", "192.168.10.50", 443)
    objects = c.objects
    assert isinstance(objects, list)
    assert len(objects) >= 5

    # Table object
    table_obj = objects[0]
    assert "table" in table_obj
    assert table_obj["table"]["family"] == "inet"
    assert table_obj["table"]["name"] == c.table
    assert table_obj["table"]["comment"].startswith("aegis-v1:")

    # Chains: input, output, forward with drop policy
    chains = [item["chain"] for item in objects if "chain" in item]
    chain_names = {ch["name"] for ch in chains}
    assert {"input", "output", "forward"}.issubset(chain_names)
    for ch in chains:
        assert ch["policy"] == "drop"
        assert ch["type"] == "filter"

    # Hashing determinism
    h1 = c.policy_hash
    assert isinstance(h1, str) and len(h1) == 64
    assert h1 == LinuxContainment._hash(objects)


def test_receipt_outcome_state_machine_matrix():
    """Validates receipt_outcome across live, simulated, verified, and tampered outcomes."""
    valid_hash = "a" * 64

    # 1. Successful simulated outcome
    assert receipt_outcome("isolate_host", "SUCCESS", {"mode": "simulated"}) == "SIMULATED"
    assert receipt_outcome("unisolate_host", "SUCCESS", {"mode": "simulated"}) == "SIMULATED"

    # 2. Failed status returns FAILED regardless of payload
    assert receipt_outcome("isolate_host", "FAILED", {"mode": "live"}) == "FAILED"
    assert receipt_outcome("isolate_host", "ERROR", {}) == "FAILED"

    # 3. Valid live enforcement
    valid_enforced_result = {
        "mode": "live",
        "outcome": "ENFORCED",
        "evidence": {
            "backend": "nftables-v1",
            "verified": True,
            "state": "ENFORCED",
            "policy_sha256": valid_hash,
            "observed_sha256": valid_hash,
        },
    }
    assert receipt_outcome("isolate_host", "SUCCESS", valid_enforced_result) == "ENFORCED"

    # 4. Valid live release
    valid_released_result = {
        "mode": "live",
        "outcome": "RELEASED",
        "evidence": {
            "backend": "nftables-v1",
            "verified": True,
            "state": "RELEASED",
            "policy_sha256": valid_hash,
            "observed_sha256": valid_hash,
        },
    }
    assert receipt_outcome("unisolate_host", "SUCCESS", valid_released_result) == "RELEASED"

    # 5. Tampered observed hash fails closed to UNKNOWN
    tampered_hash_result = {
        "mode": "live",
        "outcome": "ENFORCED",
        "evidence": {
            "backend": "nftables-v1",
            "verified": True,
            "state": "ENFORCED",
            "policy_sha256": valid_hash,
            "observed_sha256": "b" * 64,  # Mismatched!
        },
    }
    assert receipt_outcome("isolate_host", "SUCCESS", tampered_hash_result) == "UNKNOWN"

    # 6. Unverified evidence fails closed to UNKNOWN
    unverified_result = {
        "mode": "live",
        "outcome": "ENFORCED",
        "evidence": {
            "backend": "nftables-v1",
            "verified": False,  # Unverified!
            "state": "ENFORCED",
            "policy_sha256": valid_hash,
            "observed_sha256": valid_hash,
        },
    }
    assert receipt_outcome("isolate_host", "SUCCESS", unverified_result) == "UNKNOWN"

    # 7. Unsupported backend fails closed to UNKNOWN
    bad_backend_result = {
        "mode": "live",
        "outcome": "ENFORCED",
        "evidence": {
            "backend": "iptables-legacy",  # Not nftables-v1!
            "verified": True,
            "state": "ENFORCED",
            "policy_sha256": valid_hash,
            "observed_sha256": valid_hash,
        },
    }
    assert receipt_outcome("isolate_host", "SUCCESS", bad_backend_result) == "UNKNOWN"


def test_execution_containment_status_semantics_version_2():
    """Validates execution_containment_status parsing and legacy handling."""
    # Semantics version 2: trusted states preserved, unrecognized becomes UNKNOWN
    assert execution_containment_status("ENFORCED", {"semantics_version": 2}) == "ENFORCED"
    assert execution_containment_status("RELEASED", {"semantics_version": 2}) == "RELEASED"
    assert execution_containment_status("SIMULATED", {"semantics_version": 2}) == "SIMULATED"
    assert execution_containment_status("FAILED", {"semantics_version": 2}) == "FAILED"
    assert execution_containment_status("UNKNOWN", {"semantics_version": 2}) == "UNKNOWN"
    assert execution_containment_status("BOGUS_STATUS", {"semantics_version": 2}) == "UNKNOWN"

    # Legacy semantics without version 2: VERIFIED maps to UNKNOWN to prevent retroactive trust
    assert execution_containment_status("VERIFIED", {}) == "UNKNOWN"
    assert execution_containment_status("REQUESTED", {}) == "REQUESTED"
    assert execution_containment_status("APPROVAL_REQUIRED", {}) == "REQUESTED"
    assert execution_containment_status("APPROVED", {}) == "APPROVED"


def test_ed25519_receipt_cryptographic_verification():
    """Validates that containment receipts are digitally signed and tampering is detected."""
    privkey, pubkey_hex = generate_ed25519_keypair()
    exec_id = "exec-containment-991"
    policy_hash = "c" * 64
    canonical_msg = f"{exec_id}:isolate_host:target-srv-01:ENFORCED:{policy_hash}".encode()

    sig_hex = ed25519_sign(privkey, canonical_msg)
    assert ed25519_verify(pubkey_hex, sig_hex, canonical_msg) is True

    # Tampered message fails verification
    tampered_msg = f"{exec_id}:isolate_host:target-srv-02:ENFORCED:{policy_hash}".encode()
    assert ed25519_verify(pubkey_hex, sig_hex, tampered_msg) is False

    # Tampered signature fails verification
    tampered_sig_hex = "00" * 4 + sig_hex[8:]
    assert ed25519_verify(pubkey_hex, tampered_sig_hex, canonical_msg) is False
