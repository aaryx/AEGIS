#!/usr/bin/env bash
# AEGIS TITAN Phase 6: Linux Kernel Network-Namespace Containment Validation
# Exercises real nftables-v1 packet filtering in an isolated network namespace.
# Must run on Linux with root/sudo privileges (e.g., GitHub Actions Ubuntu runner).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

NS_NAME="aegis_cont_$$"
VETH_HOST="veth_h_$$"
VETH_NS="veth_n_$$"
HOST_IP="192.0.2.1"
NS_IP="192.0.2.2"
CONTROLLER_PORT=8443
EVIDENCE_FILE="${REPO_ROOT}/local-data/linux_containment_evidence.json"

mkdir -p "${REPO_ROOT}/local-data"

echo "=== AEGIS Phase 6: Linux Containment Qualification Drill ==="
echo "Operating System: $(uname -s) $(uname -r)"

if [ "$(uname -s)" != "Linux" ]; then
    echo "[!] Not running on Linux. Kernel containment drill cannot execute directly."
    exit 0
fi

# Ensure nftables and iproute2 are available
if ! command -v nft >/dev/null 2>&1; then
    echo "[*] Installing nftables..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y -qq nftables iproute2
    else
        echo "[!] nftables not installed and apt-get not available. Marking drill BLOCKED."
        exit 1
    fi
fi

# Deterministic cleanup trap
cleanup() {
    echo "[*] Running deterministic cleanup..."
    if ip netns list | grep -q "${NS_NAME}"; then
        echo "[*] Deleting network namespace ${NS_NAME}..."
        sudo ip netns del "${NS_NAME}" 2>/dev/null || true
    fi
    if ip link show "${VETH_HOST}" >/dev/null 2>&1; then
        sudo ip link del "${VETH_HOST}" 2>/dev/null || true
    fi
    sudo rm -f /run/aegis-containment.lock 2>/dev/null || true
    echo "[*] Cleanup complete."
}
trap cleanup EXIT INT TERM

echo "[*] Creating isolated network namespace: ${NS_NAME}..."
sudo ip netns add "${NS_NAME}"

echo "[*] Configuring veth pair: ${VETH_HOST} <-> ${VETH_NS}..."
sudo ip link add "${VETH_HOST}" type veth peer name "${VETH_NS}"
sudo ip link set "${VETH_NS}" netns "${NS_NAME}"

# Configure IP addressing on isolated veth
sudo ip addr add "${HOST_IP}/24" dev "${VETH_HOST}"
sudo ip link set "${VETH_HOST}" up

sudo ip netns exec "${NS_NAME}" ip link set lo up
sudo ip netns exec "${NS_NAME}" ip addr add "${NS_IP}/24" dev "${VETH_NS}"
sudo ip netns exec "${NS_NAME}" ip link set "${VETH_NS}" up
sudo ip netns exec "${NS_NAME}" ip route add default via "${HOST_IP}"

echo "[*] Network namespace network configuration verified:"
sudo ip netns exec "${NS_NAME}" ip addr show

if [ -z "${PYTHON_BIN:-}" ]; then
    if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then
        PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
    elif [ -n "${pythonLocation:-}" ] && [ -x "${pythonLocation}/bin/python" ]; then
        PYTHON_BIN="${pythonLocation}/bin/python"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python)"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
    else
        PYTHON_BIN="/usr/bin/python3"
    fi
fi

echo "[*] Using Python: ${PYTHON_BIN}"
echo "[*] Executing Python LinuxContainment qualification inside ${NS_NAME}..."

sudo env "PATH=$PATH" "PYTHONPATH=$REPO_ROOT" ip netns exec "${NS_NAME}" "$PYTHON_BIN" - <<EOF
import json
import os
import sys
from aegis.endpoint_firewall import LinuxContainment
from aegis.containment import receipt_outcome
from aegis.crypto import ed25519_sign, ed25519_verify, generate_ed25519_keypair

identity = "agent-phase6-qualification"
controller_ip = "${HOST_IP}"
controller_port = ${CONTROLLER_PORT}

print(f"[*] Initializing LinuxContainment for {identity} (Controller: {controller_ip}:{controller_port})")
containment = LinuxContainment(identity, controller_ip, controller_port)

# 1. Assert initial state is clean
initial_snap = containment.snapshot()
assert initial_snap is None, f"Expected clean initial state, got {initial_snap}"
print("[+] Initial snapshot is clean: None")

# 2. Apply Isolation
print("[*] Applying host isolation (isolate=True)...")
result_enforce = containment.apply(isolate=True)
assert result_enforce["mode"] == "live"
assert result_enforce["outcome"] == "ENFORCED"
evidence = result_enforce["evidence"]
assert evidence["backend"] == "nftables-v1"
assert evidence["verified"] is True
assert evidence["state"] == "ENFORCED"
assert evidence["policy_sha256"] == evidence["observed_sha256"]
print(f"[+] Isolation enforced successfully. Policy SHA-256: {evidence['policy_sha256']}")

# 3. Verify receipt outcome state machine
receipt_status = receipt_outcome("isolate_host", "SUCCESS", result_enforce)
assert receipt_status == "ENFORCED", f"Expected ENFORCED, got {receipt_status}"
print("[+] receipt_outcome verified as ENFORCED")

# 4. Generate & Verify Ed25519 Signed Receipt
privkey, pubkey_hex = generate_ed25519_keypair()
exec_id = "exec-phase6-test-1"
canonical_receipt_payload = f"{exec_id}:isolate_host:host-01:ENFORCED:{evidence['policy_sha256']}".encode()
sig_hex = ed25519_sign(privkey, canonical_receipt_payload)
assert ed25519_verify(pubkey_hex, sig_hex, canonical_receipt_payload), "Signature verification failed"
print("[+] Ed25519 receipt signature generated and verified")

# 5. Tampered evidence rejection (negative test)
tampered_result = dict(result_enforce)
tampered_result["evidence"] = dict(evidence)
tampered_result["evidence"]["observed_sha256"] = "f" * 64
assert receipt_outcome("isolate_host", "SUCCESS", tampered_result) == "UNKNOWN", "Tampered evidence did not fail closed to UNKNOWN!"
print("[+] Tampered evidence correctly failed closed to UNKNOWN")

# 6. Apply Quarantine Release (unisolate)
print("[*] Releasing host quarantine (isolate=False)...")
result_release = containment.apply(isolate=False)
assert result_release["outcome"] == "RELEASED"
post_release_snap = containment.snapshot()
assert post_release_snap is None, f"Expected table deletion, got {post_release_snap}"
release_status = receipt_outcome("unisolate_host", "SUCCESS", result_release)
assert release_status == "RELEASED", f"Expected RELEASED, got {release_status}"
print("[+] Host quarantine released successfully. Table cleaned from kernel nftables.")

# Write report artifact
report = {
    "status": "VERIFIED_KERNEL_ENFORCEMENT",
    "table": containment.table,
    "controller": f"{controller_ip}:{controller_port}",
    "enforce_policy_sha256": evidence["policy_sha256"],
    "receipt_enforced": receipt_status,
    "receipt_released": release_status,
    "ed25519_verification": "VALID",
    "tamper_detection": "FAIL_CLOSED_UNKNOWN",
    "cleanup_verified": post_release_snap is None,
}
with open("${EVIDENCE_FILE}", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

print("[+] All Linux kernel containment assertions passed successfully!")
EOF

echo "[*] Verified Linux containment evidence saved to ${EVIDENCE_FILE}:"
cat "${EVIDENCE_FILE}"

echo "=== AEGIS Phase 6 Linux Containment Qualification Complete: SUCCESS ==="
