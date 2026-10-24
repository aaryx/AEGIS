"""AEGIS Endpoint Containment & Execution Agent.

Provides active host isolation, process termination, and policy verification
with per-endpoint Ed25519 asymmetric cryptography, controller-signed command authentication,
and cryptographically signed execution receipts.

SECURITY NOTICE:
A valid cryptographic signature proves possession of the relevant endpoint private key.
It does not independently prove that a compromised endpoint actually performed the claimed
operating system operation. Physical and root compromises must be factored into host trust models.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import platform
import re
import secrets
import socket
import sys
import threading
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis import __version__
from aegis.crypto import (
    ed25519_sign_canonical,
    ed25519_verify_canonical,
    generate_ed25519_keypair,
    load_private_key,
    save_private_key,
)
from aegis.parsers import canonical

logger = logging.getLogger("aegis.agent")


class EndpointAgent:
    """Active endpoint agent for AEGIS SIEM/SOAR.

    Monitors host health, periodically heartbeats host posture,
    polls approved containment playbooks, verifies controller-signed command envelopes,
    executes network isolation or process termination, and submits cryptographically signed
    Ed25519 execution receipts.
    """

    def __init__(
        self,
        name: str | None = None,
        server_url: str = "http://127.0.0.1:8000",
        token: str | None = None,
        controller_ip: str = "127.0.0.1",
        simulation_mode: bool = True,
        signing_key: Ed25519PrivateKey | None = None,
        key_path: str | None = None,
        controller_public_key: str | None = None,
        allow_network_policy: bool = False,
    ) -> None:
        self.name = name or socket.gethostname()
        self.server_url = server_url.rstrip("/")
        self.token = token or ""
        self.controller_ip = controller_ip
        self.simulation_mode = simulation_mode
        self.isolated = False
        self.containment_state = "UNKNOWN"
        self.allow_network_policy = allow_network_policy
        self._execution_lock = threading.Lock()
        self._receipts: dict[str, dict] = {}
        self.active_firewall_rules: list[str] = []
        self.key_path = key_path
        self.agent_id: str | None = None
        self.controller_public_key = controller_public_key
        self._seen_nonces: set[str] = set()

        # Initialize or load Ed25519 private key
        if signing_key is not None:
            self.private_key = signing_key
        elif key_path and os.path.exists(key_path):
            self.private_key = load_private_key(key_path)
        else:
            self.private_key, _ = generate_ed25519_keypair()
            if key_path:
                save_private_key(self.private_key, key_path)

        self.public_key_hex = self.private_key.public_key().public_bytes_raw().hex()

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get_local_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return str(s.getsockname()[0])
        except Exception:
            return "127.0.0.1"

    def get_system_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": __version__,
            "os": platform.system().lower(),
            "os_release": platform.release(),
            "ip": self._get_local_ip(),
            "status": "ONLINE",
            "isolation_status": self.containment_state,
            "capabilities": ["isolate_host", "unisolate_host", "terminate_process"],
            "public_key": self.public_key_hex,
        }

    def _request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
        client: Any = None,
    ) -> Any:
        url = f"{self.server_url}/api/v1/{path.lstrip('/')}"
        if client is not None:
            kwargs: dict[str, Any] = {"json": json_body}
            if self.token:
                kwargs["headers"] = {"Authorization": f"Bearer {self.token}"}
            resp = client.request(method, url, **kwargs)
            if hasattr(resp, "raise_for_status"):
                resp.raise_for_status()
            return resp.json()
        with httpx.Client(timeout=15.0) as http_client:
            resp = http_client.request(method, url, json=json_body, headers=self.headers())
            resp.raise_for_status()
            return resp.json()

    def enroll(self, enrollment_token: str, client: Any = None) -> dict[str, Any]:
        """Enrolls this endpoint with the controller using a single-use expiring enrollment token."""
        payload = {
            "name": self.name,
            "enrollment_token": enrollment_token,
            "public_key": self.public_key_hex,
            "system_info": self.get_system_info(),
        }
        res: dict[str, Any] = self._request("POST", "agents/enroll", payload, client=client)
        self.agent_id = res.get("agent_id")
        self.token = res.get("auth_token", "")
        self.controller_public_key = res.get("controller_public_key")
        logger.info("Agent %s successfully enrolled (agent_id=%s)", self.name, self.agent_id)
        return res

    def rotate_key(self, client: Any = None) -> dict[str, Any]:
        """Rotates the endpoint's Ed25519 keypair and registers the new public key."""
        new_private, new_public_hex = generate_ed25519_keypair()
        rotation_msg = {"name": self.name, "new_public_key": new_public_hex}
        sig = ed25519_sign_canonical(self.private_key, rotation_msg)
        payload = {
            "new_public_key": new_public_hex,
            "rotation_signature": sig,
        }
        res: dict[str, Any] = self._request(
            "POST", f"agents/{self.name}/rotate-key", payload, client=client
        )
        self.private_key = new_private
        self.public_key_hex = new_public_hex
        if self.key_path:
            save_private_key(self.private_key, self.key_path)
        logger.info("Agent %s rotated cryptographic keypair to %s", self.name, new_public_hex[:16])
        return res

    def heartbeat(self, client: Any = None) -> dict[str, Any]:
        """Registers agent posture and telemetry with AEGIS controller."""
        payload = self.get_system_info()
        result: dict[str, Any] = self._request("POST", "agents/heartbeat", payload, client=client)
        self.agent_id = result.get("agent_id") or self.agent_id
        logger.info("Heartbeat sent for %s (isolated=%s)", self.name, self.isolated)
        return result

    def verify_command(self, cmd: dict[str, Any], consume: bool = True) -> bool:
        """Verifies controller signature, expiry, replay, and scoping on a command."""
        envelope = cmd.get("envelope")
        sig = cmd.get("controller_signature")
        ctrl_pubkey = self.controller_public_key or (cmd.get("controller_public_key") if self.simulation_mode else None)

        if not envelope or not sig or not ctrl_pubkey:
            # Reject unsigned commands
            logger.warning("Rejecting command %s: missing cryptographic envelope or signature", cmd.get("id"))
            return False

        # 1. Verify Ed25519 controller signature
        if not ed25519_verify_canonical(ctrl_pubkey, sig, envelope):
            logger.warning("Rejecting command %s: invalid controller signature", cmd.get("id"))
            return False

        if (envelope.get("command_id") != cmd.get("id") or envelope.get("action") != cmd.get("action")
                or envelope.get("parameters", {}) != cmd.get("params", {})):
            return False

        # 2. Verify target agent scoping
        target_agent = envelope.get("agent_id")
        if target_agent not in {self.agent_id, self.name} or not target_agent:
            logger.warning(
                "Rejecting command %s: target agent %s does not match self (%s)",
                cmd.get("id"),
                target_agent,
                self.agent_id,
            )
            return False

        # 3. Verify timestamp and expiration
        now_ts = time.time()
        expires_at = envelope.get("expires_at", 0)
        if (type(expires_at) not in (int, float) or not math.isfinite(expires_at) or expires_at < now_ts):
            logger.warning("Rejecting command %s: command expired at %s (now=%s)", cmd.get("id"), expires_at, now_ts)
            return False

        # 4. Anti-replay verification: nonce must be unique
        nonce = envelope.get("nonce")
        if not isinstance(nonce, str) or not nonce or (consume and nonce in self._seen_nonces):
            logger.warning("Rejecting command %s: replayed or missing nonce %s", cmd.get("id"), nonce)
            return False

        if consume:
            self._seen_nonces.add(nonce)
        return True

    def poll_commands(self, client: Any = None) -> list[dict[str, Any]]:
        """Queries for approved containment playbooks targeting this host and verifies controller signatures."""
        commands: list[dict[str, Any]] = self._request(
            "GET", f"agents/{self.name}/commands", client=client
        )
        verified: list[dict[str, Any]] = []
        for cmd in commands:
            if self.verify_command(cmd, consume=cmd.get("id") not in self._receipts):
                verified.append(cmd)
            else:
                logger.error("Command %s rejected by agent signature and security verification", cmd.get("id"))
        return verified

    def _network_action(self, isolate: bool, controller_ip: str | None = None):
        from aegis.endpoint_firewall import LinuxContainment

        # The exception is operator-configured, never selected by a playbook.
        if controller_ip is not None and controller_ip != self.controller_ip:
            raise ValueError("Command cannot override operator controller IP")
        if self.simulation_mode:
            self.containment_state = "SIMULATED"
            self.isolated = False
            return {"action": "isolate_host" if isolate else "unisolate_host",
                    "mode": "simulated", "outcome": "SIMULATED", "isolated": False,
                    "requested_isolation": isolate}
        if not self.allow_network_policy or sys.platform != "linux":
            raise RuntimeError("Live network policy is disabled or unsupported")
        if not self.key_path or not self.controller_public_key or not self.agent_id:
            raise RuntimeError("Live policy requires enrollment, a persistent agent key and pinned controller key")
        endpoint = urlsplit(self.server_url)
        if endpoint.scheme != "https" or endpoint.hostname != self.controller_ip:
            raise ValueError("Live controller URL must use HTTPS and the configured IPv4 literal")
        policy = LinuxContainment(self.agent_id, self.controller_ip, endpoint.port or 443)
        try:
            result = policy.apply(isolate)
        except Exception:
            self.isolated, self.containment_state = False, "UNKNOWN"
            raise
        self.isolated, self.containment_state = isolate, result["outcome"]
        return result

    def isolate_host(self, controller_ip: str | None = None) -> dict[str, Any]:
        return self._network_action(True, controller_ip)

    def unisolate_host(self) -> dict[str, Any]:
        return self._network_action(False)

    def terminate_process(self, pid: int | None = None, name: str | None = None) -> dict[str, Any]:
        """Terminates an offending process by PID or process name."""
        if pid is None and not name:
            raise ValueError("Specify either pid or process name to terminate")

        if pid is not None:
            if pid <= 1:
                raise ValueError("Invalid target PID: terminating system or critical processes is forbidden")

        if name is not None:
            clean_name = str(name).strip()
            if (
                not clean_name
                or not re.match(r"^[\w\.-]+$", clean_name)
                or clean_name.lower() in {
                    "init", "system", "idle", "systemd", "winlogon.exe",
                    "csrss.exe", "lsass.exe", "smss.exe", "services.exe",
                }
            ):
                raise ValueError("Invalid or restricted process name for termination")

        if self.simulation_mode:
            return {
                "action": "terminate_process",
                "terminated": True,
                "mode": "simulated",
                "target_pid": pid,
                "target_name": name,
                "timestamp": datetime.now(UTC).isoformat(),
            }

        # Sending a signal is not proof of termination. A qualified OS adapter
        # with process-identity binding and postcondition checks is required.
        raise RuntimeError("Live process termination is not qualified")

    def submit_receipt(
        self,
        command_id: str,
        action: str,
        status: str,
        receipt: dict[str, Any],
        signature: str,
        receipt_hash: str,
        details: dict[str, Any],
        client: Any = None,
    ) -> dict[str, Any]:
        """Submits cryptographically signed Ed25519 execution receipt to AEGIS controller."""
        payload = {
            "command_id": command_id,
            "action": action,
            "status": status,
            "receipt": receipt,
            "signature": signature,
            "receipt_hash": receipt_hash,
            "details": details,
        }
        result: dict[str, Any] = self._request(
            "POST", f"agents/{self.name}/receipts", payload, client=client
        )
        return result

    def execute_command(self, command: dict[str, Any], client: Any = None) -> dict[str, Any]:
        """Reverify at point of use; cache the signed outcome before transport."""
        with self._execution_lock:
            if not self.verify_command(command, consume=False):
                raise ValueError("Invalid or expired controller command")
            envelope = command["envelope"]
            cmd_id = envelope["command_id"]
            command_hash = hashlib.sha256(canonical(envelope).encode()).hexdigest()
            cached = self._receipts.get(cmd_id)
            if cached and cached["command_hash"] != command_hash:
                raise ValueError("Command ID reused with different signed content")
            if not cached:
                action, params = envelope["action"], envelope.get("parameters", {})
                try:
                    if action == "isolate_host":
                        if set(params) - {"controller_ip"}:
                            raise ValueError("Unsupported isolation parameters")
                        result = self.isolate_host(controller_ip=params.get("controller_ip"))
                    elif action == "unisolate_host":
                        if params:
                            raise ValueError("Unisolation does not accept parameters")
                        result = self.unisolate_host()
                    elif action == "terminate_process":
                        result = self.terminate_process(pid=params.get("pid"), name=params.get("name"))
                    else:
                        raise ValueError("Unsupported endpoint action")
                    status = "SUCCESS"
                except Exception as exc:
                    self.isolated, self.containment_state = False, "UNKNOWN"
                    status = "FAILED"
                    result = {"mode": "simulated" if self.simulation_mode else "live",
                              "outcome": "FAILED", "error": type(exc).__name__,
                              "evidence": getattr(exc, "evidence", {})}
                receipt = {"version": "2.0", "command_id": cmd_id,
                           "agent_id": self.agent_id or self.name,
                           "organization_id": envelope.get("organization_id", ""),
                           "action": action, "status": status, "result": result,
                           "command_signature": command["controller_signature"],
                           "timestamp": time.time(), "nonce": secrets.token_hex(16)}
                cached = {"command_hash": command_hash, "receipt": receipt,
                          "signature": ed25519_sign_canonical(self.private_key, receipt)}
                self._receipts[cmd_id] = cached
            receipt = cached["receipt"]
        # Transport failure must not manufacture a second, contradictory outcome.
        return self.submit_receipt(cmd_id, receipt["action"], receipt["status"], receipt,
                                   cached["signature"], hashlib.sha256(canonical(receipt).encode()).hexdigest(),
                                   receipt["result"], client=client)

    def run_cycle(self, client: Any = None) -> dict[str, Any]:
        """Runs a single poll and execution cycle."""
        hb = self.heartbeat(client=client)
        commands = self.poll_commands(client=client)
        executed = []
        for cmd in commands:
            logger.info("Executing containment command %s (%s)", cmd["id"], cmd["action"])
            res = self.execute_command(cmd, client=client)
            executed.append(res)
        return {
            "heartbeat": hb,
            "pending_commands": len(commands),
            "executed": executed,
        }

    def run_forever(self, interval: float = 5.0) -> None:
        """Runs continuous background daemon."""
        logger.info("Starting AEGIS endpoint agent '%s' against %s", self.name, self.server_url)
        while True:
            try:
                self.run_cycle()
            except KeyboardInterrupt:
                logger.info("Agent stopped by operator")
                break
            except Exception as exc:
                logger.error("Error during agent execution cycle: %s", exc)
            time.sleep(interval)
