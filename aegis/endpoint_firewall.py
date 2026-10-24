"""Opt-in Linux host policy. Only an exact, key-owned nftables table is removable.

No global flush, existing chain edits, shell, sudo or automatic privilege escalation.
Live qualification in a disposable network namespace is still required.
"""

import hashlib
import ipaddress
import json
import os
import stat
import subprocess  # nosec: B404 # endpoint firewall invokes /usr/sbin/nft without shell
import sys
from contextlib import contextmanager
from typing import Any


class ContainmentError(RuntimeError):
    def __init__(self, error_type, commands, message: str = ""):
        super().__init__(f"{error_type}: {message}" if message else error_type)
        self.evidence = {"backend": "nftables-v1", "verified": False, "state": "UNKNOWN",
                         "error_type": error_type, "attempted_commands": commands, "error_message": message}


class LinuxContainment:
    def __init__(self, identity: str, controller_ip: str, controller_port: int):
        address = ipaddress.ip_address(controller_ip)
        if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError("Live policy requires a unicast, non-loopback IPv4 controller")
        if type(controller_port) is not int or not 1 <= controller_port <= 65535:
            raise ValueError("Invalid controller port")
        self.address, self.port = str(address), controller_port
        owner = hashlib.sha256(identity.encode()).hexdigest()
        self.table = "aegis_" + owner[:24]
        self.owner = "aegis-v1:" + owner
        self.objects = self._objects()
        self.policy_hash = self._hash(self.objects)

    @staticmethod
    def _hash(objects):
        return hashlib.sha256(json.dumps(objects, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _objects(self):
        base = {"family": "inet", "table": self.table}
        objects: list[dict[str, Any]] = [{"table": {"family": "inet", "name": self.table, "comment": self.owner}}]
        for hook in ("input", "output", "forward"):
            objects.append({"chain": {**base, "name": hook, "type": "filter", "hook": hook,
                                      "prio": -10, "policy": "drop"}})
        for hook in ("input", "output"):
            interface = "iifname" if hook == "input" else "oifname"
            objects.append({"rule": {**base, "chain": hook, "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": interface}}, "right": "lo"}},
                {"accept": None},
            ]}})
            expr = [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field":
                    "saddr" if hook == "input" else "daddr"}}, "right": self.address}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field":
                    "sport" if hook == "input" else "dport"}}, "right": self.port}},
            ]
            if hook == "input":
                expr.append({"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "established"}})
            objects.append({"rule": {**base, "chain": hook, "expr": [*expr, {"accept": None}]}})
        return objects

    @contextmanager
    def locked(self):
        if sys.platform == "linux":
            import fcntl

            # /run is root-owned; reject links and existing files writable by others.
            fd = os.open("/run/aegis-containment.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise RuntimeError(f"Unsafe containment lock file: uid={info.st_uid} euid={os.geteuid()} mode={oct(info.st_mode)}")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                os.close(fd)
        else:
            raise RuntimeError("Linux containment lock unavailable")

    def run(self, arguments, document=None):
        completed = subprocess.run(  # noqa: S603  # nosec B603
            ["/usr/sbin/nft", *arguments],
            input=json.dumps(document) if document is not None else None,
            text=True, capture_output=True, check=True, timeout=10,
        )
        return json.loads(completed.stdout) if completed.stdout.strip() else {}

    def snapshot(self):
        tables = self.run(["-j", "list", "tables"])["nftables"]
        if not any(t.get("table", {}).get("family") == "inet" and
                   t.get("table", {}).get("name") == self.table for t in tables):
            return None
        entries = self.run(["-j", "list", "table", "inet", self.table])["nftables"]
        # Kernel-assigned handles are the only ignored policy fields.
        objects = [{kind: {k: v for k, v in value.items() if k != "handle"}}
                   for item in entries for kind, value in item.items() if kind != "metainfo"]
        if objects != self.objects:
            raise RuntimeError(f"Existing policy differs; refusing to modify or remove it. Objects={json.dumps(objects)} Expected={json.dumps(self.objects)}")
        return objects

    def apply(self, isolate: bool):
        commands: list[dict[str, Any]] = []
        try:
            return self._apply(isolate, commands)
        except Exception as exc:
            raise ContainmentError(type(exc).__name__, commands, str(exc)) from exc

    def _apply(self, isolate: bool, commands):
        with self.locked():
            current = self.snapshot()
            if isolate and current is None:
                commands.extend({"create" if "table" in obj else "add": obj} for obj in self.objects)
            elif not isolate and current is not None:
                commands.append({"delete": {"table": {"family": "inet", "name": self.table}}})
            if commands:
                # One netlink transaction. No fallback or destructive rollback on uncertainty.
                self.run(["-j", "-f", "-"], {"nftables": commands})
            observed = self.snapshot()
            if (observed is not None) != isolate:
                raise RuntimeError(f"Policy readback did not confirm requested state (observed is None: {observed is None}, isolate: {isolate})")
            outcome = "ENFORCED" if isolate else "RELEASED"
            proof = self._hash(observed) if isolate else self._hash([])
            return {
                "mode": "live", "outcome": outcome, "isolated": isolate,
                "evidence": {"backend": "nftables-v1", "verified": True, "state": outcome,
                             "table": self.table, "policy_sha256": proof, "observed_sha256": proof,
                             "commands": commands, "scope": "agent-reported-kernel-readback"},
            }
