"""AEGIS Native Protocol Ingestion — RFC 5424 / RFC 3164 Syslog Engine.

Supports high-throughput UDP, TCP (octet-counting and newline framing RFC 6587),
and TLS syslog streams feeding into canonical event normalization.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import threading
from datetime import UTC, datetime
from typing import Any, Callable

from aegis.schemas import EventInput

logger = logging.getLogger("aegis.syslog")

# RFC 5424 Syslog: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<timestamp>[^\s]+)\s+"
    r"(?P<hostname>[^\s]+)\s+"
    r"(?P<appname>[^\s]+)\s+"
    r"(?P<procid>[^\s]+)\s+"
    r"(?P<msgid>[^\s]+)\s+"
    r"(?:(?P<sd>\[.*?\])|-)\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# RFC 3164 Syslog: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG: MSG
RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[^\s:]+)\s+"
    r"(?:(?P<tag>[^:\s]+):\s*)?"
    r"(?P<msg>.*)$",
    re.DOTALL,
)


def parse_syslog_message(raw: str, default_source: str = "syslog") -> EventInput:
    """Parses RFC 5424, RFC 3164, or raw message into a canonical EventInput."""
    text = raw.strip()
    pri = 13  # notice / user level default
    hostname = default_source
    timestamp = datetime.now(UTC)
    message = text
    structured: dict[str, Any] = {}

    m5424 = RFC5424_PATTERN.match(text)
    if m5424:
        groups = m5424.groupdict()
        pri = int(groups["pri"])
        if groups["hostname"] != "-":
            hostname = groups["hostname"]
        if groups["timestamp"] != "-":
            try:
                timestamp = datetime.fromisoformat(groups["timestamp"])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
            except ValueError:
                pass
        structured = {
            "app_name": groups["appname"] if groups["appname"] != "-" else None,
            "proc_id": groups["procid"] if groups["procid"] != "-" else None,
            "msg_id": groups["msgid"] if groups["msgid"] != "-" else None,
            "facility": pri // 8,
            "severity": pri % 8,
            "rfc": "5424",
        }
        message = groups["msg"]
    else:
        m3164 = RFC3164_PATTERN.match(text)
        if m3164:
            groups = m3164.groupdict()
            pri = int(groups["pri"])
            hostname = groups["hostname"]
            tag = groups.get("tag")
            structured = {
                "tag": tag,
                "facility": pri // 8,
                "severity": pri % 8,
                "rfc": "3164",
            }
            message = groups["msg"]
            # Parse BSD timestamp with current year
            try:
                current_year = datetime.now(UTC).year
                ts_str = f"{current_year} {groups['timestamp']}"
                parsed_dt = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                timestamp = parsed_dt.replace(tzinfo=UTC)
            except ValueError:
                pass

    event_payload = {
        "message": message,
        "host": hostname,
        "facility": structured.get("facility", pri // 8),
        "severity": structured.get("severity", pri % 8),
        "source": hostname,
    }
    if structured.get("app_name"):
        event_payload["process"] = {"name": structured["app_name"]}
    elif structured.get("tag"):
        event_payload["process"] = {"name": structured["tag"]}

    return EventInput(
        source=hostname,
        source_type="syslog",
        collector="syslog-adapter",
        timestamp=timestamp,
        raw_event=event_payload,
    )


class SyslogServer:
    """Multi-transport Syslog Server supporting UDP and TCP framing."""

    def __init__(
        self,
        handler: Callable[[list[EventInput]], None],
        host: str = "127.0.0.1",
        port: int = 5514,
        protocol: str = "udp",
        ssl_context: ssl.SSLContext | None = None,
        batch_size: int = 100,
        max_bytes: int = 65536,
    ) -> None:
        self.handler = handler
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.ssl_context = ssl_context
        self.batch_size = batch_size
        self.max_bytes = max_bytes
        self.running = False
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None

    def start(self) -> None:
        self.running = True
        if self.protocol == "udp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((self.host, self.port))
            self._thread = threading.Thread(target=self._run_udp, daemon=True)
        elif self.protocol == "tcp":
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_sock.bind((self.host, self.port))
            raw_sock.listen(50)
            if self.ssl_context:
                self._socket = self.ssl_context.wrap_socket(raw_sock, server_side=True)
            else:
                self._socket = raw_sock
            self._thread = threading.Thread(target=self._run_tcp, daemon=True)
        else:
            raise ValueError(f"Unsupported syslog protocol: {self.protocol}")

        self._thread.start()
        logger.info("Syslog %s listener started on %s:%d", self.protocol.upper(), self.host, self.port)

    def stop(self) -> None:
        self.running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception as exc:
                logger.debug("Socket close error: %s", exc)
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Syslog listener stopped")

    def _run_udp(self) -> None:
        assert self._socket is not None
        self._socket.settimeout(1.0)
        batch: list[EventInput] = []
        while self.running:
            try:
                data, addr = self._socket.recvfrom(self.max_bytes)
                text = data.decode("utf-8", errors="replace")
                event = parse_syslog_message(text, default_source=addr[0])
                batch.append(event)
                if len(batch) >= self.batch_size:
                    self.handler(batch)
                    batch = []
            except TimeoutError:
                if batch:
                    self.handler(batch)
                    batch = []
            except Exception as exc:
                if self.running:
                    logger.warning("UDP receive error: %s", exc)
        if batch:
            try:
                self.handler(batch)
            except Exception as exc:
                logger.debug("Final batch flush error: %s", exc)

    def _run_tcp(self) -> None:
        assert self._socket is not None
        self._socket.settimeout(1.0)
        while self.running:
            try:
                client_sock, addr = self._socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_sock, addr[0]),
                    daemon=True,
                )
                client_thread.start()
            except TimeoutError:
                continue
            except Exception as exc:
                if self.running:
                    logger.warning("TCP accept error: %s", exc)

    def _handle_tcp_client(self, client_sock: socket.socket, client_ip: str) -> None:
        client_sock.settimeout(10.0)
        buffer = bytearray()
        batch: list[EventInput] = []
        try:
            while self.running:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)

                # Process framing: Octet-counting RFC 6587 vs Newline framing
                while buffer:
                    # Check for octet counting: <digits><space><msg>
                    space_idx = buffer.find(b" ")
                    if space_idx > 0 and buffer[:space_idx].isdigit():
                        msg_len = int(buffer[:space_idx].decode("ascii"))
                        total_frame = space_idx + 1 + msg_len
                        if len(buffer) >= total_frame:
                            msg_bytes = buffer[space_idx + 1 : total_frame]
                            del buffer[:total_frame]
                            text = msg_bytes.decode("utf-8", errors="replace")
                            batch.append(parse_syslog_message(text, default_source=client_ip))
                            continue
                        else:
                            break  # Await more bytes for octet-counted frame

                    # Check for newline framing
                    nl_idx = buffer.find(b"\n")
                    if nl_idx >= 0:
                        line = buffer[:nl_idx].decode("utf-8", errors="replace").strip("\r")
                        del buffer[: nl_idx + 1]
                        if line:
                            batch.append(parse_syslog_message(line, default_source=client_ip))
                        continue

                    # If buffer too large without newline or octet count, flush raw
                    if len(buffer) > self.max_bytes:
                        raw_line = buffer.decode("utf-8", errors="replace")
                        buffer.clear()
                        batch.append(parse_syslog_message(raw_line, default_source=client_ip))
                    break

                if len(batch) >= self.batch_size:
                    self.handler(batch)
                    batch = []

            if batch:
                self.handler(batch)
        except Exception as exc:
            logger.debug("TCP client %s disconnected: %s", client_ip, exc)
        finally:
            client_sock.close()
