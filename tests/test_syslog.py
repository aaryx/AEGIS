import socket
import time

from aegis.schemas import EventInput
from aegis.syslog import SyslogServer, parse_syslog_message


def test_parse_rfc5424_syslog():
    raw = "<165>1 2026-10-11T12:00:00.000Z srv-linux-01 sshd 1234 ID47 [exampleSDID@32473 iut=\"3\"] Failed password for invalid user admin from 192.0.2.1"
    event = parse_syslog_message(raw)
    assert isinstance(event, EventInput)
    assert event.source == "srv-linux-01"
    assert event.source_type == "syslog"
    assert event.collector == "syslog-adapter"
    assert isinstance(event.raw_event, dict)
    assert event.raw_event["host"] == "srv-linux-01"
    assert event.raw_event["process"]["name"] == "sshd"
    assert event.raw_event["facility"] == 20
    assert event.raw_event["severity"] == 5
    assert "Failed password" in event.raw_event["message"]


def test_parse_rfc3164_syslog():
    raw = "<34>Oct 11 22:14:15 firewall-corp sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000"
    event = parse_syslog_message(raw)
    assert isinstance(event, EventInput)
    assert event.source == "firewall-corp"
    assert event.source_type == "syslog"
    assert isinstance(event.raw_event, dict)
    assert event.raw_event["host"] == "firewall-corp"
    assert event.raw_event["process"]["name"] == "sudo"
    assert "authentication failure" in event.raw_event["message"]


def test_parse_raw_fallback_syslog():
    raw = "unformatted custom kernel event: disk full on /var/log"
    event = parse_syslog_message(raw, default_source="192.168.1.50")
    assert event.source == "192.168.1.50"
    assert isinstance(event.raw_event, dict)
    assert event.raw_event["message"] == raw


def test_syslog_tcp_server_octet_and_newline_framing():
    received = []

    def handler(batch):
        received.extend(batch)

    server = SyslogServer(handler=handler, host="127.0.0.1", port=15514, protocol="tcp", batch_size=1)
    server.start()
    try:
        # Connect TCP client
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(("127.0.0.1", 15514))

            # 1. Send newline-framed RFC 3164 message
            msg1 = "<34>Oct 11 22:14:15 host-nl app: newline message\n"
            client.sendall(msg1.encode("utf-8"))
            time.sleep(0.2)

            # 2. Send octet-counted RFC 5424 message: "<len> <msg>"
            raw_msg2 = "<165>1 2026-10-11T12:00:00Z host-oc app 1 - - octet message"
            frame2 = f"{len(raw_msg2)} {raw_msg2}"
            client.sendall(frame2.encode("utf-8"))
            time.sleep(0.2)

        deadline = time.time() + 3.0
        while len(received) < 2 and time.time() < deadline:
            time.sleep(0.1)

        assert len(received) == 2
        assert isinstance(received[0].raw_event, dict)
        assert isinstance(received[1].raw_event, dict)
        assert received[0].raw_event["host"] == "host-nl"
        assert received[1].raw_event["host"] == "host-oc"
    finally:
        server.stop()
