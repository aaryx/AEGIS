"""Focused unit tests for LinuxAuthParser compatibility with modern and historical OpenSSH logs."""

from datetime import UTC, datetime

from aegis.parsers import LinuxAuthParser
from aegis.schemas import EventInput


def test_linux_auth_parser_historical_sshd():
    parser = LinuxAuthParser()
    raw = "Oct 24 14:02:10 sec-gateway sshd[12450]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2"
    event_in = EventInput(
        source="file:test",
        collector="test",
        source_type="linux_auth",
        timestamp=datetime.now(UTC),
        raw_event=raw,
    )
    assert parser.can_parse(event_in) is True
    parsed = parser.parse(event_in)
    assert parsed["event_category"] == "authentication"
    assert parsed["action"] == "login"
    assert parsed["outcome"] == "failure"
    assert parsed["username"] == "admin"
    assert parsed["source_ip"] == "198.51.100.42"
    assert parsed["source_port"] == 54321
    assert parsed["host"] == "sec-gateway"


def test_linux_auth_parser_modern_openssh_session_syslog():
    """Verify OpenSSH 9.8+ sshd-session format with syslog facility.priority tags."""
    parser = LinuxAuthParser()
    raw = "Nov  5 17:13:25 d16fca7d8e48 auth.info sshd-session[24]: Failed password for invalid user admin from 127.0.0.1 port 34764 ssh2"
    event_in = EventInput(
        source="file:test",
        collector="test",
        source_type="linux_auth",
        timestamp=datetime.now(UTC),
        raw_event=raw,
    )
    assert parser.can_parse(event_in) is True
    parsed = parser.parse(event_in)
    assert parsed["event_category"] == "authentication"
    assert parsed["action"] == "login"
    assert parsed["outcome"] == "failure"
    assert parsed["username"] == "admin"
    assert parsed["source_ip"] == "127.0.0.1"
    assert parsed["source_port"] == 34764
    assert parsed["host"] == "d16fca7d8e48"


def test_linux_auth_parser_modern_openssh_session_accepted():
    parser = LinuxAuthParser()
    raw = "Nov  5 17:13:29 d16fca7d8e48 auth.info sshd-session[132]: Accepted password for testanalyst from 127.0.0.1 port 34864 ssh2"
    event_in = EventInput(
        source="file:test",
        collector="test",
        source_type="linux_auth",
        timestamp=datetime.now(UTC),
        raw_event=raw,
    )
    assert parser.can_parse(event_in) is True
    parsed = parser.parse(event_in)
    assert parsed["event_category"] == "authentication"
    assert parsed["action"] == "login"
    assert parsed["outcome"] == "success"
    assert parsed["username"] == "testanalyst"
    assert parsed["source_ip"] == "127.0.0.1"
    assert parsed["source_port"] == 34864
    assert parsed["host"] == "d16fca7d8e48"


def test_linux_auth_parser_sudo_and_useradd():
    parser = LinuxAuthParser()
    sudo_line = "Oct 24 14:02:20 sec-gateway sudo:   analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    useradd_line = "Oct 24 14:02:25 sec-gateway useradd[12460]: new user: name=john, UID=1001, GID=1001, home=/home/john, shell=/bin/bash"

    for line in (sudo_line, useradd_line):
        ev = EventInput(
            source="file:test",
            collector="test",
            source_type="linux_auth",
            timestamp=datetime.now(UTC),
            raw_event=line,
        )
        assert parser.can_parse(ev) is True
        parsed = parser.parse(ev)
        assert parsed["host"] == "sec-gateway"
