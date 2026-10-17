"""Normalized observables. No raw event text or credentials leave this module."""

import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, model_validator

from aegis.schemas import StrictModel, get_field


class ObservableInput(StrictModel):
    type: Literal["ip", "domain", "url", "hash", "md5", "sha1", "sha256"]
    value: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def normalize_value(self):
        kind, value, _ = normalize(self.type, self.value)
        self.type, self.value = kind, value
        return self


def domain(value):
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if (
        len(value) > 253
        or "." not in value
        or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split("."))
        or value.rsplit(".", 1)[1].isdigit()
    ):
        raise ValueError("Invalid domain")
    return value


def normalize(kind, raw):
    value = raw.strip()
    if not value or any(ord(c) < 33 for c in value) or len(value) > 2048:
        raise ValueError("Invalid observable")
    if kind == "ip":
        if "%" in value:
            raise ValueError("Scoped addresses are not supported")
        address = ipaddress.ip_address(value)
        return "ip", str(address), address.is_global and not address.is_multicast
    if kind in {"hash", "md5", "sha1", "sha256"}:
        if not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
            raise ValueError("Expected MD5, SHA-1 or SHA-256")
        actual = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
        if kind != "hash" and kind != actual:
            raise ValueError("Hash length does not match algorithm")
        return actual, value.lower(), True
    if kind == "domain":
        value = domain(value)
        allowed = not any(
            value == s or value.endswith("." + s)
            for s in (
                "localhost",
                "local",
                "internal",
                "lan",
                "home",
                "corp",
                "test",
                "invalid",
                "example",
                "example.com",
                "example.net",
                "example.org",
            )
        )
        return kind, value, allowed
    if kind == "url":
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "\\" in value
        ):
            raise ValueError("Expected HTTP(S) URL without credentials")
        try:
            host = str(ipaddress.ip_address(parsed.hostname))
            if ":" in host:
                host = "[" + host + "]"
        except ValueError:
            host = "localhost" if parsed.hostname.lower() == "localhost" else domain(parsed.hostname)
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid URL port")
        if port and (parsed.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
            host += ":" + str(port)
        # Query and fragment may contain credentials. Paths stay local, never sent to providers.
        return kind, urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", "")), False
    raise ValueError("Unsupported observable type")


FIELDS = {
    "ip": ["source_ip", "destination_ip", "network.source_ip", "network.destination_ip"],
    "domain": ["http.domain", "dns.question", "dns.query", "network.domain"],
    "url": ["http.url", "url"],
    "hash": [
        "file.hash",
        "file.md5",
        "file.sha1",
        "file.sha256",
        "file.hashes.md5",
        "file.hashes.sha1",
        "file.hashes.sha256",
    ],
}


def extract(payload, limit=32):
    """Bounded structured extraction; never regex-scrape arbitrary raw messages."""
    found = {}
    for kind, fields in FIELDS.items():
        for field in fields:
            value = get_field(payload, field)
            if not isinstance(value, str):
                continue
            try:
                k, v, allowed = normalize(kind, value)
            except (ValueError, UnicodeError):
                continue
            found[(k, v)] = allowed
            if k == "url":
                host = urlsplit(v).hostname
                try:
                    hk, hv, ha = normalize("ip", host)
                except ValueError:
                    try:
                        hk, hv, ha = normalize("domain", host)
                    except (ValueError, UnicodeError):
                        continue
                found[(hk, hv)] = ha
    return [(kind, value, allowed) for (kind, value), allowed in list(found.items())[:limit]]
