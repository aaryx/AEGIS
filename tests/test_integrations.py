import hashlib
import hmac
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import select

from aegis.db import Delivery, Notification
from aegis.integrations import dispatch_once, request_bytes


@contextmanager
def receiver():
    requests = []
    state = {"status": 200, "body": b"[]"}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(state["status"])
            self.end_headers()
            self.wfile.write(state["body"])

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            requests.append((dict(self.headers), body))
            self.do_GET()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_actual_http_delivery_signatures_retry_and_secret_redaction(system, monkeypatch):
    client = system["client"]
    settings = system["settings"]
    settings.integration_allowed_hosts = ["127.0.0.1"]
    secret = "test-signing-secret-long-enough"
    monkeypatch.setenv("AEGIS_INTEGRATION_TEST", secret)
    with receiver() as (url, requests, state):
        saved = client.put(
            "/api/v1/integrations/new",
            json={
                "name": "test-webhook",
                "kind": "webhook",
                "endpoint": url + "/private-token",
                "secret_env": "AEGIS_INTEGRATION_TEST",
            },
        )
        assert saved.status_code == 200, saved.text
        assert "private-token" not in saved.text and secret not in saved.text
        with system["app"].state.sessions.begin() as db:
            db.add(
                Notification(organization_id=system["org"], title="Critical signal", resource_id="alert-test")
            )
        state["status"] = 503
        assert dispatch_once(settings, system["app"].state.sessions) == 1
        with system["app"].state.sessions.begin() as db:
            row = db.scalar(select(Delivery))
            assert row.state == "RETRY" and row.delivered_at is None
            row.available_at = 0
        state["status"] = 200
        assert dispatch_once(settings, system["app"].state.sessions) == 1
        assert dispatch_once(settings, system["app"].state.sessions) == 0
        headers, body = requests[-1]
        expected = hmac.new(
            secret.encode(), headers["X-Aegis-Timestamp"].encode() + b"." + body, hashlib.sha256
        ).hexdigest()
        assert headers["X-Aegis-Signature"] == "sha256=" + expected
        assert requests[0][0]["Idempotency-Key"] == headers["Idempotency-Key"]
        assert client.get("/api/v1/deliveries").json()["items"][0]["state"] == "DELIVERED"
        assert client.get("/api/v1/audit/verify").json()["valid"]


def test_feed_validates_entire_document_before_persisting(system):
    client = system["client"]
    system["settings"].integration_allowed_hosts = ["127.0.0.1"]
    with receiver() as (url, _, state):
        row = client.put(
            "/api/v1/integrations/new", json={"name": "feed", "kind": "ioc_feed", "endpoint": url}
        ).json()
        state["body"] = json.dumps(
            [{"type": "ip", "value": "203.0.113.5"}, {"type": "ip", "value": "invalid"}]
        ).encode()
        assert client.post(f"/api/v1/integrations/{row['id']}/sync").status_code == 422
        assert client.get("/api/v1/iocs").json()["items"] == []
        state["body"] = json.dumps([{"type": "ip", "value": "203.0.113.5"}]).encode()
        assert client.post(f"/api/v1/integrations/{row['id']}/sync").json()["added"] == 1
        assert client.post(f"/api/v1/integrations/{row['id']}/sync").json()["added"] == 0


def test_integration_boundaries_redirects_size_and_tenant_scope(system):
    settings = system["settings"]
    with pytest.raises(ValueError, match="allowlist"):
        request_bytes(settings, "https://metadata.example/")
    settings.integration_allowed_hosts = ["127.0.0.1", "169.254.169.254"]
    with pytest.raises(ValueError, match="prohibited"):
        request_bytes(settings, "http://169.254.169.254/latest/meta-data/")
    with receiver() as (url, _, state):
        state["status"] = 302
        with pytest.raises(ValueError, match="302"):
            request_bytes(settings, url)
        state["status"] = 200
        state["body"] = b"x" * 2048
        settings.integration_max_bytes = 1024
        with pytest.raises(ValueError, match="too large"):
            request_bytes(settings, url)
        saved = (
            system["client"]
            .put(
                "/api/v1/integrations/new", json={"name": "other-scope", "kind": "ioc_feed", "endpoint": url}
            )
            .json()
        )
        system["client"].headers["Authorization"] = "Bearer " + system["tokens"]["OUTSIDER"]
        assert system["client"].post(f"/api/v1/integrations/{saved['id']}/sync").status_code == 404
