"""Acceptance must await complete evidence and still fail on permanent loss."""

import httpx
import pytest

from scripts.acceptance import wait_for_investigation


@pytest.mark.parametrize("missing", ["events", "iocs", "entities"])
def test_acceptance_waits_for_complete_investigation(monkeypatch, missing):
    polls = []
    monkeypatch.setattr("scripts.acceptance.time.sleep", polls.append)

    def respond(request):
        if request.url.path == "/incidents":
            return httpx.Response(200, json={"items": [{"id": "INC-test"}]})
        data = {"evidence": [{"event": {"host": "test-host"}}] * 16, "iocs": [{}], "entities": [{}]}
        if not polls:
            if missing == "events":
                data["evidence"] = data["evidence"][:1]
            else:
                data[missing] = []
        return httpx.Response(200, json=data)

    with httpx.Client(base_url="http://test", transport=httpx.MockTransport(respond)) as client:
        _, evidence = wait_for_investigation(client, "test-host", attempts=2)
    assert len(polls) == 1
    assert len(evidence["evidence"]) == 16 and evidence["iocs"] and evidence["entities"]


def test_acceptance_permanent_incomplete_evidence_fails(monkeypatch):
    monkeypatch.setattr("scripts.acceptance.time.sleep", lambda _: None)

    def respond(request):
        data = (
            {"items": [{"id": "INC-test"}]}
            if request.url.path == "/incidents"
            else {
                "evidence": [{"event": {"host": "test-host"}}],
                "iocs": [],
                "entities": [],
            }
        )
        return httpx.Response(200, json=data)

    with httpx.Client(base_url="http://test", transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(RuntimeError, match="incomplete"):
            wait_for_investigation(client, "test-host", attempts=2)
