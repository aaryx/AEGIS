import json

import httpx
import pytest

from aegis.collector import FileCollector


def test_checkpoint_spool_restart_partial_line_and_rotation(tmp_path):
    log = tmp_path / "auth.log"
    spool = tmp_path / "spool.db"
    log.write_bytes(b"first\npartial")
    collector = FileCollector(spool, "test")
    assert collector.collect(log) == 1
    first = collector.db.execute("SELECT payload FROM spool").fetchone()[0]
    collector.close()
    collector = FileCollector(spool, "test")
    assert collector.collect(log) == 0
    with log.open("ab") as stream:
        stream.write(b" completed\n")
    assert collector.collect(log) == 1
    log.write_bytes(b"rotated\n")
    assert collector.collect(log) == 1
    payloads = [json.loads(row[0]) for row in collector.db.execute("SELECT payload FROM spool")]
    assert len({value["source_sequence"] for value in payloads}) == 3
    assert json.loads(first)["raw_event"] == "first"
    assert payloads[1]["raw_event"] == "partial completed"
    collector.close()


def test_retry_identical_payload_and_quarantine_without_losing_siblings(tmp_path):
    log = tmp_path / "events.log"
    log.write_text("good\nbad\nother\n")
    collector = FileCollector(tmp_path / "spool.db", "test")
    collector.collect(log)
    requests = []
    offline = True

    def handler(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if offline:
            return httpx.Response(503)
        if any(event["raw_event"] == "bad" for event in payload["events"]):
            return httpx.Response(422)
        return httpx.Response(
            202, json={"accepted": [str(i) for i in range(len(payload["events"]))], "duplicates": []}
        )

    with httpx.Client(base_url="http://localhost/api/v1/", transport=httpx.MockTransport(handler)) as client:
        assert collector.flush(client, "test-key") == 0
        assert collector.status() == {"PENDING": 3}
        collector.db.execute("UPDATE spool SET available_at=0")
        collector.db.commit()
        offline = False
        assert collector.flush(client, "test-key") == 2
        assert requests[0] == requests[1]
        assert collector.status() == {"QUARANTINED": 1}
        row = json.loads(collector.db.execute("SELECT payload FROM spool").fetchone()[0])
        assert row["raw_event"] == "bad"
    collector.close()


def test_backpressure_never_advances_source_checkpoint(tmp_path):
    log = tmp_path / "events.log"
    log.write_text("one\ntwo\n")
    collector = FileCollector(tmp_path / "spool.db", "test", capacity=1)
    assert collector.collect(log) == 1
    offset = collector.db.execute("SELECT offset FROM checkpoints").fetchone()[0]
    with pytest.raises(OverflowError):
        collector.collect(log)
    assert collector.db.execute("SELECT offset FROM checkpoints").fetchone()[0] == offset
    collector.close()
