"""Checkpointed file collection with durable spooling and at-least-once delivery."""

import hashlib
import json
import os
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from aegis.schemas import EventInput


class FileCollector:
    def __init__(self, spool: Path, name: str, capacity: int = 100000, max_event_bytes: int = 65536):
        if not spool.parent.is_dir() or spool.is_symlink():
            raise ValueError("Spool requires an existing parent and must not be a symlink")
        descriptor = os.open(spool, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        self.db = sqlite3.connect(spool, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS checkpoints (
              path TEXT PRIMARY KEY, identity TEXT NOT NULL, generation TEXT NOT NULL,
              offset INTEGER NOT NULL, prefix_hash TEXT NOT NULL, prefix_length INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS spool (
              id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL,
              state TEXT NOT NULL DEFAULT 'PENDING', error TEXT, attempts INTEGER NOT NULL DEFAULT 0,
              available_at REAL NOT NULL DEFAULT 0);
        """)
        self.name, self.capacity, self.max_event_bytes = name, capacity, max_event_bytes

    def close(self):
        self.db.close()

    def collect(self, path: Path, source_type: str = "generic", limit: int = 500) -> int:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Input must be a regular non-symlink file")
        path = path.resolve()
        count = 0
        with path.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            identity = f"{stat.st_dev}:{stat.st_ino}"
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                depth = self.db.execute("SELECT count(*) FROM spool").fetchone()[0]
                if depth >= self.capacity:
                    raise OverflowError("Collector spool full; source checkpoint retained")
                checkpoint = self.db.execute(
                    "SELECT identity,generation,offset,prefix_hash,prefix_length FROM checkpoints WHERE path=?",
                    (str(path),),
                ).fetchone()
                generation, offset = str(uuid4()), 0
                if checkpoint:
                    old_identity, old_generation, old_offset, old_hash, old_length = checkpoint
                    if (
                        old_identity == identity
                        and stat.st_size >= old_offset
                        and hashlib.sha256(stream.read(old_length)).hexdigest() == old_hash
                    ):
                        generation, offset = old_generation, old_offset
                stream.seek(offset)
                while count < min(limit, self.capacity - depth):
                    start = stream.tell()
                    line = stream.readline(self.max_event_bytes + 1)
                    if not line:
                        break
                    if len(line) > self.max_event_bytes:
                        raise ValueError("Oversized log line; checkpoint retained")
                    if not line.endswith(b"\n"):
                        break
                    text = line.rstrip(b"\r\n").decode("utf-8", errors="replace")
                    raw = text
                    if source_type in {
                        "json",
                        "windows",
                        "docker",
                        "aws",
                        "azure",
                        "gcp",
                        "journald",
                    } and text.lstrip().startswith("{"):
                        try:
                            raw = json.loads(text)
                        except ValueError:
                            raw = text
                    payload = EventInput(
                        source="file:" + hashlib.sha256(str(path).encode()).hexdigest(),
                        collector=self.name,
                        source_type=source_type,
                        source_sequence=f"{generation}:{start}",
                        timestamp=datetime.now(UTC),
                        raw_event=raw,
                    )
                    self.db.execute("INSERT INTO spool(payload) VALUES (?)", (payload.model_dump_json(),))
                    offset = stream.tell()
                    count += 1
                stream.seek(0)
                prefix_length = min(offset, 4096)
                prefix_hash = hashlib.sha256(stream.read(prefix_length)).hexdigest()
                self.db.execute(
                    "INSERT INTO checkpoints VALUES(?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET identity=excluded.identity,generation=excluded.generation,offset=excluded.offset,prefix_hash=excluded.prefix_hash,prefix_length=excluded.prefix_length",
                    (str(path), identity, generation, offset, prefix_hash, prefix_length),
                )
        return count

    def status(self):
        return dict(self.db.execute("SELECT state,count(*) FROM spool GROUP BY state").fetchall())

    def flush(self, client: httpx.Client, token: str, limit: int = 100) -> int:
        if not token:
            raise ValueError("Scoped ingestion credentials required")
        rows = self.db.execute(
            "SELECT id,payload,attempts FROM spool WHERE state='PENDING' AND available_at<=? ORDER BY id LIMIT ?",
            (time.time(), limit),
        ).fetchall()
        if not rows:
            return 0
        try:
            response = client.post(
                "events/ingest",
                json={"events": [json.loads(row[1]) for row in rows]},
                headers={"Authorization": "Bearer " + token},
            )
            response.raise_for_status()
            result = response.json()
            if len(result.get("accepted", [])) + len(result.get("duplicates", [])) != len(rows):
                raise ValueError("Incomplete API acknowledgment")
        except httpx.HTTPStatusError as exc:
            permanent = exc.response.status_code in {400, 413, 422}
            if permanent and len(rows) > 1:
                return sum(self.flush(client, token, limit=1) for _ in rows)
            self._failed(rows, f"HTTP_{exc.response.status_code}", permanent)
            return 0
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(rows, type(exc).__name__, False)
            return 0
        with self.db:
            self.db.executemany("DELETE FROM spool WHERE id=?", [(row[0],) for row in rows])
        return len(rows)

    def _failed(self, rows, error, permanent):
        with self.db:
            self.db.executemany(
                "UPDATE spool SET attempts=attempts+1,error=?,state=?,available_at=? WHERE id=?",
                [
                    (
                        error,
                        "QUARANTINED" if permanent else "PENDING",
                        time.time() + min(300, 2 ** min(row[2] + 1, 9)),
                        row[0],
                    )
                    for row in rows
                ],
            )

    def retry_quarantined(self):
        with self.db:
            return self.db.execute(
                "UPDATE spool SET state='PENDING',available_at=0 WHERE state='QUARANTINED'"
            ).rowcount
