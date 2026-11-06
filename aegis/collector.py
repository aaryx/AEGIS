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

from aegis.parsers import compute_event_id
from aegis.schemas import EventInput


class FileCollector:
    def __init__(
        self,
        spool: Path,
        name: str,
        capacity: int = 100000,
        max_event_bytes: int = 65536,
        tenant_id: str | None = None,
    ):
        if not spool.parent.is_dir() or spool.is_symlink():
            raise ValueError("Spool requires an existing parent and must not be a symlink")
        descriptor = os.open(spool, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        self.db = sqlite3.connect(spool, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoints (
              identity TEXT PRIMARY KEY, path TEXT NOT NULL, generation TEXT NOT NULL,
              offset INTEGER NOT NULL, prefix_hash TEXT NOT NULL, prefix_length INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS spool (
              id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL,
              state TEXT NOT NULL DEFAULT 'PENDING', error TEXT, attempts INTEGER NOT NULL DEFAULT 0,
              available_at REAL NOT NULL DEFAULT 0);
        """)
        # Schema migration check: If checkpoints table was created under old schema with path as PK:
        table_info = self.db.execute("PRAGMA table_info(checkpoints)").fetchall()
        if table_info:
            pk_cols = [col[1] for col in table_info if col[5] == 1]
            if pk_cols == ["path"]:
                self.db.executescript("""
                    CREATE TABLE checkpoints_v2 (
                      identity TEXT PRIMARY KEY, path TEXT NOT NULL, generation TEXT NOT NULL,
                      offset INTEGER NOT NULL, prefix_hash TEXT NOT NULL, prefix_length INTEGER NOT NULL);
                    INSERT OR REPLACE INTO checkpoints_v2
                      SELECT identity, path, generation, offset, prefix_hash, prefix_length FROM checkpoints;
                    DROP TABLE checkpoints;
                    ALTER TABLE checkpoints_v2 RENAME TO checkpoints;
                """)

        # Identity binding checks
        existing_name = self.db.execute("SELECT value FROM meta WHERE key='collector_name'").fetchone()
        if existing_name:
            if existing_name[0] != name:
                raise ValueError(
                    f"Spool is bound to collector identity '{existing_name[0]}', cannot rebind to '{name}'"
                )
        else:
            with self.db:
                self.db.execute("INSERT INTO meta(key, value) VALUES('collector_name', ?)", (name,))

        if tenant_id:
            existing_tenant = self.db.execute("SELECT value FROM meta WHERE key='tenant_id'").fetchone()
            if existing_tenant:
                if existing_tenant[0] != tenant_id:
                    raise ValueError(
                        f"Spool is bound to tenant '{existing_tenant[0]}', cannot rebind to '{tenant_id}'"
                    )
            else:
                with self.db:
                    self.db.execute("INSERT INTO meta(key, value) VALUES('tenant_id', ?)", (tenant_id,))

        self.name, self.capacity, self.max_event_bytes = name, capacity, max_event_bytes

    @property
    def bound_tenant_id(self) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key='tenant_id'").fetchone()
        return row[0] if row else None

    def bind_tenant(self, tenant_id: str):
        existing_tenant = self.db.execute("SELECT value FROM meta WHERE key='tenant_id'").fetchone()
        if existing_tenant:
            if existing_tenant[0] != tenant_id:
                raise ValueError(
                    f"Spool is bound to tenant '{existing_tenant[0]}', cannot rebind to '{tenant_id}'"
                )
        else:
            with self.db:
                self.db.execute("INSERT INTO meta(key, value) VALUES('tenant_id', ?)", (tenant_id,))

    @property
    def depth(self) -> int:
        return self.db.execute("SELECT count(*) FROM spool").fetchone()[0]

    @property
    def is_full(self) -> bool:
        return self.depth >= self.capacity

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
                    "SELECT identity,generation,offset,prefix_hash,prefix_length FROM checkpoints WHERE identity=?",
                    (identity,),
                ).fetchone()
                if not checkpoint:
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
                        # Drain remainder of the oversized line until newline or EOF
                        oversized_chunks = [line]
                        total_bytes = len(line)
                        while not oversized_chunks[-1].endswith(b"\n"):
                            chunk = stream.readline(65536)
                            if not chunk:
                                break
                            total_bytes += len(chunk)
                            if len(oversized_chunks) < 4:
                                oversized_chunks.append(chunk)

                        payload = EventInput(
                            source="file:" + hashlib.sha256(str(path).encode()).hexdigest(),
                            collector=self.name,
                            source_type=source_type,
                            source_sequence=f"{generation}:{start}",
                            timestamp=datetime.now(UTC),
                            raw_event={
                                "error": "OVERSIZED_INPUT",
                                "bytes": total_bytes,
                                "max_allowed": self.max_event_bytes,
                                "snippet": b"".join(oversized_chunks)[:512].decode("utf-8", errors="replace"),
                            },
                        )
                        self.db.execute(
                            "INSERT INTO spool(payload, state, error, attempts) VALUES (?, 'QUARANTINED', 'OVERSIZED_INPUT', 1)",
                            (payload.model_dump_json(),),
                        )
                        offset = stream.tell()
                        count += 1
                        continue
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
                    """
                    INSERT INTO checkpoints VALUES(?,?,?,?,?,?)
                    ON CONFLICT(identity) DO UPDATE SET
                      path=excluded.path,
                      generation=excluded.generation,
                      offset=excluded.offset,
                      prefix_hash=excluded.prefix_hash,
                      prefix_length=excluded.prefix_length
                    """,
                    (identity, str(path), generation, offset, prefix_hash, prefix_length),
                )
        return count

    def status(self):
        return dict(self.db.execute("SELECT state,count(*) FROM spool GROUP BY state").fetchall())

    def flush(self, client: httpx.Client, token: str, limit: int = 100, tenant_id: str | None = None) -> int:
        if not token:
            raise ValueError("Scoped ingestion credentials required")
        if tenant_id:
            self.bind_tenant(tenant_id)
        bound_tenant = self.bound_tenant_id

        rows = self.db.execute(
            "SELECT id,payload,attempts FROM spool WHERE state='PENDING' AND available_at<=? ORDER BY id LIMIT ?",
            (time.time(), limit),
        ).fetchall()
        if not rows:
            return 0

        events_payload = []
        expected_id_to_row_id: dict[str, int] = {}
        for row in rows:
            ev_dict = json.loads(row[1])
            events_payload.append(ev_dict)
            if bound_tenant:
                ev_input = EventInput.model_validate(ev_dict)
                det_id = compute_event_id(bound_tenant, ev_input)
                expected_id_to_row_id[det_id] = row[0]
            else:
                expected_id_to_row_id[str(row[0])] = row[0]
                if ev_dict.get("source_sequence"):
                    expected_id_to_row_id[ev_dict["source_sequence"]] = row[0]

        headers = {"Authorization": "Bearer " + token}
        req_body: dict[str, object] = {"events": events_payload}
        if bound_tenant:
            headers["X-AEGIS-Tenant-ID"] = bound_tenant
            headers["X-AEGIS-Collector-Name"] = self.name
            req_body["tenant_id"] = bound_tenant

        spool_ids_to_delete: list[int] = []
        try:
            response = client.post("events/ingest", json=req_body, headers=headers)
            response.raise_for_status()

            try:
                result = response.json()
            except Exception as exc:
                raise ValueError(f"Malformed response body: not valid JSON: {exc}") from exc

            if not isinstance(result, dict):
                raise ValueError("Malformed response body: expected JSON object")

            # 1. Tenant verification (defense-in-depth)
            resp_org = result.get("organization_id")
            if resp_org:
                if bound_tenant and bound_tenant != resp_org:
                    raise ValueError(
                        f"Destination tenant mismatch: Spool is bound to tenant '{bound_tenant}', rejected delivery under '{resp_org}'"
                    )
                elif not bound_tenant:
                    raise ValueError(
                        f"Legacy unbound spool cannot silently acquire tenant identity '{resp_org}'; explicit tenant binding required"
                    )

            # 2. Structure & list type verification
            if "accepted" not in result or "duplicates" not in result:
                raise ValueError("Malformed response body: missing 'accepted' or 'duplicates' keys")
            accepted = result["accepted"]
            duplicates = result["duplicates"]
            if not isinstance(accepted, list) or not isinstance(duplicates, list):
                raise ValueError("Malformed response body: 'accepted' and 'duplicates' must be lists")
            if not all(isinstance(x, str) for x in accepted) or not all(
                isinstance(x, str) for x in duplicates
            ):
                raise ValueError("Malformed response body: acknowledgment IDs must be strings")

            # 3. Multiplicity & disjoint checks
            if len(accepted) != len(set(accepted)):
                raise ValueError("Repeated acknowledgment ID in accepted list")
            if len(duplicates) != len(set(duplicates)):
                raise ValueError("Repeated acknowledgment ID in duplicates list")
            overlap = set(accepted) & set(duplicates)
            if overlap:
                raise ValueError(f"Acknowledgment ID appears in both accepted and duplicates: {overlap}")

            # 4. Identity reconciliation against expected batch
            acked_ids = set(accepted) | set(duplicates)

            if bound_tenant:
                unexpected = acked_ids - set(expected_id_to_row_id.keys())
                if unexpected:
                    raise ValueError(f"Unexpected or unrelated acknowledgment IDs in response: {unexpected}")
                for eid in acked_ids:
                    if eid in expected_id_to_row_id:
                        spool_ids_to_delete.append(expected_id_to_row_id[eid])
            else:
                index_map = {str(i): row[0] for i, row in enumerate(rows)}
                for aid in acked_ids:
                    if aid in expected_id_to_row_id:
                        spool_ids_to_delete.append(expected_id_to_row_id[aid])
                    elif aid in index_map:
                        spool_ids_to_delete.append(index_map[aid])
                    else:
                        raise ValueError(f"Unexpected acknowledgment ID in response: {aid}")

        except httpx.HTTPStatusError as exc:
            permanent = exc.response.status_code in {400, 413, 422}
            if permanent and len(rows) > 1:
                return sum(self.flush(client, token, limit=1) for _ in rows)
            self._failed(rows, f"HTTP_{exc.response.status_code}", permanent)
            return 0
        except (httpx.HTTPError, ValueError) as exc:
            err_msg = str(exc).lower()
            if (
                "destination tenant mismatch" in err_msg
                or "spool is bound to tenant" in err_msg
                or "legacy unbound spool" in err_msg
                or "malformed response body" in err_msg
                or "repeated acknowledgment id" in err_msg
                or "appears in both accepted and duplicates" in err_msg
                or "unexpected" in err_msg
            ):
                self._failed(rows, type(exc).__name__, False)
                raise
            self._failed(rows, type(exc).__name__, False)
            return 0

        # 5. Atomic deletion of ONLY explicitly confirmed records
        if spool_ids_to_delete:
            with self.db:
                self.db.executemany("DELETE FROM spool WHERE id=?", [(sid,) for sid in spool_ids_to_delete])

        # 6. If acknowledgment was incomplete, retain unacknowledged rows as PENDING
        if len(spool_ids_to_delete) < len(rows):
            unacked_rows = [row for row in rows if row[0] not in set(spool_ids_to_delete)]
            self._failed(unacked_rows, "IncompleteAcknowledgment", False)

        return len(spool_ids_to_delete)

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
