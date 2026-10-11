"""Non-destructive PostgreSQL backup/restore drill using a uniquely named isolated database."""

import hashlib
import json
import os
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run([shutil.which("docker"), "compose", *args], cwd=ROOT, check=True, **kwargs)  # noqa: S603  # nosec B603


def main():
    destination = ROOT / "local-data"
    destination.mkdir(exist_ok=True)
    stamp = uuid4().hex
    database_name = "aegis_restore_" + stamp
    archive = destination / f"backup-{stamp}.dump"
    started = time.monotonic()
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        run(["exec", "-T", "postgres", "pg_dump", "-U", "aegis", "-d", "aegis", "-Fc"], stdout=output)
    backup_seconds = time.monotonic() - started
    run(["exec", "-T", "postgres", "createdb", "-U", "aegis", database_name])
    try:
        with archive.open("rb") as data:
            run(
                [
                    "exec",
                    "-T",
                    "postgres",
                    "pg_restore",
                    "-U",
                    "aegis",
                    "-d",
                    database_name,
                    "--no-owner",
                    "--exit-on-error",
                ],
                stdin=data,
            )
        verification = """
import json, os
from sqlalchemy import create_engine, select, func
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from aegis.config import get_settings
from aegis.db import EventRecord, Organization
from aegis.parsers import digest
from aegis.security import verify_audit
settings=get_settings()
engine=create_engine(make_url(settings.database_url).set(database=os.environ['RESTORE_DATABASE']))
with Session(engine) as db:
    count=0
    for event in db.scalars(select(EventRecord).execution_options(yield_per=500)):
        if digest(event.payload['raw_event']) != event.evidence_hash: raise RuntimeError('Evidence hash mismatch')
        count+=1
    for org in db.scalars(select(Organization)):
        if not verify_audit(db, settings, org.id): raise RuntimeError('Audit chain mismatch')
    print(json.dumps({'verified_events':count,'audit_chains':'valid'}))
"""
        result = run(
            ["run", "--rm", "--no-deps", "-e", "RESTORE_DATABASE=" + database_name, "initialize", "python", "-c", verification],
            capture_output=True,
            text=True,
        )
        verification_result = json.loads(result.stdout)
        with archive.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        report = verification_result | {
            "backup_seconds": backup_seconds,
            "total_seconds": time.monotonic() - started,
            "archive_bytes": archive.stat().st_size,
            "archive_sha256": checksum,
            "archive": archive.name,
            "scope": "isolated PostgreSQL restore and all evidence/audit verification; excludes OpenSearch snapshot",
        }
        (destination / "recovery-drill.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
    finally:
        run(["exec", "-T", "postgres", "dropdb", "-U", "aegis", database_name])


if __name__ == "__main__":
    main()
