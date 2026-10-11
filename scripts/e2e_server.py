"""Run a real local API containing synthetic acceptance data. Uses an isolated temporary database."""

import os
import tempfile
from pathlib import Path

import uvicorn

from aegis.api import create_app
from aegis.config import Settings
from aegis.db import IOC, Base, Organization, User
from aegis.pipeline import ingest, seed_rules
from aegis.security import PASSWORDS
from aegis.simulation import simulate
from aegis.worker import process_once


def main():
    password = os.environ.get("AEGIS_E2E_PASSWORD")
    if not password or len(password) < 14:
        raise SystemExit("Set AEGIS_E2E_PASSWORD to at least 14 characters")
    with tempfile.TemporaryDirectory(prefix="aegis-e2e-") as directory:
        settings = Settings(
            environment="testing",
            database_url=f"sqlite:///{Path(directory) / 'e2e.db'}",
            public_origin="http://127.0.0.1:3000",
            audit_secret=os.environ.get("AUDIT_SECRET", "local-e2e-integrity-key-not-production"),
            _env_file=None,
        )
        app = create_app(settings)
        Base.metadata.create_all(app.state.engine)
        with app.state.sessions.begin() as db:
            org = Organization(name="Synthetic acceptance environment")
            db.add(org)
            db.flush()
            db.add(
                User(
                    organization_id=org.id,
                    username=os.environ.get("AEGIS_E2E_USERNAME", "e2e-analyst"),
                    password_hash=PASSWORDS.hash(password),
                    role="SUPER_ADMIN",
                )
            )
            seed_rules(db, org.id)
            db.add(
                IOC(
                    organization_id=org.id,
                    type="ip",
                    value="203.0.113.10",
                    source="synthetic",
                    confidence=100,
                    severity="high",
                    description="Documentation address",
                )
            )
            ingest(db, settings, org.id, simulate("attack-chain"), "e2e-fixture")
        if process_once(settings, app.state.sessions, app.state.storage) != 16:
            raise RuntimeError("Synthetic acceptance data did not process successfully")
        uvicorn.run(app, host="127.0.0.1", port=8000, access_log=False)


if __name__ == "__main__":
    main()
