"""Run migrations and provision the first tenant plus least-privilege search credentials."""

import os

import httpx
import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import select
from sqlalchemy.engine import make_url

from aegis.config import get_settings
from aegis.db import Organization, User, database
from aegis.pipeline import seed_rules
from aegis.security import PASSWORDS, audit
from aegis.storage import OpenSearchStorage


def main():
    settings = get_settings()
    command.upgrade(Config("alembic.ini"), "head")
    if settings.database_url.startswith("postgresql"):
        url = make_url(settings.database_url)
        password = os.environ.get("POSTGRES_RUNTIME_PASSWORD")
        if password:
            with psycopg.connect(
                host=url.host,
                port=url.port or 5432,
                dbname=url.database,
                user=url.username,
                password=url.password,
            ) as connection:
                if not connection.execute(
                    "SELECT 1 FROM pg_roles WHERE rolname = %s", ("aegis_runtime",)
                ).fetchone():
                    connection.execute("CREATE ROLE aegis_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
                connection.execute(
                    sql.SQL("ALTER ROLE aegis_runtime PASSWORD {}").format(sql.Literal(password))
                )
                connection.execute("GRANT USAGE ON SCHEMA public TO aegis_runtime")
                connection.execute(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_runtime"
                )
                connection.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegis_runtime")
                connection.execute("REVOKE UPDATE, DELETE ON audit_logs FROM aegis_runtime")
                connection.execute("REVOKE DELETE ON events_metadata FROM aegis_runtime")
    _, sessions = database(settings.database_url)
    with sessions.begin() as db:
        if not db.scalar(select(User.id).limit(1)):
            password = os.environ.get("BOOTSTRAP_PASSWORD", "")
            if len(password) < 14:
                raise ValueError("BOOTSTRAP_PASSWORD must contain at least 14 characters")
            org = Organization(name="AEGIS")
            db.add(org)
            db.flush()
            user = User(
                organization_id=org.id,
                username=os.environ.get("BOOTSTRAP_USERNAME", "admin"),
                password_hash=PASSWORDS.hash(password),
                role="SUPER_ADMIN",
            )
            db.add(user)
            db.flush()
            seed_rules(db, org.id)
            audit(db, settings, org.id, user.id, "system.bootstrap", user.id)
    if settings.opensearch_url:
        admin_password = os.environ.get("OPENSEARCH_ADMIN_PASSWORD")
        if admin_password:
            with httpx.Client(
                base_url=settings.opensearch_url,
                auth=("admin", admin_password),
                timeout=20,
                verify=settings.opensearch_ca or True,
            ) as client:
                role = {
                    "cluster_permissions": [
                        "cluster_monitor",
                        "cluster_composite_ops",
                        "indices:admin/index_template/*",
                    ],
                    "index_permissions": [
                        {
                            "index_patterns": ["aegis-events*"],
                            "allowed_actions": ["crud", "create_index", "manage"],
                        }
                    ],
                }
                for path, body in [
                    ("roles/aegis_app", role),
                    (
                        "internalusers/aegis",
                        {
                            "password": settings.opensearch_password.get_secret_value(),
                            "backend_roles": ["aegis_app"],
                        },
                    ),
                    ("rolesmapping/aegis_app", {"backend_roles": ["aegis_app"], "users": ["aegis"]}),
                ]:
                    response = client.put("/_plugins/_security/api/" + path, json=body)
                    response.raise_for_status()
        OpenSearchStorage(settings).setup()
    print("Migrations, runtime privileges, bootstrap and search provisioning completed.")


if __name__ == "__main__":
    main()
