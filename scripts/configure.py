"""Generate local deployment secrets without printing them or overwriting an existing file."""

import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
target = root / ".env"
if target.exists():
    raise SystemExit(".env already exists; it was not modified")
values = {
    "ENVIRONMENT": "development",
    "PUBLIC_ORIGIN": "http://localhost:3000",
    "COOKIE_SECURE": "false",
    "AUDIT_SECRET": secrets.token_hex(32),
    "POSTGRES_PASSWORD": secrets.token_hex(24),
    "REDIS_PASSWORD": secrets.token_hex(24),
    "POSTGRES_RUNTIME_PASSWORD": secrets.token_hex(24),
    "POSTGRES_MAINTENANCE_PASSWORD": secrets.token_hex(24),
    "OPENSEARCH_ADMIN_PASSWORD": "Aa1!" + secrets.token_hex(24),
    "OPENSEARCH_PASSWORD": "Aa1!" + secrets.token_hex(24),
    "BOOTSTRAP_USERNAME": "admin",
    "BOOTSTRAP_PASSWORD": secrets.token_urlsafe(24),
    "AI_PROVIDER": "local",
}
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    stream.write("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")
print(
    "Created .env with random deployment secrets. Read BOOTSTRAP_PASSWORD locally to sign in; do not commit or share this file."
)
