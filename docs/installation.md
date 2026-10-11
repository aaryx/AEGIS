# Installation

## Supported development runtimes

- Python 3.12 or newer (local verification used 3.14; containers use 3.12).
- Node.js 24 and npm 11.
- Docker Desktop on Windows/macOS or Docker Engine with Compose on Linux.

Create a virtual environment and install with the checked-in constraints:

```sh
python -m venv .venv
python -m pip install --upgrade pip==26.2.1
python -m pip install -c requirements.lock -e ".[dev]"
npm --prefix web ci
```

Activate `.venv/Scripts/activate` on Windows or `.venv/bin/activate` on POSIX.
`python scripts/dev.py` exposes install, dev, test, lint, format, typecheck,
security and build commands. Make targets invoke the same script.

## Database initialization

Compose runs Alembic in its initialization service before API/workers start.
For a manually configured PostgreSQL deployment:

```sh
alembic upgrade head
aegis bootstrap
uvicorn aegis.api:app --host 127.0.0.1 --port 8000 --no-access-log
aegis-worker
```

`bootstrap` only creates the first user. Additional users require an authorized
API call. Development SQLite tables are created automatically by API startup;
production does not create schema outside migrations.
