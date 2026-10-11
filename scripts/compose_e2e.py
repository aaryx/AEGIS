"""Run Playwright against the running Compose web/API without exposing credentials."""

import os
import shutil
import subprocess  # nosec B404
from pathlib import Path

from dotenv import dotenv_values

root = Path(__file__).resolve().parents[1]
config = dotenv_values(root / ".env")
env = os.environ | {
    "AEGIS_E2E_USERNAME": config["BOOTSTRAP_USERNAME"],
    "AEGIS_E2E_PASSWORD": config["BOOTSTRAP_PASSWORD"],
    "AEGIS_WEB_URL": "http://localhost:3000",
    "AEGIS_DISTRIBUTED_E2E": "1",
}
subprocess.run(  # noqa: S603  # nosec B603
    [shutil.which("node"), "node_modules/@playwright/test/cli.js", "test"],
    cwd=root / "web",
    env=env,
    check=True,
)  # noqa: S603  # nosec B603
