"""Start real API and Next.js, run Playwright, then stop both processes."""

import os
import secrets
import shutil
import subprocess  # nosec B404 - fixed local test commands
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    env = os.environ | {
        "AEGIS_E2E_USERNAME": "e2e-analyst",
        "AEGIS_E2E_PASSWORD": secrets.token_urlsafe(24),
        "AEGIS_WEB_URL": "http://127.0.0.1:3000",
    }
    commands = [
        ([sys.executable, "scripts/e2e_server.py"], ROOT),
        (["node", "node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1"], ROOT / "web"),
    ]
    processes = [subprocess.Popen(command, cwd=cwd, env=env) for command, cwd in commands]  # noqa: S603  # nosec B603
    try:
        for url in ("http://127.0.0.1:8000/api/v1/system/liveness", "http://127.0.0.1:3000"):
            for _ in range(60):
                try:
                    if httpx.get(url, timeout=2).status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(1)
            else:
                raise RuntimeError("Acceptance service did not become healthy")
        subprocess.run(  # noqa: S603  # nosec B603
            [shutil.which("node"), "node_modules/@playwright/test/cli.js", "test"],
            cwd=ROOT / "web",
            env=env,
            check=True,
        )
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=15)


if __name__ == "__main__":
    main()
