"""Cross-platform development and verification commands: python scripts/dev.py --help."""

import argparse
import os
import subprocess  # nosec B404 - fixed local developer commands only
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NPM = "npm.cmd" if os.name == "nt" else "npm"


def run(command, cwd=ROOT):
    subprocess.run(command, cwd=cwd, check=True)  # noqa: S603  # nosec B603 - fixed developer command arrays


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=["install", "dev", "test", "integration", "lint", "format", "typecheck", "security", "build"]
    )
    args = parser.parse_args()
    match args.command:
        case "install":
            run([sys.executable, "-m", "pip", "install", "-c", "requirements.lock", "-e", ".[dev]"])
            run([NPM, "ci"], ROOT / "web")
        case "dev":
            processes = [
                subprocess.Popen(command, cwd=cwd)  # noqa: S603  # nosec B603 - fixed commands below
                for command, cwd in [
                    (
                        [
                            sys.executable,
                            "-m",
                            "uvicorn",
                            "aegis.api:app",
                            "--host",
                            "127.0.0.1",
                            "--port",
                            "8000",
                            "--no-access-log",
                        ],
                        ROOT,
                    ),
                    ([sys.executable, "-m", "aegis.worker"], ROOT),
                    ([sys.executable, "-m", "aegis.notification_worker"], ROOT),
                    ([NPM, "run", "dev"], ROOT / "web"),
                ]
            ]
            try:
                for process in processes:
                    process.wait()
            except KeyboardInterrupt:
                for process in processes:
                    process.terminate()
        case "test":
            run([sys.executable, "-m", "pytest"])
            run([NPM, "test"], ROOT / "web")
        case "integration":
            run([sys.executable, "scripts/integration_gate.py"])
        case "lint":
            run([sys.executable, "-m", "ruff", "check", "aegis", "tests", "scripts"])
            run([NPM, "run", "typecheck"], ROOT / "web")
        case "format":
            run([sys.executable, "-m", "ruff", "format", "aegis", "tests", "scripts"])
        case "typecheck":
            run([sys.executable, "-m", "mypy", "aegis"])
            run([NPM, "run", "typecheck"], ROOT / "web")
        case "security":
            run([sys.executable, "-m", "bandit", "-r", "aegis", "scripts", "-ll", "-q"])
            run([sys.executable, "-m", "pip_audit", "--skip-editable"])
            run([NPM, "audit"], ROOT / "web")
        case "build":
            run([NPM, "run", "build"], ROOT / "web")
            run(["docker", "compose", "build"])


if __name__ == "__main__":
    main()
