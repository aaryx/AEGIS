"""Independent notification worker; slow providers cannot delay detection."""

import logging
import os
import signal
import threading

from aegis.config import get_settings
from aegis.db import database
from aegis.integrations import dispatch_once
from aegis.observability import configure_logging
from aegis.worker import heartbeat


def main():
    configure_logging()
    settings = get_settings()
    engine, sessions = database(settings.database_url)
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    try:
        while not stopped.is_set():
            try:
                try:
                    dispatch_once(settings, sessions)
                except Exception as exc:
                    logging.getLogger("aegis.notifications").error(
                        "notification_dispatch_failed", extra={"error_type": type(exc).__name__}
                    )
                from aegis.intelligence import lookup_once
                lookup_once(settings, sessions)
                with sessions.begin() as db:
                    heartbeat(db, f"notifications-{os.environ.get('HOSTNAME', 'local')}")
            except Exception as exc:
                logging.getLogger("aegis.notifications").error(
                    "delivery_iteration_failed", extra={"error_type": type(exc).__name__}
                )
            stopped.wait(5)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
