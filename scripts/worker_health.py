import os
import sys
import time

from sqlalchemy import func, select

from aegis.config import get_settings
from aegis.db import WorkerHeartbeat, database

_, sessions = database(get_settings().database_url)
with sessions() as db:
    prefix = (
        "notifications-" + os.environ.get("HOSTNAME", "local")
        if "notifications" in sys.argv
        else os.environ.get("HOSTNAME", "local") + "-"
    )
    latest = db.scalar(
        select(func.max(WorkerHeartbeat.last_seen)).where(WorkerHeartbeat.id.startswith(prefix))
    )
    raise SystemExit(0 if latest and latest > time.time() - 45 else 1)
