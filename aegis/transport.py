"""Shared Redis transport policy for API and worker clients."""

from redis import Redis
from sqlalchemy.engine import make_url

from aegis.config import Settings


def redis_client(settings: Settings):
    if not settings.redis_url:
        return None
    options: dict = {}
    if settings.redis_url.startswith("rediss://"):
        options = {"ssl_cert_reqs": "required", "ssl_check_hostname": True}
        if settings.redis_ca:
            options["ssl_ca_certs"] = settings.redis_ca
    return Redis.from_url(
        settings.redis_url, socket_timeout=3, socket_connect_timeout=3, **options
    )


def postgres_connect_kwargs(url: str) -> dict:
    """Preserve libpq TLS parameters for bootstrap connections outside SQLAlchemy."""
    parsed = make_url(url)
    return parsed.translate_connect_args(username="user", database="dbname") | dict(parsed.query)
