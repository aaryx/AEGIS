from functools import lru_cache
from typing import Literal
from urllib.parse import parse_qs, urlparse

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def validate_postgres_transport(url: str):
    if urlparse(url).scheme not in {"postgresql", "postgresql+psycopg"}:
        raise ValueError("Production requires PostgreSQL")
    parsed_db = urlparse(url)
    db_params = parse_qs(parsed_db.query, keep_blank_values=True)
    if any(len(values) != 1 or not values[0] for values in db_params.values()):
        raise ValueError("Production PostgreSQL parameters must be unique and nonempty")
    if not parsed_db.hostname or any(k in db_params for k in ("host", "hostaddr", "service")):
        raise ValueError("Production PostgreSQL requires an explicit URL hostname without overrides")
    sslmode = db_params.get("sslmode", [None])[0]
    if sslmode != "verify-full":
        raise ValueError(
            "Production requires verified PostgreSQL TLS (sslmode=verify-full with sslrootcert). "
            "sslmode=require alone does not verify certificates or hostnames."
        )
    if not db_params.get("sslrootcert", [None])[0]:
        raise ValueError(
            "Production requires PostgreSQL CA certificate path (sslrootcert) for TLS verification"
        )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    environment: Literal["development", "testing", "production"] = "development"
    database_url: str = Field("sqlite:///./aegis.db", repr=False)
    redis_url: str | None = Field(None, repr=False)
    redis_ca: str | None = None
    opensearch_url: str | None = None
    opensearch_username: str = "aegis"
    opensearch_password: SecretStr = SecretStr("")
    opensearch_ca: str | None = None
    audit_secret: SecretStr = SecretStr("")
    audit_key_version: int = Field(1, ge=1)
    controller_signing_key: SecretStr = SecretStr("")
    audit_anchor_backend: Literal["none", "s3", "local_worm"] = "none"
    audit_anchor_s3_bucket: str = ""
    audit_anchor_s3_prefix: str = "audit-checkpoints"
    audit_anchor_s3_region: str = "us-east-1"
    audit_anchor_s3_endpoint_url: str | None = None
    audit_anchor_s3_access_key_id: SecretStr = SecretStr("")
    audit_anchor_s3_secret_access_key: SecretStr = SecretStr("")
    audit_anchor_s3_object_lock_mode: Literal["COMPLIANCE", "GOVERNANCE"] = "COMPLIANCE"
    audit_anchor_s3_retention_days: int = Field(365, ge=1)
    audit_anchor_s3_kms_key_id: str | None = None
    audit_anchor_local_dir: str = "./local-data/worm-audit"
    cookie_secure: bool = False
    public_origin: str = "http://localhost:3000"
    session_hours: int = Field(8, ge=1, le=24)
    max_request_bytes: int = Field(2_000_000, ge=1024, le=20_000_000)
    max_event_bytes: int = Field(65536, ge=1024, le=262144)
    max_batch_events: int = Field(500, ge=1, le=2000)
    queue_capacity: int = Field(100000, ge=100)
    worker_batch_size: int = Field(100, ge=1, le=500)
    worker_max_attempts: int = Field(6, ge=1, le=12)
    ueba_baseline_days: int = Field(14, ge=7, le=30)
    ueba_min_observations: int = Field(20, ge=10, le=10000)
    ueba_min_active_days: int = Field(7, ge=3, le=7)
    ueba_event_limit: int = Field(10000, ge=100, le=50000)
    soar_queue_capacity: int = Field(100, ge=1, le=10000)
    soar_batch_size: int = Field(20, ge=1, le=100)
    intel_auto_provider: Literal["none", "mock", "virustotal"] = "none"
    intel_mock_enabled: bool = False
    intel_vt_enabled: bool = False
    intel_vt_api_key: SecretStr = SecretStr("")
    intel_cache_seconds: int = Field(3600, ge=60, le=604800)
    intel_failure_cache_seconds: int = Field(300, ge=30, le=3600)
    intel_refresh_seconds: int = Field(60, ge=30, le=3600)
    intel_requests_per_minute: int = Field(4, ge=1, le=1000)
    intel_queue_capacity: int = Field(500, ge=1, le=10000)
    intel_timeout_seconds: int = Field(5, ge=1, le=15)
    detection_lateness_seconds: int = Field(120, ge=0, le=3600)
    detection_window_limit: int = Field(10000, ge=100, le=50000)
    integration_allowed_hosts: list[str] = Field(default_factory=list)
    integration_max_bytes: int = Field(2_000_000, ge=1024, le=10_000_000)
    integration_timeout_seconds: int = Field(10, ge=1, le=30)
    integration_max_attempts: int = Field(6, ge=1, le=12)
    response_approval_seconds: int = Field(3600, ge=60, le=86400)
    max_search_days: int = Field(31, ge=1, le=366)
    retention_days: int = Field(90, ge=7)
    retention_batch_size: int = Field(500, ge=10, le=5000)
    retention_interval_seconds: int = Field(3600, ge=60)
    maintenance_database_url: str | None = Field(None, repr=False)
    opensearch_replicas: int = Field(0, ge=0, le=5)
    max_entities_per_event: int = Field(15, ge=2, le=50)
    ai_provider: Literal["local", "openai", "azure"] = "local"
    ai_api_key: SecretStr = SecretStr("")
    ai_endpoint: str = "https://api.openai.com/v1/chat/completions"
    ai_model: str = "gpt-4.1-mini"
    ai_max_tokens: int = Field(1500, ge=100, le=4000)
    ai_evidence_limit: int = Field(20, ge=1, le=50)

    @model_validator(mode="after")
    def secure_configuration(self):
        if self.environment == "production":
            validate_postgres_transport(self.database_url)
            if self.maintenance_database_url:
                validate_postgres_transport(self.maintenance_database_url)

            if not self.redis_url or not self.opensearch_url:
                raise ValueError("Production requires Redis and OpenSearch")
            if not self.redis_url.startswith("rediss://"):
                raise ValueError("Production requires TLS for Redis (rediss://)")
            parsed_redis = urlparse(self.redis_url)
            redis_params = parse_qs(parsed_redis.query, keep_blank_values=True)
            if any(len(values) != 1 or not values[0] for values in redis_params.values()):
                raise ValueError("Production Redis parameters must be unique and nonempty")
            ssl_cert_reqs = redis_params.get("ssl_cert_reqs", [None])[0]
            if ssl_cert_reqs not in {None, "required"}:
                raise ValueError("Production Redis TLS certificate verification must not be disabled")
            if redis_params.get("ssl_check_hostname", ["true"])[0].lower() != "true":
                raise ValueError("Production Redis requires TLS hostname verification")
            if set(redis_params) - {"ssl_cert_reqs", "ssl_check_hostname", "db"}:
                raise ValueError("Production Redis URL contains unsupported overrides; configure trust with REDIS_CA")
            if not parsed_redis.hostname or not parsed_redis.password:
                raise ValueError("Production requires authenticated Redis connection")

            if not self.opensearch_url.startswith("https://"):
                raise ValueError("Production requires HTTPS for OpenSearch")
            if not self.opensearch_ca:
                raise ValueError("Production requires CA certificate validation for OpenSearch (opensearch_ca)")
            if len(self.audit_secret.get_secret_value()) < 32:
                raise ValueError("AUDIT_SECRET must contain at least 32 characters")
            if not self.cookie_secure or not self.public_origin.startswith("https://"):
                raise ValueError("Production requires HTTPS and secure cookies")
        if self.ai_provider != "local":
            if not self.ai_endpoint.startswith("https://") or not self.ai_api_key.get_secret_value():
                raise ValueError("External AI requires an HTTPS endpoint and API key")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
