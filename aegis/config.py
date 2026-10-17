from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["development", "testing", "production"] = "development"
    database_url: str = "sqlite:///./aegis.db"
    redis_url: str | None = None
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
    maintenance_database_url: str | None = None
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
            if not self.database_url.startswith("postgresql"):
                raise ValueError("Production requires PostgreSQL")
            if not self.redis_url or not self.opensearch_url:
                raise ValueError("Production requires Redis and OpenSearch")
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
