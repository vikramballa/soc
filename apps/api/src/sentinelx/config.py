"""Environment-driven configuration. Every tunable lives here; nothing security-relevant is hard-coded."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[4]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(REPO_ROOT / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: Literal["development", "test", "production"] = "development"
    app_secret: SecretStr = SecretStr("dev-insecure-change-me")
    app_base_url: str = "http://localhost:5173"
    api_cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    log_level: str = "INFO"
    log_json: bool = True

    database_url: str = "postgresql+asyncpg://sentinelx@127.0.0.1:5432/sentinelx"
    database_pool_size: int = 10

    # Auth
    auth_mode: Literal["local", "oidc", "both"] = "local"
    session_ttl_minutes: int = 480
    session_cookie_name: str = "sx_session"
    session_cookie_secure: bool = False
    login_max_failures: int = 8
    login_lockout_minutes: int = 15
    keycloak_url: str | None = None
    keycloak_realm: str = "sentinelx"
    keycloak_client_id: str = "sentinelx-web"
    keycloak_client_secret: SecretStr | None = None
    oidc_tenant_claim: str = "tenant"
    oidc_role_claim_prefix: str = "sentinelx:"
    oidc_allow_super_admin: bool = False

    # Workers / pipeline
    embedded_worker: bool = False
    worker_concurrency: int = 2
    worker_poll_seconds: float = 2.0
    ingest_max_body_bytes: int = 10 * 1024 * 1024
    ingest_max_events_per_request: int = 5000

    # Correlation (all windows configurable, see ADR-012)
    correlation_window_minutes: int = 60
    correlation_link_threshold: float = 1.0
    correlation_hub_entity_limit: int = 8
    incident_promote_risk: int = 50
    incident_promote_severity: int = 70
    ml_alone_can_promote: bool = False

    # Retention
    event_retention_days: int = 30
    rule_match_retention_hours: int = 48

    # Threat intel
    misp_url: str | None = None
    misp_api_key: SecretStr | None = None
    misp_verify_tls: bool = True
    ti_cache_hours: int = 24

    # AI (local only)
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:4b-instruct"
    ollama_timeout_seconds: float = 180.0
    ollama_num_ctx: int = 8192
    ai_enabled: bool = True
    ai_max_evidence_events: int = 24

    # Optional search backend
    opensearch_url: str | None = None
    opensearch_username: str | None = None
    opensearch_password: SecretStr | None = None
    opensearch_verify_tls: bool = True

    # Ingestion sources (file tailing for lab/single-node deployments)
    suricata_eve_path: Path | None = None
    zeek_log_dir: Path | None = None
    wazuh_alerts_path: Path | None = None
    wazuh_indexer_url: str | None = None
    wazuh_indexer_username: str | None = None
    wazuh_indexer_password: SecretStr | None = None
    wazuh_min_alert_level: int = 10
    file_ingest_tenant: str = "default"

    # Paths
    sigma_rules_dir: Path = REPO_ROOT / "security" / "sigma-rules"
    mitre_data_file: Path = REPO_ROOT / "security" / "mitre-data" / "enterprise-attack-compact.json"

    rate_limit_login_per_minute: int = 10
    rate_limit_api_per_minute: int = 600

    bootstrap_admin_email: str = "admin@sentinelx.local"
    bootstrap_admin_password: SecretStr | None = Field(default=None)

    @field_validator("api_cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str) and not v.strip().startswith("["):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def validate_for_production(self) -> list[str]:
        problems: list[str] = []
        if self.is_production:
            if (
                self.app_secret.get_secret_value() in ("dev-insecure-change-me", "")
                or len(self.app_secret.get_secret_value()) < 32
            ):
                problems.append("APP_SECRET must be a random value of at least 32 characters")
            local_only = urlparse(self.app_base_url).hostname in ("localhost", "127.0.0.1", "::1")
            if not self.session_cookie_secure and not local_only:
                problems.append("SESSION_COOKIE_SECURE must be true in production (serve SentinelX over HTTPS)")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
