"""Application configuration for the LinSec360 FastAPI backend.

All runtime configuration is environment-driven and validated at startup.
Secrets are never hardcoded for production: setting ``LINSEC_ENVIRONMENT`` to
``production`` requires an explicit ``LINSEC_SECRET_KEY``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import quote

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LINSEC_",
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "LinSec360 API"
    environment: str = "development"
    debug: bool = False
    api_prefix: str = "/api/v1"
    docs_enabled: bool = True

    secret_key: str = "dev-only-change-me"
    session_ttl_minutes: int = 480
    cookie_name: str = "linsec_session"
    csrf_cookie_name: str = "linsec_csrf"
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    database_url: str = f"sqlite:///{BASE_DIR / 'instance' / 'linsec.db'}"
    database_password: str = ""
    database_host: str = "postgres"
    database_port: int = 5432
    database_user: str = "linsec"
    database_name: str = "linsec"
    auto_create_tables: bool = True
    database_echo: bool = False

    redis_url: str = ""
    deployment_worker_threads: int = 2
    deployment_timeout_seconds: int = 1800
    deployment_retention_days: int = 365
    deployment_max_per_environment: int = Field(default=1, ge=1, le=100)

    log_dir: Path = BASE_DIR / "logs"
    taskengine_dir: Path = BASE_DIR / "taskengine"
    playbook_dir: Path | None = None
    inventory_dir: Path | None = None
    artifact_dir: Path | None = None
    config_dir: Path = BASE_DIR / "config"
    bundled_playbooks_dir: Path = BASE_DIR / "taskengine" / "playbooks"
    openscap_profile_dir: Path = BASE_DIR / "config" / "openscap" / "profiles"
    hardening_baseline_path: Path = (
        BASE_DIR / "config" / "hardening" / "baseline.yml"
    )
    ansible_playbook_bin: str = "ansible-playbook"
    # Optional explicit ansible.cfg. When empty the worker relies on the
    # system/user configuration but always sets ANSIBLE_ROLES_PATH itself.
    ansible_config_path: Path | None = None

    # Wazuh API / indexer. Empty values mean "not configured"; the API then
    # returns explicit unknown/503 states instead of fabricated data.
    wazuh_api_url: str = ""
    wazuh_api_username: str = ""
    wazuh_api_password: str = ""
    wazuh_api_verify_tls: bool = True
    wazuh_indexer_url: str = ""
    wazuh_indexer_username: str = ""
    wazuh_indexer_password: str = ""
    wazuh_indexer_verify_tls: bool = True
    wazuh_ca_bundle: Path | None = None
    wazuh_timeout_seconds: float = 15.0
    wazuh_alert_index: str = "wazuh-alerts-*"

    # Uyuni patch/repository control plane.
    uyuni_api_url: str = ""
    uyuni_username: str = ""
    uyuni_password: str = ""
    uyuni_verify_tls: bool = True
    uyuni_timeout_seconds: float = 30.0

    # Login protection.
    login_max_attempts: int = 5
    login_window_seconds: int = 300

    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""

    @property
    def playbooks_dir(self) -> Path:
        # Runtime materialization target. Kept separate from the bundled
        # playbooks so deleting a playbook cannot resurrect it on restart.
        return self.playbook_dir or (BASE_DIR / "var" / "playbooks")

    @property
    def inventories_dir(self) -> Path:
        return self.inventory_dir or (BASE_DIR / "var" / "inventories")

    @property
    def artifacts_dir(self) -> Path:
        return self.artifact_dir or (BASE_DIR / "var" / "artifacts")

    @property
    def ansible_roles_paths(self) -> list[Path]:
        """Role search path, including the vendored Wazuh collection layout."""
        roles = self.taskengine_dir / "roles"
        return [roles, roles / "wazuh"]

    @property
    def wazuh_configured(self) -> bool:
        return bool(
            self.wazuh_api_url
            and self.wazuh_api_username
            and self.wazuh_api_password
        )

    @property
    def uyuni_configured(self) -> bool:
        return bool(
            self.uyuni_api_url and self.uyuni_username and self.uyuni_password
        )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value):
        if value is None or isinstance(value, list):
            return value or []
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                parsed = value.split(",")
            if isinstance(parsed, list):
                return [item.strip() for item in parsed if isinstance(item, str) and item.strip()]
        return value

    @model_validator(mode="after")
    def _production_safety(self) -> Settings:
        if self.database_password:
            password = quote(self.database_password, safe="")
            self.database_url = (
                f"postgresql+psycopg://{quote(self.database_user, safe='')}:"
                f"{password}@{self.database_host}:{self.database_port}/{self.database_name}"
            )
        if self.environment == "production":
            if self.secret_key == "dev-only-change-me":
                raise ValueError(
                    "LINSEC_SECRET_KEY must be set when LINSEC_ENVIRONMENT=production"
                )
            if self.cookie_secure is False:
                raise ValueError(
                    "LINSEC_COOKIE_SECURE must be true when "
                    "LINSEC_ENVIRONMENT=production"
                )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
