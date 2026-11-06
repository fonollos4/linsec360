"""Application configuration for the LinSec360 FastAPI backend.

All runtime configuration is environment-driven and validated at startup.
Secrets are never hardcoded for production: setting ``LINSEC_ENVIRONMENT`` to
``production`` requires an explicit ``LINSEC_SECRET_KEY``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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
    cookie_samesite: str = "lax"

    database_url: str = f"sqlite:///{BASE_DIR / 'instance' / 'linsec.db'}"
    auto_create_tables: bool = True
    database_echo: bool = False

    redis_url: str = ""
    deployment_worker_threads: int = 2

    log_dir: Path = BASE_DIR / "logs"
    taskengine_dir: Path = BASE_DIR / "taskengine"
    playbook_dir: Path | None = None
    inventory_dir: Path | None = None
    bundled_playbooks_dir: Path = BASE_DIR / "taskengine" / "playbooks"
    ansible_playbook_bin: str = "ansible-playbook"

    cors_origins: list[str] = Field(default_factory=list)

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

    @model_validator(mode="after")
    def _production_safety(self) -> Settings:
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
