"""Database-persisted, non-secret overrides for stack connection settings."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from .. import models
from ..config import Settings, get_settings
from ..schemas import StackConfiguration, StackConfigurationUpdate

SETTING_FIELDS = (
    "wazuh_manager_address",
    "wazuh_manager_agent_port",
    "wazuh_manager_enrollment_port",
    "wazuh_api_url",
    "wazuh_indexer_url",
    "wazuh_dashboard_url",
    "uyuni_api_url",
    "uyuni_server",
)
PORT_FIELDS = frozenset({"wazuh_manager_agent_port", "wazuh_manager_enrollment_port"})


def effective_settings(db: Session, settings: Settings | None = None) -> Settings:
    base = settings or get_settings()
    rows = (
        db.query(models.RuntimeSetting)
        .filter(models.RuntimeSetting.key.in_(SETTING_FIELDS))
        .all()
    )
    updates: dict[str, str | int] = {}
    for row in rows:
        updates[row.key] = int(row.value) if row.key in PORT_FIELDS else row.value
    return base.model_copy(update=updates) if updates else base


def _safe_endpoint(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return ""
    if not parsed.scheme or not hostname:
        return ""
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def read(db: Session) -> StackConfiguration:
    settings = effective_settings(db)
    return StackConfiguration(
        wazuh_manager_address=settings.wazuh_manager_address,
        wazuh_manager_agent_port=settings.wazuh_manager_agent_port,
        wazuh_manager_enrollment_port=settings.wazuh_manager_enrollment_port,
        wazuh_api_url=_safe_endpoint(settings.wazuh_api_url),
        wazuh_indexer_url=_safe_endpoint(settings.wazuh_indexer_url),
        wazuh_dashboard_url=_safe_endpoint(settings.wazuh_dashboard_url),
        uyuni_api_url=_safe_endpoint(settings.uyuni_api_url),
        uyuni_server=settings.uyuni_server,
    )


def save(
    db: Session,
    payload: StackConfigurationUpdate,
    *,
    updated_by_id: int,
) -> StackConfiguration:
    values = payload.model_dump()
    for key, value in values.items():
        setting = db.get(models.RuntimeSetting, key)
        if setting is None:
            setting = models.RuntimeSetting(key=key, value=str(value))
            db.add(setting)
        else:
            setting.value = str(value)
        setting.updated_by_id = updated_by_id
    db.flush()
    return read(db)


def reset(db: Session) -> StackConfiguration:
    db.query(models.RuntimeSetting).filter(
        models.RuntimeSetting.key.in_(SETTING_FIELDS)
    ).delete(synchronize_session=False)
    db.flush()
    return read(db)
