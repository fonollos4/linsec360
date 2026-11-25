"""Encrypted credentials for native kernel live-patching tools."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy.orm import Session

from .. import models
from ..errors import IntegrationUnavailable
from . import credential_service

logger = logging.getLogger(__name__)

SECRET_KEYS: tuple[str, ...] = (
    "ubuntu_pro_token",
    "canonical_livepatch_token",
)


def catalog(db: Session) -> dict:
    """Return configuration status only; secret values are never exposed."""
    rows = {
        row.key: row
        for row in db.query(models.PlatformSecret)
        .filter(models.PlatformSecret.key.in_(SECRET_KEYS))
        .all()
    }
    return {
        "secrets": [
            {
                "key": key,
                "configured": key in rows,
                "updated_at": rows[key].updated_at if key in rows else None,
            }
            for key in SECRET_KEYS
        ]
    }


def update(
    db: Session,
    *,
    secrets: Mapping[Literal["ubuntu_pro_token", "canonical_livepatch_token"], str | None],
    actor: models.User | None = None,
) -> dict:
    """Store or clear tokens. ``None``/empty values remove the stored secret."""
    for key, value in secrets.items():
        if key not in SECRET_KEYS:  # pragma: no cover - validated by the API
            continue
        existing = db.get(models.PlatformSecret, key)
        if value is None or not value.strip():
            if existing is not None:
                db.delete(existing)
            continue
        encrypted = credential_service.encrypt_secret(value)
        if existing is None:
            existing = models.PlatformSecret(key=key, value_encrypted=encrypted)
            db.add(existing)
        else:
            existing.value_encrypted = encrypted
        existing.updated_by_id = actor.id if actor else None
        existing.updated_at = datetime.now(UTC)
    db.commit()
    return catalog(db)


def values(db: Session) -> dict[str, str]:
    """Decrypt tokens for worker injection, skipping unreadable rows."""
    rows = (
        db.query(models.PlatformSecret)
        .filter(models.PlatformSecret.key.in_(SECRET_KEYS))
        .all()
    )
    result: dict[str, str] = {}
    for row in rows:
        try:
            result[row.key] = credential_service.decrypt_secret(row.value_encrypted)
        except IntegrationUnavailable:
            logger.warning(
                "native tool secret could not be decrypted; skipping injection",
                extra={"key": row.key},
            )
    return result
