"""Audit trail helpers."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from .. import models


def record(
    db: Session,
    *,
    action: str,
    target_type: str,
    actor: models.User | None = None,
    target_id: str | int | None = None,
    data: dict[str, Any] | None = None,
    request: Request | None = None,
) -> models.AuditLog:
    entry = models.AuditLog(
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        data=data or {},
        request_id=getattr(request.state, "request_id", None) if request else None,
        ip_address=(request.client.host if request and request.client else None),
    )
    db.add(entry)
    return entry
