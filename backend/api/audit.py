"""Audit log read API (admin and auditor roles)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import AuditOut
from ..security import require_roles

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "auditor")),
) -> list[AuditOut]:
    entries = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [AuditOut.model_validate(entry) for entry in entries]
