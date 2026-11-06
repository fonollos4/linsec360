"""Patch/CVE exposure queries shared by API and KPI layers."""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..errors import NotFoundError


def list_findings(
    db: Session,
    *,
    host_name: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[models.PatchFinding]:
    query = db.query(models.PatchFinding)
    if host_name:
        query = query.filter(models.PatchFinding.host_name == host_name)
    if severity:
        query = query.filter(models.PatchFinding.severity == severity)
    if status:
        query = query.filter(models.PatchFinding.status == status)
    if source:
        query = query.filter(models.PatchFinding.source == source)
    return (
        query.order_by(
            models.PatchFinding.updated_at.desc(), models.PatchFinding.id.desc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


def resolve(db: Session, finding_id: int) -> models.PatchFinding:
    finding = db.get(models.PatchFinding, finding_id)
    if finding is None:
        raise NotFoundError("patch finding not found")
    finding.status = "resolved"
    db.commit()
    db.refresh(finding)
    return finding


def summary(db: Session) -> dict:
    rows = (
        db.query(
            models.PatchFinding.status,
            models.PatchFinding.severity,
            func.count(models.PatchFinding.id),
        )
        .group_by(models.PatchFinding.status, models.PatchFinding.severity)
        .all()
    )
    counts: dict[str, dict[str, int]] = {}
    total_open = 0
    for status, severity, count in rows:
        counts.setdefault(status, {})[severity] = count
        if status == "open":
            total_open += count
    reboot_required = (
        db.query(func.count(models.PatchFinding.id))
        .filter(
            models.PatchFinding.status == "open",
            models.PatchFinding.reboot_required.is_(True),
        )
        .scalar()
        or 0
    )
    return {
        "open": total_open,
        "reboot_required": reboot_required,
        "by_status": counts,
    }
