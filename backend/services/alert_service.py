"""Alert queries and acknowledgement."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..errors import NotFoundError


def list_alerts(
    db: Session,
    *,
    severity: str | None = None,
    acknowledged: bool | None = None,
    agent_name: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[models.Alert]:
    query = db.query(models.Alert)
    if severity:
        query = query.filter(models.Alert.severity == severity)
    if acknowledged is not None:
        query = query.filter(models.Alert.acknowledged.is_(acknowledged))
    if agent_name:
        query = query.filter(models.Alert.agent_name == agent_name)
    return (
        query.order_by(models.Alert.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_alert(db: Session, alert_id: int) -> models.Alert:
    alert = db.get(models.Alert, alert_id)
    if alert is None:
        raise NotFoundError("alert not found")
    return alert


def acknowledge(
    db: Session, *, alert: models.Alert, username: str
) -> models.Alert:
    alert.acknowledged = True
    alert.acknowledged_by = username
    alert.acknowledged_at = datetime.now(UTC)
    db.commit()
    db.refresh(alert)
    return alert


def severity_counts(db: Session, *, unacknowledged_only: bool = False) -> dict[str, int]:
    query = db.query(models.Alert.severity, func.count(models.Alert.id))
    if unacknowledged_only:
        query = query.filter(models.Alert.acknowledged.is_(False))
    return {severity: count for severity, count in query.group_by(models.Alert.severity)}
