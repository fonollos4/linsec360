"""KPI aggregation with explicit unknown states (no synthetic values)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..schemas import KpiItem, KpiOverview


def _ok(value: float | int | None, source: str) -> KpiItem:
    if value is None:
        return KpiItem(value=None, status="unknown", source=source)
    return KpiItem(value=float(value), status="ok", source=source)


def _unknown(source: str, status: str = "unknown") -> KpiItem:
    return KpiItem(value=None, status=status, source=source)


def overview(db: Session) -> KpiOverview:
    now = datetime.now(UTC)
    window_start = now - timedelta(days=30)

    total_hosts = db.query(func.count(models.Host.id)).scalar() or 0
    secured_hosts = (
        db.query(func.count(models.Host.id))
        .filter(models.Host.status == "secured")
        .scalar()
        or 0
    )
    deploying_hosts = (
        db.query(func.count(models.Host.id))
        .filter(models.Host.status == "deploying")
        .scalar()
        or 0
    )
    active_deployments = (
        db.query(func.count(models.Deployment.id))
        .filter(models.Deployment.status.in_(("queued", "running")))
        .scalar()
        or 0
    )

    finished = (
        db.query(models.Deployment.status, func.count(models.Deployment.id))
        .filter(models.Deployment.finished_at.is_not(None))
        .filter(models.Deployment.created_at >= window_start)
        .group_by(models.Deployment.status)
        .all()
    )
    counts = {status: count for status, count in finished}
    succeeded = counts.get("succeeded", 0)
    failed = counts.get("failed", 0)
    completed = succeeded + failed
    success_rate = (succeeded / completed * 100) if completed else None

    return KpiOverview(
        generated_at=now,
        hosts_total=_ok(total_hosts, "database"),
        hosts_secured=_ok(secured_hosts, "database"),
        hosts_deploying=_ok(deploying_hosts, "database"),
        active_deployments=_ok(active_deployments, "database"),
        deployment_success_rate=(
            _ok(success_rate, "database")
            if success_rate is not None
            else _unknown("database")
        ),
        open_vulnerabilities=_unknown("wazuh"),
        compliance_score=_unknown("openscap"),
    )
