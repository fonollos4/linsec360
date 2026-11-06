"""KPI aggregation with explicit unknown states (no synthetic values)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..schemas import KpiItem, KpiOverview
from . import alert_service, hardening_service


def _ok(value: float | int | None, source: str) -> KpiItem:
    if value is None:
        return KpiItem(value=None, status="unknown", source=source)
    return KpiItem(value=float(value), status="ok", source=source)


def _unknown(
    source: str, status: Literal["unknown", "stale"] = "unknown"
) -> KpiItem:
    return KpiItem(value=None, status=status, source=source)


def _has_rows(db: Session, model) -> bool:
    return db.query(model.id).first() is not None


def overview(db: Session) -> KpiOverview:
    now = datetime.now(UTC)
    window_start = now - timedelta(days=30)
    agent_window = now - timedelta(minutes=15)

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

    # Patch/CVE data comes from Wazuh vulnerability detection or Uyuni errata.
    patch_rows = _has_rows(db, models.PatchFinding)
    open_patch = (
        db.query(func.count(models.PatchFinding.id))
        .filter(models.PatchFinding.status == "open")
        .scalar()
        or 0
    )
    critical = (
        db.query(func.count(models.PatchFinding.id))
        .filter(
            models.PatchFinding.status == "open",
            models.PatchFinding.severity == "critical",
        )
        .scalar()
        or 0
    )
    high = (
        db.query(func.count(models.PatchFinding.id))
        .filter(
            models.PatchFinding.status == "open",
            models.PatchFinding.severity == "high",
        )
        .scalar()
        or 0
    )
    reboot_required = (
        db.query(func.count(models.PatchFinding.id))
        .filter(
            models.PatchFinding.status == "open",
            models.PatchFinding.reboot_required.is_(True),
        )
        .scalar()
        or 0
    )
    open_hosts = (
        db.query(func.count(func.distinct(models.PatchFinding.host_name)))
        .filter(models.PatchFinding.status == "open")
        .scalar()
        or 0
    )
    patch_coverage = (
        (1 - open_hosts / total_hosts) * 100 if total_hosts and patch_rows else None
    )

    # OpenSCAP: use the newest scan per host.
    scans = (
        db.query(models.ComplianceScan)
        .filter(models.ComplianceScan.score.is_not(None))
        .order_by(models.ComplianceScan.finished_at.desc())
        .all()
    )
    latest_by_host: dict[str, models.ComplianceScan] = {}
    for scan in scans:
        latest_by_host.setdefault(scan.host_name, scan)
    compliance_score = (
        sum(
            scan.score
            for scan in latest_by_host.values()
            if scan.score is not None
        )
        / len(latest_by_host)
        if latest_by_host
        else None
    )

    # Agent health is only known once Wazuh has been synchronized.
    agents_known = (
        db.query(func.count(models.Host.id))
        .filter(models.Host.agent_id.is_not(None))
        .scalar()
        or 0
    )
    connected = (
        db.query(func.count(models.Host.id))
        .filter(
            models.Host.agent_id.is_not(None),
            models.Host.last_seen.is_not(None),
            models.Host.last_seen >= agent_window,
        )
        .scalar()
        or 0
    )
    if agents_known:
        agent_coverage = (connected / total_hosts * 100) if total_hosts else None
        disconnected = max(agents_known - connected, 0)
    else:
        agent_coverage = None
        disconnected = None

    hardening = hardening_service.summary(db)
    hardening_known = hardening["checked_controls"] > 0
    selinux_failed = sum(
        1
        for check in hardening_service.latest_checks(db)
        if check.category == "selinux" and check.status == "fail"
    )

    livepatch_records = db.query(models.LivepatchStatus).all()
    exposure_values = [
        item.exposure_days
        for item in livepatch_records
        if item.exposure_days is not None
    ]
    kernel_exposure = max(exposure_values) if exposure_values else None

    alerts_known = _has_rows(db, models.Alert)
    severity_counts = (
        alert_service.severity_counts(db, unacknowledged_only=True)
        if alerts_known
        else None
    )

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
        open_vulnerabilities=(
            _ok(open_patch, "wazuh")
            if patch_rows
            else _unknown("wazuh")
        ),
        compliance_score=(
            _ok(compliance_score, "openscap")
            if compliance_score is not None
            else _unknown("openscap")
        ),
        agent_coverage=(
            _ok(agent_coverage, "wazuh")
            if agent_coverage is not None
            else _unknown("wazuh")
        ),
        disconnected_agents=(
            _ok(disconnected, "wazuh")
            if disconnected is not None
            else _unknown("wazuh")
        ),
        open_critical_vulnerabilities=(
            _ok(critical, "wazuh") if patch_rows else _unknown("wazuh")
        ),
        open_high_vulnerabilities=(
            _ok(high, "wazuh") if patch_rows else _unknown("wazuh")
        ),
        patch_coverage=(
            _ok(patch_coverage, "uyuni") if patch_coverage is not None else _unknown("uyuni")
        ),
        reboot_required=(
            _ok(reboot_required, "uyuni") if patch_rows else _unknown("uyuni")
        ),
        kernel_exposure_days=(
            _ok(kernel_exposure, "livepatch")
            if kernel_exposure is not None
            else _unknown("livepatch")
        ),
        hardening_drift=(
            _ok(len(hardening["drifted_hosts"]), "hardening")
            if hardening_known
            else _unknown("hardening")
        ),
        selinux_non_compliant=(
            _ok(selinux_failed, "hardening")
            if hardening_known
            else _unknown("hardening")
        ),
        alerts_by_severity=severity_counts,
    )


def capture_snapshot(db: Session) -> int:
    """Persist the current KPI values for trend/history queries."""
    current = overview(db)
    created = 0
    for metric, item in current.model_dump().items():
        if metric in {"generated_at", "alerts_by_severity"}:
            continue
        if not isinstance(item, dict) or "status" not in item:
            continue
        db.add(
            models.KpiSnapshot(
                metric=metric,
                scope_type="global",
                value=item.get("value"),
                status=item["status"],
                source=item["source"],
                captured_at=current.generated_at,
            )
        )
        created += 1
    db.commit()
    return created


def history(
    db: Session,
    *,
    metric: str | None = None,
    days: int = 30,
    limit: int = 1000,
) -> list[models.KpiSnapshot]:
    since = datetime.now(UTC) - timedelta(days=days)
    query = db.query(models.KpiSnapshot).filter(
        models.KpiSnapshot.captured_at >= since
    )
    if metric:
        query = query.filter(models.KpiSnapshot.metric == metric)
    return (
        query.order_by(models.KpiSnapshot.captured_at.asc())
        .limit(limit)
        .all()
    )
