"""Patch/CVE exposure queries shared by API and KPI layers."""

from __future__ import annotations

import re

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


def _version_at_least(installed: str, expected: str) -> bool:
    """Compare dotted versions without adding a dependency to the stack."""

    def parts(value: str) -> tuple[object, ...]:
        return tuple(
            int(part) if part.isdigit() else part
            for part in re.split(r"[^0-9A-Za-z]+", value)
            if part
        )

    try:
        return parts(installed) >= parts(expected)
    except TypeError:
        return installed == expected


def ingest_results(
    db: Session,
    *,
    host_name: str,
    checks: list[dict],
) -> list[models.PatchFinding]:
    """Apply evidence reported by patch/verify playbooks to patch findings."""
    touched: list[models.PatchFinding] = []
    for check in checks:
        package = check["package"]
        cve = check.get("cve") or ""
        records = (
            db.query(models.PatchFinding)
            .filter(
                models.PatchFinding.host_name == host_name,
                models.PatchFinding.package == package,
                models.PatchFinding.cve == cve,
            )
            .all()
        )
        if not records:
            host = (
                db.query(models.Host)
                .filter(models.Host.name == host_name)
                .one_or_none()
            )
            record = models.PatchFinding(
                host_id=host.id if host else None,
                host_name=host_name,
                package=package,
                cve=cve,
                source="native",
                severity="unknown",
            )
            db.add(record)
            records = [record]

        reboot_required = bool(check.get("reboot_required"))
        applied = bool(check.get("applied"))
        installed_version = check.get("installed_version") or ""
        expected = check.get("fixed_version") or next(
            (record.fixed_version for record in records if record.fixed_version), ""
        )
        version_ok = not (installed_version and expected) or _version_at_least(
            installed_version, str(expected)
        )
        verified = bool(check.get("verified")) and bool(installed_version) and version_ok
        # An install report cannot close a finding when the measured version is
        # still below the fixed version we are remediating.
        applied = applied and version_ok
        status = "open"
        if applied or verified:
            status = "reboot_required" if reboot_required else "resolved"
        for record in records:
            if installed_version:
                record.current_version = installed_version
            record.reboot_required = reboot_required
            record.status = status
            touched.append(record)
    db.commit()
    for record in touched:
        db.refresh(record)
    return touched


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
