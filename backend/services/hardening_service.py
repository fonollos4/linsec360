"""Hardening baseline metadata and per-host check ingestion."""

from __future__ import annotations

from datetime import UTC, datetime

import yaml
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..errors import DomainError, NotFoundError
from ..schemas import HardeningCheckIn


def load_baseline() -> dict:
    path = get_settings().hardening_baseline_path
    if not path.exists():
        return {"controls": []}
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise DomainError(f"could not read hardening baseline: {exc}") from exc
    if not isinstance(payload, dict):
        raise DomainError("hardening baseline must be a mapping")
    return payload


def baseline_controls() -> list[dict]:
    controls = load_baseline().get("controls") or []
    return [control for control in controls if isinstance(control, dict)]


def _require_host(db: Session, name: str) -> models.Host:
    host = db.query(models.Host).filter(models.Host.name == name).one_or_none()
    if host is None:
        raise NotFoundError("host not found")
    return host


def ingest_results(
    db: Session, *, host_name: str, checks: list[HardeningCheckIn]
) -> list[models.HardeningCheck]:
    host = _require_host(db, host_name)
    checked_at = datetime.now(UTC)
    seen: set[str] = set()
    records: list[models.HardeningCheck] = []
    for check in checks:
        if check.control in seen:
            continue
        seen.add(check.control)
        record = models.HardeningCheck(
            host_id=host.id,
            host_name=host.name,
            category=check.category,
            control=check.control,
            expected=check.expected,
            actual=check.actual,
            status=check.status,
            checked_at=checked_at,
        )
        db.add(record)
        records.append(record)
    db.commit()
    for record in records:
        db.refresh(record)
    return records


def latest_checks(
    db: Session, *, host_name: str | None = None
) -> list[models.HardeningCheck]:
    """Return the newest result per (host, control)."""
    query = db.query(models.HardeningCheck).order_by(
        models.HardeningCheck.checked_at.desc(),
        models.HardeningCheck.id.desc(),
    )
    if host_name:
        query = query.filter(models.HardeningCheck.host_name == host_name)
    latest: dict[tuple[str, str], models.HardeningCheck] = {}
    for check in query.all():
        key = (check.host_name, check.control)
        if key not in latest:
            latest[key] = check
    return list(latest.values())


def summary(db: Session, *, host_name: str | None = None) -> dict:
    checks = latest_checks(db, host_name=host_name)
    counts = {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0}
    by_host: dict[str, dict[str, int]] = {}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1
        host_counts = by_host.setdefault(
            check.host_name,
            {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0, "drift": 0},
        )
        host_counts[check.status] = host_counts.get(check.status, 0) + 1
        if check.status == "fail":
            host_counts["drift"] += 1
    drifted_hosts = [name for name, values in by_host.items() if values["drift"] > 0]
    evaluated = counts["pass"] + counts["fail"]
    score = (counts["pass"] / evaluated * 100) if evaluated else None
    return {
        "checked_controls": len(checks),
        "counts": counts,
        "score": round(score, 2) if score is not None else None,
        "drifted_hosts": sorted(drifted_hosts),
        "hosts": by_host,
    }


def host_checks(db: Session, host_id: int) -> list[models.HardeningCheck]:
    host = db.get(models.Host, host_id)
    if host is None:
        raise NotFoundError("host not found")
    return latest_checks(db, host_name=host.name)
