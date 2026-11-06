"""Native kernel live-patching (klp) state for managed hosts."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from .. import models
from ..errors import NotFoundError
from ..schemas import LivepatchIn, LivepatchOut


def ingest(db: Session, payload: LivepatchIn) -> models.LivepatchStatus:
    host = (
        db.query(models.Host)
        .filter(models.Host.name == payload.host_name)
        .one_or_none()
    )
    if host is None:
        raise NotFoundError("host not found")
    record = models.LivepatchStatus(
        host_id=host.id,
        host_name=host.name,
        kernel=payload.kernel,
        livepatch_state=payload.livepatch_state,
        patch_available=payload.patch_available,
        exposure_days=payload.exposure_days,
        last_checked=datetime.now(UTC),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def latest_for_host(db: Session, host_id: int) -> models.LivepatchStatus | None:
    return (
        db.query(models.LivepatchStatus)
        .filter(models.LivepatchStatus.host_id == host_id)
        .order_by(models.LivepatchStatus.last_checked.desc())
        .first()
    )


def list_latest(db: Session) -> list[models.LivepatchStatus]:
    records = (
        db.query(models.LivepatchStatus)
        .order_by(
            models.LivepatchStatus.last_checked.desc(),
            models.LivepatchStatus.id.desc(),
        )
        .all()
    )
    latest: dict[str, models.LivepatchStatus] = {}
    for record in records:
        latest.setdefault(record.host_name, record)
    return list(latest.values())


def summary(db: Session) -> dict:
    records = list_latest(db)
    exposure = [item.exposure_days for item in records if item.exposure_days is not None]
    return {
        "hosts": len(records),
        "pending": sum(1 for item in records if item.patch_available),
        "max_exposure_days": max(exposure) if exposure else None,
    }


def serialize(record: models.LivepatchStatus) -> LivepatchOut:
    return LivepatchOut.model_validate(record)
