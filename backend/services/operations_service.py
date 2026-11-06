from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..schemas import DeploymentCreate
from . import deployment_service

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def window_allows(db: Session, environment: str, now: datetime | None = None) -> bool:
    current = now or _now()
    windows = (
        db.query(models.MaintenanceWindow)
        .filter(
            models.MaintenanceWindow.enabled.is_(True),
            models.MaintenanceWindow.environment_name == environment,
        )
        .all()
    )
    if not windows:
        return True
    return any(
        _aware(window.starts_at) <= current <= _aware(window.ends_at)
        for window in windows
    )


def run_due_schedules(db: Session) -> int:
    now = _now()
    candidates = (
        db.query(models.OperationSchedule)
        .filter(models.OperationSchedule.enabled.is_(True))
        .all()
    )
    due = [
        schedule
        for schedule in candidates
        if schedule.next_run_at is not None
        and _aware(schedule.next_run_at) <= now
    ]
    executed = 0
    for schedule in due:
        schedule.last_run_at = now
        if not window_allows(db, schedule.environment_name, now):
            schedule.last_status = "outside_maintenance_window"
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            continue

        if schedule.operation in {"openscap", "patch"}:
            playbook = (
                schedule.playbook_name
                or ("openscap-scan.yml" if schedule.operation == "openscap" else "patch-security.yml")
            )
            try:
                actor = db.query(models.User).filter(models.User.role == "admin").first()
                if actor is None:
                    schedule.last_status = "no_admin_actor"
                else:
                    deployment_service.create_deployment(
                        db,
                        payload=DeploymentCreate(
                            environment=schedule.environment_name,
                            playbook=playbook,
                            hosts=schedule.target_hosts,
                        ),
                        actor=actor,
                    )
                    schedule.last_status = "queued"
                    executed += 1
            except Exception as exc:
                logger.exception("Scheduled operation %s failed", schedule.name)
                schedule.last_status = "failed"
                schedule.config = {**schedule.config, "last_error": str(exc)}
        else:
            schedule.last_status = "integration_sync_not_automated"
        schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
    db.commit()
    return executed


def cleanup_orphans(db: Session) -> int:
    settings = get_settings()
    cutoff = _now() - timedelta(seconds=settings.deployment_timeout_seconds)
    orphaned = (
        db.query(models.Deployment)
        .filter(
            models.Deployment.status.in_(["queued", "running"]),
            models.Deployment.created_at < cutoff,
        )
        .all()
    )
    for deployment in orphaned:
        deployment.status = "failed"
        deployment.finished_at = _now()
        deployment.error_message = "deployment timed out or orphaned by worker restart"
        deployment.events.append(
            models.DeploymentEvent(
                level="error",
                event="deployment_orphan_cleaned",
                message=deployment.error_message,
            )
        )
        for target in deployment.targets:
            if target.status in {"pending", "running"}:
                target.status = "failed"
    db.commit()
    return len(orphaned)


async def scheduler_loop() -> None:
    from ..db import session_scope

    while True:
        try:
            with session_scope() as db:
                run_due_schedules(db)
                cleanup_orphans(db)
        except Exception:
            logger.exception("Operation scheduler poll failed")
        await asyncio.sleep(60)
