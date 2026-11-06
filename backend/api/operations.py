from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..errors import DomainError, NotFoundError
from ..schemas import (
    MaintenanceWindowCreate,
    MaintenanceWindowOut,
    OperationScheduleCreate,
    OperationScheduleOut,
)
from ..security import get_current_user, require_roles
from ..services import audit_service, operations_service

router = APIRouter(prefix="/operations", tags=["operations"])


@router.get("/schedules", response_model=list[OperationScheduleOut])
def list_schedules(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[OperationScheduleOut]:
    return [
        OperationScheduleOut.model_validate(schedule)
        for schedule in db.query(models.OperationSchedule)
        .order_by(models.OperationSchedule.id)
        .all()
    ]


@router.post("/schedules", response_model=OperationScheduleOut, status_code=201)
def create_schedule(
    payload: OperationScheduleCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> OperationScheduleOut:
    schedule = models.OperationSchedule(
        name=payload.name,
        operation=payload.operation,
        environment_name=payload.environment,
        playbook_name=payload.playbook,
        profile=payload.profile,
        interval_minutes=payload.interval_minutes,
        enabled=payload.enabled,
        next_run_at=datetime.now(UTC) + timedelta(minutes=payload.interval_minutes),
        target_hosts=payload.hosts,
        config=payload.config,
    )
    db.add(schedule)
    db.flush()
    audit_service.record(
        db, actor=user, action="schedule.create", target_type="operation_schedule",
        target_id=str(schedule.id), data={"operation": schedule.operation}, request=request,
    )
    db.commit()
    db.refresh(schedule)
    return OperationScheduleOut.model_validate(schedule)


@router.delete("/schedules/{schedule_id}", response_model=dict)
def delete_schedule(
    schedule_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> dict:
    schedule = db.get(models.OperationSchedule, schedule_id)
    if schedule is None:
        raise NotFoundError("schedule not found")
    db.delete(schedule)
    audit_service.record(
        db, actor=user, action="schedule.delete", target_type="operation_schedule",
        target_id=str(schedule_id), request=request,
    )
    db.commit()
    return {"deleted": schedule_id}


@router.post("/cleanup-orphans", response_model=dict)
def cleanup_orphans(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> dict:
    return {"cleaned": operations_service.cleanup_orphans(db)}


@router.post("/schedules/run-due", response_model=dict)
def run_due(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    return {"queued": operations_service.run_due_schedules(db)}


@router.get("/maintenance", response_model=list[MaintenanceWindowOut])
def list_windows(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[MaintenanceWindowOut]:
    return [
        MaintenanceWindowOut.model_validate(window)
        for window in db.query(models.MaintenanceWindow)
        .order_by(models.MaintenanceWindow.starts_at)
        .all()
    ]


@router.post("/maintenance", response_model=MaintenanceWindowOut, status_code=201)
def create_window(
    payload: MaintenanceWindowCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> MaintenanceWindowOut:
    if payload.ends_at <= payload.starts_at:
        raise DomainError("maintenance window end must be after start")
    window = models.MaintenanceWindow(
        name=payload.name,
        environment_name=payload.environment,
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
        enabled=payload.enabled,
        config=payload.config,
    )
    db.add(window)
    db.commit()
    db.refresh(window)
    return MaintenanceWindowOut.model_validate(window)
