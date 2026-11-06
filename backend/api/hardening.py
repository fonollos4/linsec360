"""Hardening baseline, check ingestion and drift reporting."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import HardeningCheckOut, HardeningResultIn
from ..security import get_current_user, require_roles
from ..services import audit_service, hardening_service, kpi_service

router = APIRouter(prefix="/hardening", tags=["hardening"])


@router.get("/baseline")
def get_baseline(user: models.User = Depends(get_current_user)) -> dict:
    return hardening_service.load_baseline()


@router.get("/summary")
def get_summary(
    host_name: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> dict:
    return hardening_service.summary(db, host_name=host_name)


@router.get("/checks", response_model=list[HardeningCheckOut])
def list_checks(
    host_name: str | None = None,
    limit: int = Query(default=500, ge=1, le=2000),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[HardeningCheckOut]:
    checks = hardening_service.latest_checks(db, host_name=host_name)
    checks = sorted(checks, key=lambda item: (item.host_name, item.control))[:limit]
    return [HardeningCheckOut.model_validate(item) for item in checks]


@router.post("/results", response_model=list[HardeningCheckOut], status_code=201)
def ingest_results(
    payload: HardeningResultIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> list[HardeningCheckOut]:
    records = hardening_service.ingest_results(
        db, host_name=payload.host_name, checks=payload.checks
    )
    audit_service.record(
        db,
        actor=user,
        action="hardening.results.ingest",
        target_type="host",
        target_id=payload.host_name,
        data={"checks": len(records)},
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return [HardeningCheckOut.model_validate(item) for item in records]
