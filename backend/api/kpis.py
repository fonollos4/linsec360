"""KPI endpoints with explicit unknown/stale states."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import KpiOverview, KpiSnapshotOut
from ..security import get_current_user
from ..services import kpi_service

router = APIRouter(prefix="/kpis", tags=["kpis"])


@router.get("/overview", response_model=KpiOverview)
def overview(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> KpiOverview:
    return kpi_service.overview(db)


@router.get("/history", response_model=list[KpiSnapshotOut])
def history(
    metric: str | None = Query(default=None, max_length=64),
    days: int = Query(default=30, ge=1, le=3650),
    limit: int = Query(default=1000, ge=1, le=10000),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[KpiSnapshotOut]:
    snapshots = kpi_service.history(
        db, metric=metric, days=days, limit=limit
    )
    return [
        KpiSnapshotOut.model_validate(snapshot) for snapshot in snapshots
    ]
