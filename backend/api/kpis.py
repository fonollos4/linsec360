"""KPI endpoints with explicit unknown/stale states."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import KpiOverview
from ..security import get_current_user
from ..services import kpi_service

router = APIRouter(prefix="/kpis", tags=["kpis"])


@router.get("/overview", response_model=KpiOverview)
def overview(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> KpiOverview:
    return kpi_service.overview(db)
