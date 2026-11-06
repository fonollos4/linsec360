"""Connection status and tests for external control planes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..schemas import IntegrationState, IntegrationStatus
from ..security import get_current_user, require_roles
from ..services import (
    audit_service,
    kpi_service,
    uyuni_service,
    wazuh_service,
)

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/status", response_model=IntegrationStatus)
def status(user: models.User = Depends(get_current_user)) -> IntegrationStatus:
    settings = get_settings()
    return IntegrationStatus(
        wazuh=IntegrationState(configured=settings.wazuh_configured),
        uyuni=IntegrationState(configured=settings.uyuni_configured),
    )


@router.post("/wazuh/test", response_model=IntegrationState)
def test_wazuh(
    user: models.User = Depends(require_roles("admin", "operator")),
) -> IntegrationState:
    settings = get_settings()
    if not settings.wazuh_configured:
        return IntegrationState(configured=False, reachable=False)
    try:
        wazuh_service.get_client().test_connection()
    except Exception as exc:
        return IntegrationState(
            configured=True, reachable=False, detail=str(exc)
        )
    return IntegrationState(configured=True, reachable=True)


@router.post("/uyuni/test", response_model=IntegrationState)
def test_uyuni(
    user: models.User = Depends(require_roles("admin", "operator")),
) -> IntegrationState:
    settings = get_settings()
    if not settings.uyuni_configured:
        return IntegrationState(configured=False, reachable=False)
    try:
        uyuni_service.get_client().test_connection()
    except Exception as exc:
        return IntegrationState(configured=True, reachable=False, detail=str(exc))
    return IntegrationState(configured=True, reachable=True)


@router.post("/wazuh/sync")
def sync_wazuh(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    agents = wazuh_service.sync_agents(db)
    alerts = wazuh_service.sync_alerts(db)
    vulnerabilities = wazuh_service.sync_vulnerabilities(db)
    result = {
        "agents": agents,
        "alerts": alerts,
        "vulnerabilities": vulnerabilities,
    }
    audit_service.record(
        db,
        actor=user,
        action="integrations.wazuh.sync",
        target_type="integration",
        target_id="wazuh",
        data=result,
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return result
