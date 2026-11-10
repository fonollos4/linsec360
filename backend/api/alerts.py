"""Detection alerts from the Wazuh indexer."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import ActiveResponseRequest, AlertOut
from ..security import get_current_user, require_roles
from ..services import (
    alert_service,
    audit_service,
    kpi_service,
    runtime_configuration_service,
    wazuh_service,
)

router = APIRouter(prefix="/alerts", tags=["detection"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    severity: str | None = None,
    acknowledged: bool | None = None,
    agent_name: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[AlertOut]:
    alerts = alert_service.list_alerts(
        db,
        severity=severity,
        acknowledged=acknowledged,
        agent_name=agent_name,
        limit=limit,
        offset=offset,
    )
    return [AlertOut.model_validate(alert) for alert in alerts]


@router.get("/summary")
def alert_summary(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> dict:
    alerts = db.query(models.Alert).all()
    detected = [
        (alert.created_at - alert.timestamp).total_seconds() / 3600
        for alert in alerts
        if alert.created_at is not None and alert.timestamp is not None
    ]
    responded = [
        (alert.acknowledged_at - alert.timestamp).total_seconds() / 3600
        for alert in alerts
        if alert.acknowledged_at is not None and alert.timestamp is not None
    ]
    return {
        "by_severity": alert_service.severity_counts(db),
        "unacknowledged": alert_service.severity_counts(
            db, unacknowledged_only=True
        ),
        "mean_time_to_detect_hours": (
            round(sum(detected) / len(detected), 2) if detected else None
        ),
        "mean_time_to_respond_hours": (
            round(sum(responded) / len(responded), 2) if responded else None
        ),
    }


@router.post("/sync")
def sync_alerts(
    request: Request,
    limit: int = Query(default=500, ge=1, le=2000),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    result = wazuh_service.sync_alerts(db, limit=limit)
    audit_service.record(
        db,
        actor=user,
        action="wazuh.alerts.sync",
        target_type="integration",
        target_id="wazuh",
        data=result,
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return result


@router.post("/{alert_id}/active-response", response_model=dict)
def active_response(
    alert_id: int,
    payload: ActiveResponseRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    alert = alert_service.get_alert(db, alert_id)
    if not alert.agent_id:
        return {"status": "rejected", "reason": "alert has no Wazuh agent ID"}
    allowed = {"firewall-drop", "disable-account"}
    if payload.action not in allowed:
        return {"status": "rejected", "reason": "action is not allowlisted"}
    settings = runtime_configuration_service.effective_settings(db)
    result = wazuh_service.get_client(settings=settings).active_response(
        agent_id=alert.agent_id,
        action=payload.action,
        alert_id=alert.alert_id,
    )
    audit_service.record(
        db,
        actor=user,
        action="alert.active_response",
        target_type="alert",
        target_id=str(alert.id),
        data={"action": payload.action, "agent_id": alert.agent_id},
        request=request,
    )
    db.commit()
    return {"status": "submitted", "action": payload.action, "result": result}


@router.post("/{alert_id}/ack", response_model=AlertOut)
def acknowledge_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator", "auditor")),
) -> AlertOut:
    alert = alert_service.get_alert(db, alert_id)
    alert = alert_service.acknowledge(db, alert=alert, username=user.username)
    audit_service.record(
        db,
        actor=user,
        action="alert.acknowledge",
        target_type="alert",
        target_id=str(alert.id),
        data={"alert_id": alert.alert_id},
        request=request,
    )
    db.commit()
    return AlertOut.model_validate(alert)
