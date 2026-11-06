"""Wazuh agent coverage endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import AgentOut, AgentSummary, KpiItem
from ..security import get_current_user, require_roles
from ..services import audit_service, kpi_service, wazuh_service

router = APIRouter(prefix="/agents", tags=["detection"])


def _host_index(db: Session) -> tuple[dict[str, models.Host], dict[str, models.Host]]:
    hosts = db.query(models.Host).all()
    by_agent = {host.agent_id: host for host in hosts if host.agent_id}
    by_name = {host.name: host for host in hosts}
    return by_agent, by_name


def _agent_out(agent: dict, host: models.Host | None) -> AgentOut:
    return AgentOut(
        **agent,
        host_id=host.id if host else None,
    )


@router.get("", response_model=list[AgentOut])
def list_agents(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[AgentOut]:
    by_agent, by_name = _host_index(db)
    agents = wazuh_service.get_client().list_agents()
    return [
        _agent_out(
            agent,
            by_agent.get(agent["id"]) or by_name.get(agent["name"]),
        )
        for agent in agents
    ]


@router.get("/summary", response_model=AgentSummary)
def agent_summary(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> AgentSummary:
    agents = wazuh_service.get_client().list_agents()
    statuses = [str(agent.get("status") or "unknown").lower() for agent in agents]
    active = statuses.count("active")
    total = len(agents)
    total_hosts = db.query(models.Host).count()
    coverage = (active / total_hosts * 100) if total_hosts else None
    return AgentSummary(
        total=total,
        active=active,
        disconnected=statuses.count("disconnected"),
        pending=statuses.count("pending"),
        never_connected=statuses.count("never_connected"),
        coverage=KpiItem(
            value=float(coverage) if coverage is not None else None,
            status="ok" if coverage is not None else "unknown",
            source="wazuh",
        ),
    )


@router.post("/sync")
def sync_agents(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    result = wazuh_service.sync_agents(db)
    audit_service.record(
        db,
        actor=user,
        action="wazuh.agents.sync",
        target_type="integration",
        target_id="wazuh",
        data=result,
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return result
