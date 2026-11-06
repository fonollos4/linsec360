"""Deployment endpoints and log retrieval."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..errors import ForbiddenError
from ..schemas import (
    DeploymentCreate,
    DeploymentEventOut,
    DeploymentOut,
)
from ..security import get_current_user, require_roles
from ..services import deployment_service

router = APIRouter(prefix="/deployments", tags=["deployments"])

LOG_TAIL_BYTES = 256 * 1024


@router.get("", response_model=list[DeploymentOut])
def list_deployments(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[DeploymentOut]:
    deployments = deployment_service.list_deployments(
        db, limit=limit, offset=offset, status=status
    )
    return [deployment_service.serialize(item) for item in deployments]


@router.post("", response_model=DeploymentOut, status_code=202)
def create_deployment(
    payload: DeploymentCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> DeploymentOut:
    deployment = deployment_service.create_deployment(db, payload=payload, actor=user)
    return deployment_service.serialize(deployment)


@router.get("/{deployment_id}", response_model=DeploymentOut)
def get_deployment(
    deployment_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> DeploymentOut:
    return deployment_service.serialize(
        deployment_service.get_deployment(db, deployment_id)
    )


@router.get("/{deployment_id}/events", response_model=list[DeploymentEventOut])
def get_events(
    deployment_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[DeploymentEventOut]:
    deployment = deployment_service.get_deployment(db, deployment_id)
    return [
        DeploymentEventOut.model_validate(event)
        for event in sorted(deployment.events, key=lambda item: item.id)
    ]


@router.get("/{deployment_id}/log", response_class=PlainTextResponse)
def get_log(
    deployment_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> PlainTextResponse:
    deployment = deployment_service.get_deployment(db, deployment_id)
    log_root = get_settings().log_dir.resolve()
    path = Path(deployment.log_path).resolve()
    if not path.is_relative_to(log_root):
        raise ForbiddenError("log path is outside the configured log directory")
    if not path.exists():
        return PlainTextResponse("")

    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > LOG_TAIL_BYTES:
            handle.seek(size - LOG_TAIL_BYTES)
        data = handle.read()
    return PlainTextResponse(data.decode("utf-8", errors="replace"))
