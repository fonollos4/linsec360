"""Deployment endpoints and log retrieval."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db, session_scope
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


@router.post("/{deployment_id}/cancel", response_model=DeploymentOut)
def cancel_deployment(
    deployment_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> DeploymentOut:
    deployment = deployment_service.get_deployment(db, deployment_id)
    deployment = deployment_service.cancel_deployment(
        db, deployment=deployment, actor=user
    )
    return deployment_service.serialize(deployment)


@router.post("/{deployment_id}/retry", response_model=DeploymentOut, status_code=202)
def retry_deployment(
    deployment_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> DeploymentOut:
    deployment = deployment_service.get_deployment(db, deployment_id)
    replacement = deployment_service.retry_deployment(
        db, deployment=deployment, actor=user
    )
    return deployment_service.serialize(replacement)


@router.get("/{deployment_id}/events/stream")
async def stream_events(
    deployment_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> StreamingResponse:
    deployment = deployment_service.get_deployment(db, deployment_id)
    log_path = Path(deployment.log_path)

    async def generator():
        seen_event = 0
        log_offset = 0
        terminal = {"succeeded", "failed", "cancelled"}
        for _ in range(1800):  # hard cap: 30 minutes at one-second intervals
            with session_scope() as stream_db:
                current = stream_db.get(models.Deployment, deployment_id)
                if current is None:
                    yield "event: error\ndata: {\"message\":\"deployment removed\"}\n\n"
                    return
                events = (
                    stream_db.query(models.DeploymentEvent)
                    .filter(
                        models.DeploymentEvent.deployment_id == deployment_id,
                        models.DeploymentEvent.id > seen_event,
                    )
                    .order_by(models.DeploymentEvent.id)
                    .all()
                )
                for event in events:
                    seen_event = event.id
                    payload = {
                        "event": event.event,
                        "level": event.level,
                        "message": event.message,
                        "data": event.data,
                        "created_at": event.created_at.isoformat(),
                    }
                    yield (
                        "event: deployment\n"
                        f"data: {json.dumps(payload)}\n\n"
                    )
                status = current.status

            if log_path.exists():
                with log_path.open("rb") as handle:
                    handle.seek(log_offset)
                    chunk = handle.read()
                    log_offset = handle.tell()
                if chunk:
                    text = chunk.decode("utf-8", errors="replace")
                    for line in text.splitlines():
                        yield f"event: log\ndata: {json.dumps(line)}\n\n"

            if status in terminal:
                yield f"event: done\ndata: {json.dumps({'status': status})}\n\n"
                return
            yield "event: ping\ndata: {}\n\n"
            await asyncio.sleep(1)

        yield "event: timeout\ndata: {}\n\n"

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
