"""Host inventory endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import HostCreate, HostOut, HostUpdate, Message
from ..security import get_current_user, require_roles
from ..services import host_service

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=list[HostOut])
def list_hosts(
    environment: str | None = None,
    status: str | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[HostOut]:
    hosts = host_service.list_hosts(
        db,
        environment=environment,
        status=status,
        query=q,
        limit=limit,
        offset=offset,
    )
    return [host_service.serialize(host) for host in hosts]


@router.post("", response_model=HostOut, status_code=201)
def create_host(
    payload: HostCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> HostOut:
    host = host_service.create_host(db, payload=payload, actor=user, request=request)
    return host_service.serialize(host)


@router.get("/{host_id}", response_model=HostOut)
def get_host(
    host_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> HostOut:
    return host_service.serialize(host_service.get_host(db, host_id))


@router.patch("/{host_id}", response_model=HostOut)
def update_host(
    host_id: int,
    payload: HostUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> HostOut:
    host = host_service.get_host(db, host_id)
    host = host_service.update_host(
        db, host=host, payload=payload, actor=user, request=request
    )
    return host_service.serialize(host)


@router.delete("/{host_id}", response_model=Message)
def delete_host(
    host_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> Message:
    host = host_service.get_host(db, host_id)
    name = host.name
    host_service.delete_host(db, host=host, actor=user, request=request)
    return Message(message=f"host {name} deleted")
