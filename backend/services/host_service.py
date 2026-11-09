"""Host inventory business logic."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models
from ..errors import ConflictError, NotFoundError
from ..schemas import HostCreate, HostOut, HostUpdate
from . import audit_service


def _get_or_create_environment(db: Session, name: str) -> models.Environment:
    environment = (
        db.query(models.Environment)
        .filter(models.Environment.name == name)
        .one_or_none()
    )
    if environment is None:
        environment = models.Environment(name=name)
        db.add(environment)
        db.flush()
    return environment


def _get_or_create_groups(db: Session, names: list[str]) -> list[models.HostGroup]:
    groups: list[models.HostGroup] = []
    for name in names:
        group = (
            db.query(models.HostGroup)
            .filter(models.HostGroup.name == name)
            .one_or_none()
        )
        if group is None:
            group = models.HostGroup(name=name)
            db.add(group)
            db.flush()
        groups.append(group)
    return groups


def serialize(host: models.Host) -> HostOut:
    return HostOut(
        id=host.id,
        name=host.name,
        ip=host.ip,
        environment=host.environment.name,
        security_level=host.security_level,
        groups=sorted(group.name for group in host.groups),
        status=host.status,
        agent_id=host.agent_id,
        os=host.os,
        last_seen=host.last_seen,
        added_date=host.added_date,
        ansible_user=host.ansible_user,
        ansible_port=host.ansible_port,
        ssh_status=host.ssh_status,
        ssh_fingerprint=host.ssh_fingerprint,
        ssh_error=host.ssh_error,
        last_ssh_test_at=host.last_ssh_test_at,
    )


def list_hosts(
    db: Session,
    *,
    environment: str | None = None,
    status: str | None = None,
    query: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[models.Host]:
    statement = db.query(models.Host).join(models.Environment)
    if environment:
        statement = statement.filter(models.Environment.name == environment)
    if status:
        statement = statement.filter(models.Host.status == status)
    if query:
        pattern = f"%{query}%"
        statement = statement.filter(
            or_(
                models.Host.name.ilike(pattern),
                models.Host.ip.ilike(pattern),
            )
        )
    return (
        statement.order_by(models.Host.added_date.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_host(db: Session, host_id: int) -> models.Host:
    host = db.get(models.Host, host_id)
    if host is None:
        raise NotFoundError("host not found")
    return host


def create_host(
    db: Session,
    *,
    payload: HostCreate,
    actor: models.User,
    request: Request | None = None,
) -> models.Host:
    environment = _get_or_create_environment(db, payload.environment)
    existing = (
        db.query(models.Host)
        .filter(
            models.Host.name == payload.name,
            models.Host.environment_id == environment.id,
        )
        .one_or_none()
    )
    if existing is not None:
        raise ConflictError("host already exists in this environment")

    host = models.Host(
        name=payload.name,
        ip=payload.ip,
        environment=environment,
        security_level=payload.security_level,
        status=payload.status,
        groups=_get_or_create_groups(db, payload.groups),
        ansible_user=payload.ansible_user,
        ansible_port=payload.ansible_port,
        ssh_fingerprint=payload.ssh_fingerprint,
    )
    db.add(host)
    audit_service.record(
        db,
        actor=actor,
        action="host.create",
        target_type="host",
        target_id=payload.name,
        data={
            "ip": payload.ip,
            "environment": payload.environment,
            "groups": payload.groups,
        },
        request=request,
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("host already exists") from exc
    db.refresh(host)
    return host


def update_host(
    db: Session,
    *,
    host: models.Host,
    payload: HostUpdate,
    actor: models.User,
    request: Request | None = None,
) -> models.Host:
    if payload.ip is not None:
        host.ip = payload.ip
    if payload.security_level is not None:
        host.security_level = payload.security_level
    if payload.status is not None:
        host.status = payload.status
    if payload.ansible_user is not None:
        host.ansible_user = payload.ansible_user
    if payload.ansible_port is not None:
        host.ansible_port = payload.ansible_port
    if payload.groups is not None:
        host.groups = _get_or_create_groups(db, payload.groups)

    audit_service.record(
        db,
        actor=actor,
        action="host.update",
        target_type="host",
        target_id=host.id,
        data=payload.model_dump(exclude_unset=True),
        request=request,
    )
    db.commit()
    db.refresh(host)
    return host


def delete_host(
    db: Session,
    *,
    host: models.Host,
    actor: models.User,
    request: Request | None = None,
) -> None:
    audit_service.record(
        db,
        actor=actor,
        action="host.delete",
        target_type="host",
        target_id=host.id,
        data={"name": host.name, "environment": host.environment.name},
        request=request,
    )
    db.delete(host)
    db.commit()
