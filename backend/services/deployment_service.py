"""Deployment lifecycle: resolve targets, persist the job, enqueue the worker."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..errors import DomainError, NotFoundError
from ..schemas import DeploymentCreate, DeploymentOut
from . import audit_service, inventory_service, playbook_service


def _now() -> datetime:
    return datetime.now(UTC)


def resolve_targets(
    db: Session,
    *,
    environment_name: str,
    host_names: list[str],
    group: str | None,
) -> list[models.Host]:
    environment = inventory_service.get_environment(db, environment_name)
    query = db.query(models.Host).filter(models.Host.environment_id == environment.id)

    if group is not None:
        query = query.filter(models.Host.groups.any(models.HostGroup.name == group))
        hosts = query.order_by(models.Host.name).all()
    elif host_names:
        hosts = query.filter(models.Host.name.in_(host_names)).all()
        found = {host.name for host in hosts}
        missing = set(host_names) - found
        if missing:
            raise DomainError(
                "hosts not found in environment: " + ", ".join(sorted(missing))
            )
        by_name = {host.name: host for host in hosts}
        hosts = [by_name[name] for name in host_names]
    else:
        hosts = query.order_by(models.Host.name).all()

    if not hosts:
        raise DomainError("no hosts match the deployment target")
    return hosts


def create_deployment(
    db: Session,
    *,
    payload: DeploymentCreate,
    actor: models.User,
) -> models.Deployment:
    settings = get_settings()
    environment = inventory_service.get_environment(db, payload.environment)
    playbook = playbook_service.get_by_filename(db, payload.playbook)
    if playbook is None:
        raise NotFoundError("playbook not found")
    if not playbook.is_allowlisted:
        raise DomainError("playbook is not allowlisted")

    targets = resolve_targets(
        db,
        environment_name=payload.environment,
        host_names=payload.hosts,
        group=payload.group,
    )

    deployment_id = str(uuid.uuid4())
    settings.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    deployment = models.Deployment(
        id=deployment_id,
        playbook_id=playbook.id,
        playbook_name=playbook.filename,
        environment_id=environment.id,
        environment_name=environment.name,
        status="queued",
        requested_by_id=actor.id,
        log_path=str(settings.log_dir / f"deploy-{deployment_id}.log"),
        extra_vars={"linsec_env": environment.name},
    )
    deployment.targets = [
        models.DeploymentTarget(
            host_id=host.id,
            host_name=host.name,
            status="pending",
        )
        for host in targets
    ]
    deployment.events.append(
        models.DeploymentEvent(
            level="info",
            event="deployment_queued",
            message=f"Queued {playbook.filename} for {len(targets)} host(s)",
            data={"hosts": [host.name for host in targets]},
        )
    )
    db.add(deployment)

    for host in targets:
        host.status = "deploying"

    audit_service.record(
        db,
        actor=actor,
        action="deployment.create",
        target_type="deployment",
        target_id=deployment_id,
        data={
            "environment": environment.name,
            "playbook": playbook.filename,
            "hosts": [host.name for host in targets],
        },
    )
    db.commit()
    db.refresh(deployment)

    try:
        from ..queue import get_queue

        get_queue().enqueue_deployment(deployment_id)
    except Exception as exc:  # pragma: no cover - depends on queue backend
        deployment.status = "failed"
        deployment.finished_at = _now()
        deployment.error_message = "unable to enqueue deployment"
        deployment.events.append(
            models.DeploymentEvent(
                level="error",
                event="deployment_enqueue_failed",
                message=str(exc),
            )
        )
        db.commit()
        raise DomainError("unable to enqueue deployment") from exc

    return deployment


def get_deployment(db: Session, deployment_id: str) -> models.Deployment:
    deployment = db.get(models.Deployment, deployment_id)
    if deployment is None:
        raise NotFoundError("deployment not found")
    return deployment


def list_deployments(
    db: Session,
    *,
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> list[models.Deployment]:
    query = db.query(models.Deployment)
    if status:
        query = query.filter(models.Deployment.status == status)
    return (
        query.order_by(models.Deployment.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def target_names(deployment: models.Deployment) -> list[str]:
    return [target.host_name for target in deployment.targets]


def serialize(deployment: models.Deployment) -> DeploymentOut:
    return DeploymentOut(
        id=deployment.id,
        environment=deployment.environment_name,
        playbook=deployment.playbook_name,
        target_hosts=target_names(deployment),
        status=deployment.status,
        created_at=deployment.created_at,
        started_at=deployment.started_at,
        finished_at=deployment.finished_at,
        error_message=deployment.error_message,
        log_url=f"/api/v1/deployments/{deployment.id}/log",
    )


def log_path(deployment: models.Deployment) -> Path:
    return Path(deployment.log_path)
