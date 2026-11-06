"""Ansible deployment worker shared by the thread and RQ backends."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .. import models
from ..config import get_settings
from ..db import session_scope
from ..services import inventory_service, playbook_service

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def _write_extra_vars(values: dict, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, path = tempfile.mkstemp(
        prefix="linsec-deploy-",
        suffix=".yml",
        dir=directory,
    )
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        yaml.safe_dump(values, handle)
    return Path(path)


def _build_command(
    *,
    playbook_path: Path,
    inventory_path: Path,
    env_vars_path: Path,
    host_vars_path: Path,
    target_hosts: list[str],
) -> list[str]:
    settings = get_settings()
    return [
        settings.ansible_playbook_bin,
        "-i",
        str(inventory_path),
        str(playbook_path),
        "--extra-vars",
        f"@{env_vars_path}",
        "--extra-vars",
        f"@{host_vars_path}",
        "--limit",
        ",".join(target_hosts),
    ]


def _append_log(log_path: Path, text: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        log_path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(text)


def run_deployment(deployment_id: str) -> None:
    """Execute a queued deployment. Safe to call from a thread or RQ worker."""
    settings = get_settings()
    with session_scope() as db:
        deployment = db.get(models.Deployment, deployment_id)
        if deployment is None:
            logger.error("deployment %s not found", deployment_id)
            return
        if deployment.status != "queued":
            logger.info(
                "deployment %s is %s; skipping",
                deployment_id,
                deployment.status,
            )
            return

        deployment.status = "running"
        deployment.started_at = _now()
        deployment.events.append(
            models.DeploymentEvent(
                level="info",
                event="deployment_started",
                message="Ansible execution started",
            )
        )
        db.commit()

        target_names = [target.host_name for target in deployment.targets]
        log_path = Path(deployment.log_path)
        temporary_paths: list[Path] = []
        success = False
        error_message: str | None = None

        try:
            if not target_names:
                raise RuntimeError("deployment has no target hosts")
            playbook = playbook_service.get_or_raise(db, deployment.playbook_name)
            playbook_path = playbook_service.materialize(
                playbook, settings.playbooks_dir
            )
            inventory_path = inventory_service.write_inventory(
                db, deployment.environment_name
            )
            env_vars_path = _write_extra_vars(
                {"linsec_env": deployment.environment_name},
                settings.log_dir,
            )
            host_vars_path = _write_extra_vars(
                {"target_hosts": target_names},
                settings.log_dir,
            )
            temporary_paths.extend([env_vars_path, host_vars_path])

            command = _build_command(
                playbook_path=playbook_path,
                inventory_path=inventory_path,
                env_vars_path=env_vars_path,
                host_vars_path=host_vars_path,
                target_hosts=target_names,
            )

            _append_log(
                log_path,
                "job_id={} environment={} playbook={} hosts={}\n".format(
                    deployment.id,
                    deployment.environment_name,
                    deployment.playbook_name,
                    ",".join(target_names),
                ),
            )
            descriptor = os.open(log_path, os.O_WRONLY | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as log:
                process = subprocess.run(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    cwd=str(settings.taskengine_dir),
                    check=False,
                    text=True,
                )
            _append_log(
                log_path,
                f"\nfinished_at={_now().isoformat()} return_code={process.returncode}\n",
            )
            success = process.returncode == 0
            if not success:
                error_message = (
                    f"ansible-playbook exited with code {process.returncode}"
                )
        except Exception as exc:
            success = False
            error_message = "deployment execution failed"
            logger.exception("deployment %s failed", deployment_id)
            try:
                _append_log(log_path, f"\nerror={exc}\n")
            except OSError:
                logger.exception("could not write failure to %s", log_path)
        finally:
            for path in temporary_paths:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    logger.warning("could not remove temporary file %s", path)

        deployment.status = "succeeded" if success else "failed"
        deployment.finished_at = _now()
        deployment.error_message = error_message
        for target in deployment.targets:
            target.status = "succeeded" if success else "failed"
            if target.host_id is not None:
                host = db.get(models.Host, target.host_id)
                if host is not None:
                    host.status = "secured" if success else "error"
        deployment.events.append(
            models.DeploymentEvent(
                level="info" if success else "error",
                event="deployment_finished",
                message=(
                    "Ansible execution completed"
                    if success
                    else (error_message or "Ansible execution failed")
                ),
                data={"success": success, "hosts": target_names},
            )
        )
