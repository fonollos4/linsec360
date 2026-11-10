"""Ansible deployment worker shared by the thread and RQ backends."""

from __future__ import annotations

import contextlib
import logging
import os
import shlex
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .. import models
from ..config import get_settings
from ..db import session_scope
from ..errors import IntegrationUnavailable
from ..services import (
    credential_service,
    inventory_service,
    playbook_service,
    ssh_service,
)

logger = logging.getLogger(__name__)


class DeploymentPreflightError(RuntimeError):
    """A deployment was blocked before Ansible could connect to any host."""


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


def _write_known_hosts(
    db,
    environment_name: str,
    target_names: list[str],
    directory: Path,
) -> Path:
    environment = inventory_service.get_environment(db, environment_name)
    hosts = (
        db.query(models.Host)
        .filter(
            models.Host.environment_id == environment.id,
            models.Host.name.in_(target_names),
        )
        .all()
    )
    hosts_by_name = {host.name: host for host in hosts}
    entries: list[str] = []
    for name in target_names:
        host = hosts_by_name.get(name)
        if host is None:
            raise DeploymentPreflightError(
                f"target host {name} was not found in the environment"
            )
        if not host.ssh_fingerprint:
            raise DeploymentPreflightError(
                f"target host {name} has no approved SSH fingerprint; "
                "verify and approve it before deployment"
            )
        scanned = ssh_service.scan_host_key(
            host.ip,
            host.ansible_port,
            expected_fingerprint=host.ssh_fingerprint,
        )
        if scanned is None:
            raise DeploymentPreflightError(
                f"could not scan the SSH fingerprint for {name}"
            )
        known_hosts_entry, fingerprint = scanned
        if fingerprint != host.ssh_fingerprint:
            raise DeploymentPreflightError(
                f"SSH fingerprint for {name} changed; verify and approve it "
                "before deployment"
            )
        entries.append(known_hosts_entry)

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, path = tempfile.mkstemp(
        prefix="linsec-known-hosts-",
        dir=directory,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(entries) + "\n")
    except Exception:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        Path(path).unlink(missing_ok=True)
        raise
    return Path(path)


def _deployment_passwords(
    db,
    environment_name: str,
    target_names: list[str],
) -> dict[str, str]:
    environment = inventory_service.get_environment(db, environment_name)
    hosts = (
        db.query(models.Host)
        .filter(
            models.Host.environment_id == environment.id,
            models.Host.name.in_(target_names),
        )
        .all()
    )
    passwords: dict[str, str] = {}
    for host in hosts:
        if host.ansible_password_encrypted is None:
            continue
        try:
            passwords[host.name] = credential_service.decrypt_password(
                host.ansible_password_encrypted
            )
        except IntegrationUnavailable as exc:
            raise DeploymentPreflightError(
                f"stored Ansible credentials for {host.name} could not be decrypted; "
                "verify LINSEC_CREDENTIAL_ENCRYPTION_KEY"
            ) from exc
    return passwords


def _ansible_environment(settings) -> dict[str, str]:
    """Environment that lets materialized playbooks find roles and config.

    Playbooks are materialized under ``var/playbooks`` while roles and the
    hardening/OpenSCAP assets live in the repository, so both are injected
    explicitly instead of relying on whatever ansible.cfg is installed.
    """
    environment = os.environ.copy()
    roles_path = os.pathsep.join(
        str(path) for path in settings.ansible_roles_paths if path
    )
    environment["ANSIBLE_ROLES_PATH"] = roles_path
    environment["ANSIBLE_NOCOLOR"] = "1"
    if settings.ansible_config_path:
        environment["ANSIBLE_CONFIG"] = str(settings.ansible_config_path)
    elif (settings.taskengine_dir / "playbooks" / "ansible.cfg").is_file():
        environment["ANSIBLE_CONFIG"] = str(
            settings.taskengine_dir / "playbooks" / "ansible.cfg"
        )
    return environment


def _build_command(
    *,
    playbook_path: Path,
    inventory_path: Path,
    env_vars_path: Path,
    host_vars_path: Path,
    target_hosts: list[str],
    check_mode: bool = False,
) -> list[str]:
    settings = get_settings()
    command = [
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
    if check_mode:
        command.append("--check")
    return command


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

        if deployment.cancel_requested:
            deployment.status = "cancelled"
            deployment.cancelled_at = _now()
            deployment.finished_at = _now()
            deployment.events.append(
                models.DeploymentEvent(
                    level="info",
                    event="deployment_cancelled",
                    message="Cancelled before execution",
                )
            )
            db.commit()
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
            try:
                ssh_service.ensure_keypair()
            except (IntegrationUnavailable, OSError, subprocess.SubprocessError) as exc:
                raise DeploymentPreflightError(
                    "Configured Ansible SSH private key is unavailable or invalid; "
                    "check its path and permissions, or run "
                    "config/scripts/generate-ansible-key.sh for the default key"
                ) from exc
            known_hosts_path = _write_known_hosts(
                db,
                deployment.environment_name,
                target_names,
                settings.log_dir,
            )
            temporary_paths.append(known_hosts_path)
            playbook = playbook_service.get_or_raise(db, deployment.playbook_name)
            playbook_path = playbook_service.materialize(
                playbook, settings.playbooks_dir
            )
            inventory_path = inventory_service.write_deployment_inventory(
                db,
                deployment.environment_name,
                _deployment_passwords(
                    db,
                    deployment.environment_name,
                    target_names,
                ),
                Path(tempfile.gettempdir()),
            )
            temporary_paths.append(inventory_path)
            settings.artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            env_vars_path = _write_extra_vars(
                {
                    "linsec_env": deployment.environment_name,
                    "linsec_config_dir": str(settings.config_dir),
                    "linsec_artifact_dir": str(settings.artifacts_dir),
                    "linsec_wazuh_manager_address": (
                        settings.effective_wazuh_manager_address
                    ),
                    **deployment.extra_vars,
                },
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
                check_mode=bool(deployment.extra_vars.get("linsec_check_mode")),
            )
            environment = _ansible_environment(settings)
            environment["ANSIBLE_HOST_KEY_CHECKING"] = "True"
            environment["ANSIBLE_SSH_ARGS"] = (
                f"-o UserKnownHostsFile={shlex.quote(str(known_hosts_path))} "
                "-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null"
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
                    env=environment,
                    check=False,
                    text=True,
                    timeout=settings.deployment_timeout_seconds,
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
        except DeploymentPreflightError as exc:
            success = False
            error_message = str(exc)
            logger.warning("deployment %s blocked by preflight: %s", deployment_id, exc)
            try:
                _append_log(log_path, f"\nerror={error_message}\n")
            except OSError:
                logger.exception("could not write preflight failure to %s", log_path)
        except subprocess.TimeoutExpired as exc:
            success = False
            error_message = (
                f"ansible-playbook exceeded {settings.deployment_timeout_seconds}s"
            )
            try:
                _append_log(log_path, f"\n{error_message}\n")
            except OSError:
                logger.exception("could not write timeout to %s", log_path)
            logger.warning("deployment %s timed out: %s", deployment_id, exc)
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

        try:
            db.refresh(deployment)
        except Exception:  # pragma: no cover - defensive refresh
            logger.exception("could not refresh deployment %s", deployment_id)
        cancelled = bool(deployment.cancel_requested)
        if cancelled:
            deployment.status = "cancelled"
            deployment.cancelled_at = _now()
            deployment.finished_at = _now()
            deployment.error_message = "cancelled by operator"
            for target in deployment.targets:
                target.status = "cancelled"
                if target.host_id is not None:
                    host = db.get(models.Host, target.host_id)
                    if host is not None and host.status == "deploying":
                        host.status = "pending"
            deployment.events.append(
                models.DeploymentEvent(
                    level="info",
                    event="deployment_cancelled",
                    message="Deployment cancelled by operator",
                    data={"hosts": target_names},
                )
            )
            db.commit()
            return

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
