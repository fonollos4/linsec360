"""Generate Ansible inventories from the database (single source of truth)."""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..errors import NotFoundError


def build_inventory(
    hosts: list[models.Host],
    passwords_by_name: Mapping[str, str] | None = None,
) -> dict:
    private_key_path = str(get_settings().ansible_ssh_private_key_path)
    children: dict[str, dict] = {}
    for host in hosts:
        group_names = [group.name for group in host.groups] or ["ungrouped"]
        for group_name in group_names:
            group = children.setdefault(group_name, {"hosts": {}})
            host_vars = {
                "ansible_host": host.ip,
                "ansible_user": host.ansible_user,
                "ansible_port": host.ansible_port,
                "ansible_private_key_file": private_key_path,
                "linsec_security_level": host.security_level,
            }
            password = (passwords_by_name or {}).get(host.name)
            if password is not None:
                host_vars.pop("ansible_private_key_file")
                host_vars["ansible_password"] = password
                host_vars["ansible_become_password"] = password
            group["hosts"][host.name] = host_vars
    return {"all": {"children": children}}


def get_environment(db: Session, name: str) -> models.Environment:
    environment = (
        db.query(models.Environment)
        .filter(models.Environment.name == name)
        .one_or_none()
    )
    if environment is None:
        raise NotFoundError("environment not found")
    return environment


def write_inventory(db: Session, environment_name: str) -> Path:
    settings = get_settings()
    environment = get_environment(db, environment_name)
    hosts = (
        db.query(models.Host)
        .filter(models.Host.environment_id == environment.id)
        .order_by(models.Host.name)
        .all()
    )

    directory = settings.inventories_dir / environment_name
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "hosts.yml"

    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".hosts-",
        suffix=".yml",
        dir=directory,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                build_inventory(hosts),
                handle,
                default_flow_style=False,
                sort_keys=False,
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary_path)
        raise
    return path


def write_deployment_inventory(
    db: Session,
    environment_name: str,
    passwords_by_name: Mapping[str, str],
    directory: Path,
) -> Path:
    environment = get_environment(db, environment_name)
    hosts = (
        db.query(models.Host)
        .filter(models.Host.environment_id == environment.id)
        .order_by(models.Host.name)
        .all()
    )
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, path = tempfile.mkstemp(
        prefix="linsec-inventory-",
        suffix=".yml",
        dir=directory,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                build_inventory(hosts, passwords_by_name),
                handle,
                default_flow_style=False,
                sort_keys=False,
            )
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        raise
    return Path(path)
