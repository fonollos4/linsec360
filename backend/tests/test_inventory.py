from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from backend import models
from backend.config import get_settings
from backend.db import session_scope
from backend.errors import NotFoundError
from backend.services import inventory_service
from backend.services.inventory_service import (
    build_inventory,
    write_deployment_inventory,
    write_inventory,
)


def _seed() -> None:
    with session_scope() as db:
        environment = models.Environment(name="production")
        web = models.HostGroup(name="web")
        database = models.HostGroup(name="database")
        db.add_all([environment, web, database])
        db.flush()
        db.add(
            models.Host(
                name="web01",
                ip="10.0.0.10",
                environment=environment,
                security_level="high",
                groups=[web],
            )
        )
        db.add(
            models.Host(
                name="db01",
                ip="10.0.0.20",
                environment=environment,
                security_level="critical",
                groups=[database],
            )
        )
        db.add(
            models.Host(
                name="lonely",
                ip="10.0.0.30",
                environment=environment,
                security_level="low",
            )
        )


def test_build_inventory_groups_hosts(client):
    _seed()
    with session_scope() as db:
        hosts = db.query(models.Host).order_by(models.Host.name).all()
        inventory = build_inventory(hosts)

    children = inventory["all"]["children"]
    assert "web" in children
    assert children["web"]["hosts"]["web01"]["ansible_host"] == "10.0.0.10"
    assert children["web"]["hosts"]["web01"]["linsec_security_level"] == "high"
    assert "db01" in children["database"]["hosts"]
    assert "lonely" in children["ungrouped"]["hosts"]


def test_build_inventory_uses_configured_ssh_key_path(
    client, monkeypatch, tmp_path: Path
):
    _seed()
    key_path = tmp_path / "ansible-key"
    monkeypatch.setattr(
        inventory_service,
        "get_settings",
        lambda: SimpleNamespace(ansible_ssh_private_key_path=key_path),
    )
    with session_scope() as db:
        hosts = db.query(models.Host).order_by(models.Host.name).all()
        inventory = build_inventory(hosts)

    assert (
        inventory["all"]["children"]["web"]["hosts"]["web01"][
            "ansible_private_key_file"
        ]
        == str(key_path)
    )


def test_build_inventory_uses_password_for_ssh_and_sudo_without_key(
    client, monkeypatch, tmp_path: Path
):
    _seed()
    key_path = tmp_path / "ansible-key"
    monkeypatch.setattr(
        inventory_service,
        "get_settings",
        lambda: SimpleNamespace(ansible_ssh_private_key_path=key_path),
    )
    with session_scope() as db:
        hosts = db.query(models.Host).order_by(models.Host.name).all()
        inventory = build_inventory(hosts, {"web01": "temporary-secret"})

    web_host = inventory["all"]["children"]["web"]["hosts"]["web01"]
    database_host = inventory["all"]["children"]["database"]["hosts"]["db01"]
    assert web_host["ansible_password"] == "temporary-secret"
    assert web_host["ansible_become_password"] == "temporary-secret"
    assert "ansible_private_key_file" not in web_host
    assert database_host["ansible_private_key_file"] == str(key_path)


def test_write_deployment_inventory_keeps_password_file_private(client, tmp_path: Path):
    _seed()
    with session_scope() as db:
        path = write_deployment_inventory(
            db,
            "production",
            {"web01": "temporary-secret"},
            tmp_path,
        )
        persistent_path = write_inventory(db, "production")

    assert path.stat().st_mode & 0o777 == 0o600
    content = yaml.safe_load(path.read_text())
    web_host = content["all"]["children"]["web"]["hosts"]["web01"]
    assert web_host["ansible_password"] == "temporary-secret"
    persistent_content = yaml.safe_load(persistent_path.read_text())
    persistent_web_host = persistent_content["all"]["children"]["web"]["hosts"]["web01"]
    assert "ansible_password" not in persistent_web_host
    assert "temporary-secret" not in persistent_path.read_text()


def test_write_inventory_creates_private_yaml(client):
    _seed()
    with session_scope() as db:
        path = write_inventory(db, "production")

    assert path.exists()
    assert path.stat().st_mode & 0o777 == 0o600
    content = yaml.safe_load(path.read_text())
    assert "production" not in content
    assert "web01" in content["all"]["children"]["web"]["hosts"]
    assert path.parent == get_settings().inventories_dir / "production"


def test_write_inventory_unknown_environment(client):
    with session_scope() as db, pytest.raises(NotFoundError):
        write_inventory(db, "missing")
