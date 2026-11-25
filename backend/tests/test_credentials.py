"""Regression tests for host credential encryption and graceful degradation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend import models
from backend.config import Settings
from backend.db import session_scope
from backend.services import credential_service

from .conftest import create_host, create_playbook

SCRIPTS = Path(__file__).resolve().parents[2] / "config" / "scripts"


def _load_module(name: str, path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_credential_key_is_accepted_by_fernet(tmp_path: Path):
    module = _load_module("linsec_key_generation", SCRIPTS / "init-wazuh-env.py")
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "LINSEC_SECRET_KEY=secret",
                "LINSEC_CREDENTIAL_ENCRYPTION_KEY=",
                "WAZUH_ADMIN_PASSWORD='AdminPass1!'",
                "WAZUH_DASHBOARD_PASSWORD='Dashboard1!'",
                "WAZUH_API_USERNAME=wazuh-wui",
                "WAZUH_API_PASSWORD='ApiPass1!'",
                "POSTGRES_PASSWORD=postgrespass",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    module.initialize(env_file)
    values = dict(
        line.split("=", 1)
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    key = values["LINSEC_CREDENTIAL_ENCRYPTION_KEY"].strip().strip("'\"")

    # A 43-character token_urlsafe(32) value is rejected by Fernet; the
    # generated key must be a padded, 32-byte url-safe base64 value.
    fernet = Fernet(key.encode("ascii"))
    assert fernet.decrypt(fernet.encrypt(b"roundtrip")) == b"roundtrip"


def test_production_rejects_blank_credential_key():
    with pytest.raises(ValidationError, match="LINSEC_CREDENTIAL_ENCRYPTION_KEY"):
        Settings(
            _env_file=None,
            environment="production",
            secret_key="production-secret-key-at-least-32-bytes",
            credential_encryption_key="",
            cookie_secure=True,
        )


def test_credential_status_distinguishes_missing_ok_and_undecryptable():
    good = credential_service.encrypt_password("known-secret")
    other = Fernet(Fernet.generate_key()).encrypt(b"other-secret").decode("ascii")

    assert credential_service.password_status(None) == "not_configured"
    assert credential_service.password_status(good) == "ok"
    assert credential_service.password_status(other) == "undecryptable"


def test_worker_uses_key_only_for_undecryptable_hosts_without_blocking_others(
    client: TestClient, csrf_headers, monkeypatch
):
    headers = csrf_headers()
    for name, ip in (("good01", "10.0.0.61"), ("bad01", "10.0.0.62")):
        response = create_host(
            client,
            headers,
            name=name,
            ip=ip,
            ssh_fingerprint="SHA256:" + name[0] * 43,
        )
        assert response.status_code == 201, response.text
    assert create_playbook(client, headers).status_code == 201

    with session_scope() as db:
        for host in db.query(models.Host).all():
            if host.name == "good01":
                host.ansible_password_encrypted = credential_service.encrypt_password(
                    "good-secret"
                )
            else:
                host.ansible_password_encrypted = (
                    Fernet(Fernet.generate_key()).encrypt(b"bad-secret").decode("ascii")
                )

    created = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "custom.yml",
            "hosts": ["good01", "bad01"],
        },
    )
    assert created.status_code == 202, created.text
    deployment_id = created.json()["id"]

    captured: dict = {}

    def fake_run(command, **kwargs):
        inventory_path = Path(command[command.index("-i") + 1])
        captured["inventory"] = yaml.safe_load(
            inventory_path.read_text(encoding="utf-8")
        )
        kwargs["stdout"].write("fake ansible output\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.ensure_keypair", lambda: None
    )
    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.scan_host_key",
        lambda ip, port, expected_fingerprint=None: (f"{ip} ssh-ed25519 AAAA", None),
    )
    monkeypatch.setattr("backend.workers.deployment_worker.subprocess.run", fake_run)

    from backend.workers.deployment_worker import run_deployment

    run_deployment(deployment_id)

    with session_scope() as db:
        deployment = db.get(models.Deployment, deployment_id)
        assert deployment is not None
        assert deployment.status == "succeeded", deployment.error_message
        events = [
            event
            for event in deployment.events
            if event.event == "credentials_unavailable"
        ]
        assert len(events) == 1
        assert events[0].level == "warning"
        assert "bad01" in events[0].data["hosts"]
        assert "bad01" not in (deployment.error_message or "")

    hosts = captured["inventory"]["all"]["children"]["web"]["hosts"]
    assert hosts["good01"]["ansible_password"] == "good-secret"
    assert "ansible_password" not in hosts["bad01"]
    assert "ansible_private_key_file" in hosts["bad01"]


def test_cli_reencrypts_only_credentials_readable_with_previous_key(capsys):
    from backend.cli import main

    old_key = Fernet.generate_key().decode("ascii")
    with session_scope() as db:
        db.add(
            models.Host(
                name="legacy01",
                ip="10.0.0.71",
                environment_id=1,
                ansible_password_encrypted=Fernet(old_key).encrypt(
                    b"legacy-secret"
                ).decode("ascii"),
            )
        )
        db.add(
            models.Host(
                name="lost01",
                ip="10.0.0.72",
                environment_id=1,
                ansible_password_encrypted=Fernet(
                    Fernet.generate_key()
                ).encrypt(b"lost-secret").decode("ascii"),
            )
        )

    assert main(["reencrypt-credentials", "--old-key", old_key]) == 0
    with session_scope() as db:
        legacy = db.query(models.Host).filter(models.Host.name == "legacy01").one()
        assert legacy.ansible_password_encrypted.startswith("gAAAAA")
        assert credential_service.password_status(legacy.ansible_password_encrypted) == (
            "undecryptable"
        )
    assert "DRY RUN" in capsys.readouterr().out

    assert (
        main(["reencrypt-credentials", "--old-key", old_key, "--apply"]) == 0
    )
    with session_scope() as db:
        legacy = db.query(models.Host).filter(models.Host.name == "legacy01").one()
        assert credential_service.decrypt_password(
            legacy.ansible_password_encrypted or ""
        ) == "legacy-secret"
        lost = db.query(models.Host).filter(models.Host.name == "lost01").one()
        assert credential_service.password_status(lost.ansible_password_encrypted) == (
            "undecryptable"
        )


def test_host_serialization_exposes_non_secret_credential_status(
    client: TestClient, csrf_headers
):
    headers = csrf_headers()
    host_id = create_host(client, headers, ssh_fingerprint="SHA256:" + "C" * 43).json()[
        "id"
    ]
    with session_scope() as db:
        host = db.get(models.Host, host_id)
        assert host is not None
        host.ansible_password_encrypted = (
            Fernet(Fernet.generate_key()).encrypt(b"unreadable").decode("ascii")
        )

    response = client.get(f"/api/v1/hosts/{host_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["ansible_password_configured"] is True
    assert body["credential_status"] == "undecryptable"
    assert "unreadable" not in response.text
