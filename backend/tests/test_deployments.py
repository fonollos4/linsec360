import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend import models
from backend.db import session_scope
from backend.services import credential_service

from .conftest import create_host, create_playbook


def _create_deployment(client: TestClient, headers: dict[str, str]):
    create_host(
        client,
        headers,
        ssh_fingerprint="SHA256:" + "F" * 43,
    )
    create_playbook(client, headers)
    return client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "custom.yml",
            "hosts": ["web01"],
        },
    )


def test_create_and_list_deployment(client: TestClient, csrf_headers, queue):
    headers = csrf_headers()
    response = _create_deployment(client, headers)
    assert response.status_code == 202, response.text
    deployment = response.json()
    assert deployment["status"] == "queued"
    assert deployment["target_hosts"] == ["web01"]
    assert queue.enqueued == [deployment["id"]]

    response = client.get("/api/v1/deployments")
    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [deployment["id"]]

    response = client.get(f"/api/v1/deployments/{deployment['id']}")
    assert response.status_code == 200

    response = client.get(f"/api/v1/deployments/{deployment['id']}/events")
    assert response.status_code == 200
    assert response.json()[0]["event"] == "deployment_queued"

    response = client.get(f"/api/v1/deployments/{deployment['id']}/log")
    assert response.status_code == 200
    assert response.text == ""


def test_deployment_list_is_paginated_and_filterable(client: TestClient, csrf_headers, queue):
    headers = csrf_headers()
    identifiers = []
    for _ in range(3):
        response = _create_deployment(client, headers)
        assert response.status_code == 202, response.text
        identifiers.append(response.json()["id"])
        with session_scope() as db:
            finished = db.get(models.Deployment, response.json()["id"])
            assert finished is not None
            finished.status = "succeeded"

    first_page = client.get("/api/v1/deployments?limit=2&offset=0")
    assert first_page.status_code == 200
    assert first_page.headers["X-Total-Count"] == "3"
    first_ids = [item["id"] for item in first_page.json()]
    assert len(first_ids) == 2

    second_page = client.get("/api/v1/deployments?limit=2&offset=2")
    assert second_page.status_code == 200
    second_ids = [item["id"] for item in second_page.json()]
    assert len(second_ids) == 1
    assert set(first_ids).isdisjoint(second_ids)
    assert set(first_ids + second_ids) == set(identifiers)

    with session_scope() as db:
        deployment = db.get(models.Deployment, identifiers[0])
        assert deployment is not None
        deployment.status = "failed"

    filtered = client.get("/api/v1/deployments?status=failed")
    assert filtered.status_code == 200
    assert filtered.headers["X-Total-Count"] == "1"
    assert [item["id"] for item in filtered.json()] == [identifiers[0]]

    combined = client.get("/api/v1/deployments?status=succeeded,failed")
    assert combined.status_code == 200
    assert combined.headers["X-Total-Count"] == "3"


def test_deployment_check_mode_and_extra_vars(client: TestClient, csrf_headers, queue):
    headers = csrf_headers()
    create_host(client, headers)
    create_playbook(client, headers)
    response = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "custom.yml",
            "hosts": ["web01"],
            "check_mode": True,
            "extra_vars": {"openscap_profile": "cis_ubuntu.xml"},
        },
    )
    assert response.status_code == 202, response.text
    deployment_id = response.json()["id"]
    with session_scope() as db:
        deployment = db.get(models.Deployment, deployment_id)
        assert deployment is not None
        assert deployment.extra_vars["linsec_check_mode"] == "true"
        assert deployment.extra_vars["openscap_profile"] == "cis_ubuntu.xml"


def test_check_mode_is_rejected_for_playbooks_that_ingest_results(client: TestClient, csrf_headers, queue):
    headers = csrf_headers()
    create_host(client, headers)
    response = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "patch-security.yml",
            "hosts": ["web01"],
            "check_mode": True,
        },
    )
    assert response.status_code == 400
    assert "check mode" in response.json()["error"]["message"].lower()
    assert queue.enqueued == []


def test_retry_preserves_targeting_and_check_mode(client: TestClient, csrf_headers, queue):
    headers = csrf_headers()
    create_host(client, headers, groups=["web"])
    create_playbook(client, headers)
    created = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "custom.yml",
            "hosts": ["web01"],
            "group": "web",
            "check_mode": True,
            "extra_vars": {"openscap_profile": "cis_ubuntu.xml"},
        },
    )
    assert created.status_code == 202, created.text
    original_id = created.json()["id"]

    with session_scope() as db:
        original = db.get(models.Deployment, original_id)
        assert original is not None
        original.status = "failed"

    retried = client.post(f"/api/v1/deployments/{original_id}/retry", headers=headers)
    assert retried.status_code == 202, retried.text
    with session_scope() as db:
        replacement = db.get(models.Deployment, retried.json()["id"])
        assert replacement is not None
        assert replacement.extra_vars["openscap_profile"] == "cis_ubuntu.xml"
        assert replacement.extra_vars["linsec_check_mode"] == "true"
        assert replacement.extra_vars["linsec_target_group"] == "web"


def test_deployment_with_unknown_host_is_rejected(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)
    create_playbook(client, headers)
    response = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "custom.yml",
            "hosts": ["missing"],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "domain_error"


def test_viewer_cannot_create_deployment(client: TestClient, csrf_headers):
    headers = csrf_headers("viewer", "viewer-test-password-123")
    response = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={"environment": "production", "playbook": "connectivity.yml"},
    )
    assert response.status_code == 403


def test_worker_runs_ansible_and_updates_state(
    client: TestClient, csrf_headers, monkeypatch
):
    from backend.config import get_settings

    headers = csrf_headers()
    create_host(client, headers, ssh_fingerprint="SHA256:" + "F" * 43)
    create_playbook(client, headers)
    response = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "custom.yml",
            "hosts": ["web01"],
            "extra_vars": {
                "openscap_api_token": "attacker-token",
                "patch_api_token": "attacker-token",
            },
        },
    )
    assert response.status_code == 202, response.text
    deployment_id = response.json()["id"]

    captured: dict = {}
    settings = get_settings()
    monkeypatch.setattr(settings, "wazuh_manager_address", "")
    monkeypatch.setattr(settings, "wazuh_api_url", "https://192.0.2.25:55000")
    monkeypatch.setattr(settings, "ingest_api_url", "http://api:8000")
    monkeypatch.setattr(settings, "ingest_api_token", SecretStr("linsec-worker-token"))
    with session_scope() as db:
        db.add(
            models.RuntimeSetting(
                key="wazuh_manager_agent_port",
                value="1614",
            )
        )
        db.add(
            models.RuntimeSetting(
                key="wazuh_manager_enrollment_port",
                value="1615",
            )
        )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        extra_vars_path = command[command.index("--extra-vars") + 1][1:]
        captured["extra_vars"] = yaml.safe_load(
            Path(extra_vars_path).read_text(encoding="utf-8")
        )
        kwargs["stdout"].write("fake ansible output\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.ensure_keypair",
        lambda: None,
    )
    monkeypatch.setattr("backend.workers.deployment_worker.subprocess.run", fake_run)

    from backend.workers.deployment_worker import run_deployment

    run_deployment(deployment_id)

    with session_scope() as db:
        deployment = db.get(models.Deployment, deployment_id)
        assert deployment is not None
        assert deployment.status == "succeeded"
        assert deployment.started_at is not None
        assert deployment.finished_at is not None
        host = db.query(models.Host).filter(models.Host.name == "web01").one()
        assert host.status == "secured"
        target = deployment.targets[0]
        assert target.status == "succeeded"

    command = captured["command"]
    assert "--limit" in command
    assert command[command.index("--limit") + 1] == "web01"
    assert captured["environment"]["ANSIBLE_HOST_KEY_CHECKING"] == "False"
    assert "StrictHostKeyChecking=no" in captured["environment"]["ANSIBLE_SSH_ARGS"]
    assert "UserKnownHostsFile=/dev/null" in captured["environment"]["ANSIBLE_SSH_ARGS"]
    assert "GlobalKnownHostsFile=/dev/null" in captured["environment"]["ANSIBLE_SSH_ARGS"]
    assert captured["extra_vars"]["linsec_wazuh_manager_address"] == "192.0.2.25"
    assert captured["extra_vars"]["linsec_wazuh_manager_agent_port"] == 1614
    assert captured["extra_vars"]["linsec_wazuh_manager_enrollment_port"] == 1615
    assert captured["extra_vars"]["openscap_ingest_url"] == "http://api:8000"
    assert captured["extra_vars"]["openscap_api_token"] == "linsec-worker-token"
    assert captured["extra_vars"]["patch_ingest_url"] == "http://api:8000"
    assert captured["extra_vars"]["patch_api_token"] == "linsec-worker-token"
    assert captured["extra_vars"]["hardening_api_token"] == "linsec-worker-token"
    assert captured["extra_vars"]["livepatch_api_token"] == "linsec-worker-token"
    assert not any(
        key.startswith("linsec_uyuni_") for key in captured["extra_vars"]
    )
    roles_path = captured["environment"]["ANSIBLE_ROLES_PATH"].split(os.pathsep)
    assert str(settings.taskengine_dir / "roles") in roles_path

    response = client.get(f"/api/v1/deployments/{deployment_id}/log")
    assert response.status_code == 200
    assert "job_id=" in response.text
    assert "fake ansible output" in response.text


def test_worker_records_failure(client: TestClient, csrf_headers, monkeypatch):
    headers = csrf_headers()
    response = _create_deployment(client, headers)
    deployment_id = response.json()["id"]

    def fake_run(command, **kwargs):
        kwargs["stdout"].write("boom\n")
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.ensure_keypair",
        lambda: None,
    )
    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.scan_host_key",
        lambda ip, port, expected_fingerprint=None: (
            f"{ip} ssh-ed25519 AAAA",
            "SHA256:" + "F" * 43,
        ),
    )
    monkeypatch.setattr("backend.workers.deployment_worker.subprocess.run", fake_run)

    from backend.workers.deployment_worker import run_deployment

    run_deployment(deployment_id)

    with session_scope() as db:
        deployment = db.get(models.Deployment, deployment_id)
        assert deployment.status == "failed"
        assert "exited with code 2" in (deployment.error_message or "")
        host = db.query(models.Host).filter(models.Host.name == "web01").one()
        assert host.status == "error"


def test_worker_does_not_scan_or_pin_host_fingerprints(
    client: TestClient, csrf_headers, monkeypatch
):
    headers = csrf_headers()
    response = _create_deployment(client, headers)
    deployment_id = response.json()["id"]
    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.ensure_keypair",
        lambda: None,
    )
    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.scan_host_key",
        lambda *args, **kwargs: pytest.fail(
            "deployment must not scan SSH host fingerprints"
        ),
    )

    def fake_run(command, **kwargs):
        kwargs["stdout"].write("fake ansible output\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("backend.workers.deployment_worker.subprocess.run", fake_run)

    from backend.workers.deployment_worker import run_deployment

    run_deployment(deployment_id)

    with session_scope() as db:
        deployment = db.get(models.Deployment, deployment_id)
        assert deployment is not None
        assert deployment.status == "succeeded"


def test_worker_decrypts_password_into_private_temporary_inventory(
    client: TestClient, csrf_headers, monkeypatch
):
    headers = csrf_headers()
    response = _create_deployment(client, headers)
    deployment_id = response.json()["id"]
    with session_scope() as db:
        host = db.query(models.Host).filter(models.Host.name == "web01").one()
        host.ansible_password_encrypted = credential_service.encrypt_password(
            "temporary-secret"
        )
        db.commit()

    captured: dict = {}

    def fake_run(command, **kwargs):
        inventory_path = Path(command[command.index("-i") + 1])
        captured["inventory_path"] = inventory_path
        captured["inventory_mode"] = inventory_path.stat().st_mode & 0o777
        captured["inventory"] = yaml.safe_load(
            inventory_path.read_text(encoding="utf-8")
        )
        kwargs["stdout"].write("fake ansible output\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.ensure_keypair",
        lambda: None,
    )
    monkeypatch.setattr(
        "backend.workers.deployment_worker.ssh_service.scan_host_key",
        lambda ip, port, expected_fingerprint=None: (
            f"{ip} ssh-ed25519 AAAA",
            "SHA256:" + "F" * 43,
        ),
    )
    monkeypatch.setattr("backend.workers.deployment_worker.subprocess.run", fake_run)

    from backend.workers.deployment_worker import run_deployment

    run_deployment(deployment_id)

    host_vars = captured["inventory"]["all"]["children"]["web"]["hosts"]["web01"]
    assert host_vars["ansible_password"] == "temporary-secret"
    assert host_vars["ansible_become_password"] == "temporary-secret"
    assert "ansible_private_key_file" not in host_vars
    assert captured["inventory_mode"] == 0o600
    assert not captured["inventory_path"].exists()
