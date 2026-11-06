from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend import models
from backend.db import session_scope

from .conftest import create_host, create_playbook


def _create_deployment(client: TestClient, headers: dict[str, str]):
    create_host(client, headers)
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
    headers = csrf_headers()
    response = _create_deployment(client, headers)
    deployment_id = response.json()["id"]

    captured: dict = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        kwargs["stdout"].write("fake ansible output\n")
        return SimpleNamespace(returncode=0)

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

    monkeypatch.setattr("backend.workers.deployment_worker.subprocess.run", fake_run)

    from backend.workers.deployment_worker import run_deployment

    run_deployment(deployment_id)

    with session_scope() as db:
        deployment = db.get(models.Deployment, deployment_id)
        assert deployment.status == "failed"
        assert "exited with code 2" in (deployment.error_message or "")
        host = db.query(models.Host).filter(models.Host.name == "web01").one()
        assert host.status == "error"
