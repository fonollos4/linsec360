import sqlite3
import sys
from pathlib import Path

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from routes import register_routes
from repositories.deployment_repository import DeploymentRepository
from services.deployment_service import DeploymentService


def create_test_app(tmp_path):
    database_path = tmp_path / "linsec.db"
    with sqlite3.connect(database_path) as db:
        db.executescript((APP_DIR / "instance" / "schema.sql").read_text())

    app = Flask(__name__)
    app.config.update(
        DATABASE_PATH=str(database_path),
        LOG_DIR=str(tmp_path / "logs"),
    )
    register_routes(app)
    return app


def test_health_readiness_and_deployment_validation(monkeypatch, tmp_path):
    app = create_test_app(tmp_path)
    client = app.test_client()

    assert client.get("/health").json == {"status": "ok"}
    assert client.get("/ready").json == {"status": "ready"}
    assert client.post("/deploy", json=None).status_code == 400

    monkeypatch.setattr(
        DeploymentService,
        "get_target_hosts",
        lambda environment, hosts, group: ["web-01"],
    )
    monkeypatch.setattr(
        DeploymentService,
        "start_deployment",
        lambda environment, playbook, hosts: {
            "job_id": "job-1",
            "target_hosts": hosts,
        },
    )
    response = client.post(
        "/deploy",
        json={"environment": "production", "playbook": "site.yml"},
    )

    assert response.status_code == 200
    assert response.json["job_id"] == "job-1"


def test_deployment_status_and_log_endpoints(tmp_path):
    app = create_test_app(tmp_path)
    log_directory = Path(app.config["LOG_DIR"])
    log_directory.mkdir()
    log_path = log_directory / "deploy-job-1.log"
    log_path.write_text("deployment output")
    job = {
        "job_id": "job-1",
        "environment": "production",
        "playbook": "site.yml",
        "target_hosts": ["web-01"],
        "status": "succeeded",
        "created_at": "2026-11-05T00:00:00+00:00",
        "started_at": "2026-11-05T00:00:01+00:00",
        "finished_at": "2026-11-05T00:00:02+00:00",
        "log_path": str(log_path),
        "error_message": None,
    }
    with app.app_context():
        DeploymentRepository.create(job)

    client = app.test_client()
    status_response = client.get("/deployments/job-1")
    assert status_response.status_code == 200
    assert status_response.json["status"] == "succeeded"
    assert "log_path" not in status_response.json
    assert client.get("/deployments/job-1/log").status_code == 503
    app.config["LOG_API_TOKEN"] = "test-token"
    assert client.get("/deployments/job-1/log").status_code == 401
    log_response = client.get(
        "/deployments/job-1/log",
        headers={"Authorization": "Bearer test-token"},
    )
    assert log_response.text == "deployment output"
    assert client.get("/deployments/unknown").status_code == 404


def test_event_stream_uses_request_application_context(tmp_path):
    app = create_test_app(tmp_path)
    response = app.test_client().get("/events", buffered=False)
    first_event = next(response.response)
    response.close()

    assert b'"type": "stats"' in first_event
