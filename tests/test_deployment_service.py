import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from config import Config
from repositories.deployment_repository import DeploymentRepository
from services import deployment_service
from services.deployment_service import DeploymentService


def create_database(path):
    with sqlite3.connect(path) as db:
        db.executescript(
            """
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY,
                name TEXT,
                ip TEXT,
                environment TEXT,
                security_level TEXT,
                groups TEXT,
                status TEXT
            );
            CREATE TABLE stats (
                id INTEGER PRIMARY KEY,
                host_count INTEGER,
                secured_count INTEGER,
                vulnerabilities_count INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO hosts (id, name, environment, status)
            VALUES (1, 'web-01', 'production', 'deploying');
            INSERT INTO stats (host_count, secured_count, vulnerabilities_count)
            VALUES (1, 0, 1);
            """
        )


def test_worker_persists_job_result_and_host_status(monkeypatch, tmp_path):
    database_path = tmp_path / "linsec.db"
    create_database(database_path)
    log_dir = tmp_path / "logs"
    playbook_dir = tmp_path / "playbooks"
    inventory_dir = tmp_path / "inventories"
    log_dir.mkdir()
    playbook_dir.mkdir()
    inventory_dir.mkdir()

    monkeypatch.setattr(Config, "LOG_DIR", str(log_dir))
    monkeypatch.setattr(Config, "PLAYBOOKS_DIR", str(playbook_dir))
    monkeypatch.setattr(Config, "INVENTORY_DIR", str(inventory_dir))
    monkeypatch.setattr(Config, "ANSIBLE_DIR", str(tmp_path))
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path)

    job = {
        "job_id": "job-1",
        "environment": "production",
        "playbook": "site.yml",
        "target_hosts": ["web-01"],
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "log_path": str(log_dir / "deploy-job-1.log"),
    }
    with app.app_context():
        DeploymentRepository.create(job)

    monkeypatch.setattr(
        deployment_service.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0),
    )
    DeploymentService._run_ansible_deployment(app, job)

    with app.app_context():
        persisted_job = DeploymentRepository.get_by_id("job-1")
        host = sqlite3.connect(database_path).execute(
            "SELECT status FROM hosts WHERE id = 1"
        ).fetchone()

    assert persisted_job["status"] == "succeeded"
    assert persisted_job["started_at"]
    assert persisted_job["finished_at"]
    assert host[0] == "secured"
    assert Path(job["log_path"]).stat().st_mode & 0o777 == 0o600


def test_ansible_command_limits_execution_to_target_hosts(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "PLAYBOOKS_DIR", str(tmp_path))
    monkeypatch.setattr(Config, "INVENTORY_DIR", str(tmp_path))
    job = {
        "environment": "production",
        "playbook": "system-update.yml",
        "target_hosts": ["web-01", "db-01"],
    }

    command = DeploymentService._build_ansible_command(
        job,
        str(tmp_path / "env.yml"),
        str(tmp_path / "hosts.yml"),
    )

    assert command[command.index("--limit") + 1] == "web-01,db-01"


def test_selected_deployment_hosts_must_belong_to_environment(monkeypatch):
    monkeypatch.setattr(
        "services.deployment_service.HostRepository.get_by_environment",
        lambda environment: [{"name": "web-01"}],
    )

    assert DeploymentService.get_target_hosts(
        "production",
        ["web-01", "web-01"],
    ) == ["web-01"]

    try:
        DeploymentService.get_target_hosts("production", ["other-01"])
        assert False, "Expected hosts from another environment to be rejected"
    except ValueError as exc:
        assert "environnement" in str(exc)
