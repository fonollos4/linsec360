import os
import sqlite3
import sys
from pathlib import Path

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from config import Config
from app import create_app


def test_database_path_uses_configured_path(tmp_path):
    database_path = tmp_path / "custom" / "linsec.db"
    app = Flask(__name__, instance_path=str(tmp_path / "instance"))
    app.config["DATABASE_PATH"] = str(database_path)

    with app.app_context():
        assert Config.get_database_path() == str(database_path)


def test_database_path_defaults_to_instance_directory(tmp_path):
    app = Flask(__name__, instance_path=str(tmp_path / "instance"))
    app.config["DATABASE_PATH"] = None

    with app.app_context():
        assert Config.get_database_path() == os.path.join(
            app.instance_path,
            "linsec.db",
        )


def test_runtime_paths_can_be_overridden(monkeypatch, tmp_path):
    inventory_dir = tmp_path / "inventories"
    playbooks_dir = tmp_path / "playbooks"
    monkeypatch.setattr(Config, "INVENTORY_DIR", str(inventory_dir))
    monkeypatch.setattr(Config, "PLAYBOOKS_DIR", str(playbooks_dir))

    assert Config.get_inventory_path("test") == str(
        inventory_dir / "test" / "hosts.yml"
    )
    assert Config.get_playbook_path("site.yml") == str(
        playbooks_dir / "site.yml"
    )


def test_app_factory_creates_configured_runtime_directories(monkeypatch, tmp_path):
    database_path = tmp_path / "custom-db" / "linsec.db"
    logs_dir = tmp_path / "logs"
    playbooks_dir = tmp_path / "playbooks"
    monkeypatch.setattr(Config, "DATABASE_PATH", str(database_path))
    monkeypatch.setattr(Config, "LOG_DIR", str(logs_dir))
    monkeypatch.setattr(Config, "PLAYBOOKS_DIR", str(playbooks_dir))

    app = create_app()
    result = app.test_cli_runner().invoke(args=["init-db"])

    assert result.exit_code == 0
    assert database_path.exists()
    assert logs_dir.is_dir()
    assert playbooks_dir.is_dir()
    assert app.test_client().get("/").status_code == 200
    assert app.test_client().get("/static/js/script.js").status_code == 200
    with sqlite3.connect(database_path) as db:
        assert db.execute(
            "SELECT name FROM sqlite_master WHERE name = 'deployment_jobs'"
        ).fetchone()
