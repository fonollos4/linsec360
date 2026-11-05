import sqlite3
import sys
from pathlib import Path

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from repositories.host_repository import HostRepository
from repositories.stats_repository import StatsRepository


def test_host_and_stats_repositories_persist_data(tmp_path):
    database_path = tmp_path / "linsec.db"
    with sqlite3.connect(database_path) as db:
        db.executescript((APP_DIR / "instance" / "schema.sql").read_text())

    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path)
    with app.app_context():
        host_id = HostRepository.create({
            "name": "web-01",
            "ip": "192.0.2.10",
            "environment": "production",
            "security_level": "medium",
            "groups": "web,webapp",
            "status": "pending",
        })

        assert [row["name"] for row in HostRepository.get_by_group(
            "web",
            "production",
        )] == ["web-01"]
        assert not HostRepository.get_by_group("webapp2", "production")

        HostRepository.update_statuses(["web-01"], "secured")
        StatsRepository.refresh()
        stats = StatsRepository.get_latest()
        assert stats["host_count"] == 1
        assert stats["secured_count"] == 1
        assert HostRepository.get_by_id(host_id)["status"] == "secured"

        deleted = HostRepository.delete(host_id)
        assert deleted["name"] == "web-01"
        assert HostRepository.delete(host_id) is None
