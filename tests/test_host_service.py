from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from services.host_service import HostService
from services.stats_service import StatsService


def test_host_service_lists_hosts_as_dictionaries(monkeypatch):
    hosts = [{"id": 1, "name": "web-01"}]
    monkeypatch.setattr("services.host_service.HostRepository.list_all", lambda: hosts)

    assert HostService.list_hosts() == hosts


def test_host_service_create_host_validates_and_registers_inventory(monkeypatch):
    captured = {}

    def fake_validate_ip(ip):
        return ip == "10.0.0.5"

    def fake_create(host_data):
        captured["created"] = host_data
        return None

    def fake_refresh():
        captured["stats_refreshed"] = True
        return None

    def fake_save_host_to_inventory(host_data):
        captured["inventory"] = host_data
        return None

    monkeypatch.setattr("services.validation_service.ValidationService.validate_ip", fake_validate_ip)
    monkeypatch.setattr("services.host_service.HostRepository.create", fake_create)
    monkeypatch.setattr("services.host_service.StatsRepository.refresh", fake_refresh)
    monkeypatch.setattr("services.host_service.InventoryService.save_host_to_inventory", fake_save_host_to_inventory)

    host_data = {
        "name": "web-01",
        "ip": "10.0.0.5",
        "environment": "production",
        "security_level": "medium",
        "groups": "web",
        "status": "pending",
    }

    result = HostService.create_host(host_data)

    assert result == host_data
    assert captured["created"] == host_data
    assert captured["stats_refreshed"] is True
    assert captured["inventory"] == host_data


def test_host_service_rejects_invalid_ip():
    try:
        HostService.create_host({
            "name": "web-01",
            "ip": "999.999.999.999",
            "environment": "production",
            "security_level": "medium",
            "groups": "web",
            "status": "pending",
        })
        assert False, "Expected ValueError for invalid IP"
    except ValueError as exc:
        assert "Adresse IP invalide" in str(exc)


def test_stats_service_returns_latest_stats(monkeypatch):
    def fake_get_latest():
        return {"host_count": 2, "secured_count": 1, "vulnerabilities_count": 1}

    monkeypatch.setattr("services.stats_service.StatsRepository.get_latest", fake_get_latest)

    assert StatsService.get_current_stats() == {
        "host_count": 2,
        "secured_count": 1,
        "vulnerabilities_count": 1,
    }
