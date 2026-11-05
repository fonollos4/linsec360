import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from config import Config
from services.inventory_service import InventoryService


def host(name, group):
    return {
        "name": name,
        "ip": "192.0.2.10",
        "environment": "production",
        "security_level": "medium",
        "groups": group,
    }


def test_inventory_service_writes_private_inventory_and_removes_host(
    monkeypatch,
    tmp_path,
):
    inventory_dir = tmp_path / "inventories"
    monkeypatch.setattr(Config, "INVENTORY_DIR", str(inventory_dir))

    InventoryService.save_host_to_inventory(host("web-01", "web"))
    InventoryService.save_host_to_inventory(host("db-01", "database"))
    inventory_path = inventory_dir / "production" / "hosts.yml"
    inventory = yaml.safe_load(inventory_path.read_text())

    assert inventory["all"]["children"]["web"]["hosts"]["web-01"]["ansible_host"] == (
        "192.0.2.10"
    )
    assert inventory_path.stat().st_mode & 0o777 == 0o600

    InventoryService.remove_host_from_inventory(host("web-01", "web"))
    inventory = yaml.safe_load(inventory_path.read_text())
    assert "web-01" not in inventory["all"]["children"]["web"]["hosts"]
    assert "db-01" in inventory["all"]["children"]["database"]["hosts"]


def test_inventory_service_rejects_malformed_existing_yaml(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "INVENTORY_DIR", str(tmp_path))
    environment_dir = tmp_path / "production"
    environment_dir.mkdir()
    (environment_dir / "hosts.yml").write_text("- invalid-root\n")

    try:
        InventoryService.save_host_to_inventory(host("web-01", "web"))
        assert False, "Expected invalid inventory structure to be rejected"
    except ValueError as exc:
        assert "inventaire" in str(exc)
