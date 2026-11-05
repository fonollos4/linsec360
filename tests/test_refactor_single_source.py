import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))


def load_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_legacy_services_module_reuses_canonical_deployment_service():
    legacy_module = load_module_from_path(
        "legacy_services_module",
        APP_DIR / "services.py",
    )
    deployment_module = __import__("services.deployment_service", fromlist=["DeploymentService"])
    inventory_module = __import__("services.inventory_service", fromlist=["InventoryService"])

    assert legacy_module.DeploymentService is deployment_module.DeploymentService
    assert legacy_module.InventoryService is inventory_module.InventoryService


def test_legacy_services_module_reuses_canonical_event_service():
    legacy_module = load_module_from_path(
        "legacy_services_module_2",
        APP_DIR / "services.py",
    )
    canonical_module = __import__("services.event_service", fromlist=["EventService"])

    assert legacy_module.EventService is canonical_module.EventService
