from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from services.validation_service import ValidationService


def test_validation_service_accepts_valid_values():
    assert ValidationService.validate_ip("192.0.2.10")
    assert ValidationService.validate_host_name("web-01.example")
    assert ValidationService.validate_environment_name("pre-prod")
    assert ValidationService.validate_group_name("web_servers")
    assert ValidationService.validate_playbook_name("site.yaml")


def test_validation_service_rejects_paths_and_invalid_values():
    assert not ValidationService.validate_ip("127.1")
    assert not ValidationService.validate_ip("192.0.2.999")
    assert not ValidationService.validate_host_name("../host")
    assert not ValidationService.validate_environment_name("prod/../../tmp")
    assert not ValidationService.validate_group_name("web,db")
    assert not ValidationService.validate_playbook_name("../playbook.yml")
    assert not ValidationService.validate_playbook_name(".hidden.yml")
    assert not ValidationService.validate_security_level([])
