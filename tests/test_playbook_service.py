from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from config import Config
from services.playbook_service import PlaybookService


def test_playbook_service_rejects_path_traversal():
    with pytest.raises(ValueError, match="invalide"):
        PlaybookService.create_playbook("../outside.yml", "content")


def test_playbook_service_creates_and_updates_private_file(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "PLAYBOOKS_DIR", str(tmp_path))

    PlaybookService.create_playbook("site.yml", "- hosts: all\n")
    playbook_path = tmp_path / "site.yml"
    assert playbook_path.read_text() == "- hosts: all\n"
    assert playbook_path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(ValueError, match="existe déjà"):
        PlaybookService.create_playbook("site.yml", "duplicate")

    PlaybookService.update_playbook("site.yml", "- hosts: web\n")
    assert playbook_path.read_text() == "- hosts: web\n"


def test_playbook_service_does_not_update_symlinks(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "PLAYBOOKS_DIR", str(tmp_path))
    outside = tmp_path / "outside.yml"
    outside.write_text("unchanged")
    (tmp_path / "site.yml").symlink_to(outside)

    with pytest.raises(ValueError, match="non trouvé"):
        PlaybookService.update_playbook("site.yml", "changed")
    assert outside.read_text() == "unchanged"
