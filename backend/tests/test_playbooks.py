from pathlib import Path

from fastapi.testclient import TestClient

from backend.config import get_settings
from backend.db import session_scope
from backend.services import playbook_service

from .conftest import create_playbook

SUPPORTED_PLAYBOOKS = {
    "site.yml",
    "verify.yml",
    "openscap-scan.yml",
    "openscap-remediate.yml",
    "compliance-verify.yml",
    "hardening.yml",
    "patch-security.yml",
    "patch-verify.yml",
    "livepatch-check.yml",
    "wazuh-agent.yml",
    "connectivity.yml",
}

REMOVED_PLAYBOOKS = {
    "site-legacy.yml",
    "system-audit.yml",
    "hardening-audit.yml",
    "system-update.yml",
    "disk-cleanup.yml",
}


def test_bundled_playbooks_are_seeded(client: TestClient, login):
    login()
    response = client.get("/api/v1/playbooks")
    assert response.status_code == 200
    filenames = {item["filename"] for item in response.json()}
    assert filenames >= SUPPORTED_PLAYBOOKS
    assert not filenames & REMOVED_PLAYBOOKS
    assert "ansible.cfg" not in filenames


def test_bundled_playbook_sync_removes_deleted_files_and_keeps_user_playbooks(
    client: TestClient, csrf_headers, monkeypatch, tmp_path: Path
):
    headers = csrf_headers()
    assert create_playbook(client, headers).status_code == 201

    directory = tmp_path / "playbooks"
    directory.mkdir()
    stale = directory / "stale-bundled.yml"
    stale.write_text("- name: Stale\n  hosts: all\n  tasks: []\n", encoding="utf-8")

    monkeypatch.setattr(get_settings(), "bundled_playbooks_dir", directory)
    with session_scope() as db:
        playbook_service.seed_from_directory(db, directory)

    with session_scope() as db:
        assert playbook_service.get_by_filename(db, "stale-bundled.yml") is not None

    stale.unlink()
    with session_scope() as db:
        playbook_service.seed_from_directory(db, directory)

    with session_scope() as db:
        assert playbook_service.get_by_filename(db, "stale-bundled.yml") is None
        assert playbook_service.get_by_filename(db, "custom.yml") is not None


def test_playbook_crud(client: TestClient, csrf_headers):
    headers = csrf_headers()
    response = create_playbook(client, headers)
    assert response.status_code == 201, response.text
    assert response.json()["content"].startswith("- name: Ping")

    response = client.get("/api/v1/playbooks/custom.yml")
    assert response.status_code == 200
    assert response.json()["filename"] == "custom.yml"

    response = client.put(
        "/api/v1/playbooks/custom.yml",
        headers=headers,
        json={
            "content": "- name: Updated\n  hosts: all\n  tasks: []\n",
            "description": "updated",
        },
    )
    assert response.status_code == 200
    assert response.json()["description"] == "updated"

    response = client.delete("/api/v1/playbooks/custom.yml", headers=headers)
    assert response.status_code == 200
    assert client.get("/api/v1/playbooks/custom.yml").status_code == 404


def test_invalid_yaml_is_rejected(client: TestClient, csrf_headers):
    headers = csrf_headers()
    response = create_playbook(
        client, headers, filename="broken.yml", content="- name: [\n"
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "domain_error"


def test_playbook_filename_traversal_is_rejected(client: TestClient, csrf_headers):
    headers = csrf_headers()
    response = create_playbook(client, headers, filename="../../etc/passwd.yml")
    assert response.status_code == 422


def test_playbook_non_list_yaml_is_rejected(client: TestClient, csrf_headers):
    headers = csrf_headers()
    response = create_playbook(
        client, headers, filename="mapping.yml", content="name: nope\n"
    )
    assert response.status_code == 400


def test_playbook_validation_reports_yaml_and_structure(client: TestClient, csrf_headers):
    headers = csrf_headers()
    valid = client.post(
        "/api/v1/playbooks/validate",
        headers=headers,
        json={"content": "- name: Ping\n  hosts: all\n  tasks: []\n"},
    )
    assert valid.status_code == 200
    assert valid.json()["valid"] is True
    assert "liste" in valid.json()["detail"]

    invalid_yaml = client.post(
        "/api/v1/playbooks/validate",
        headers=headers,
        json={"content": "- name: [\n"},
    )
    assert invalid_yaml.status_code == 200
    assert invalid_yaml.json()["valid"] is False
    assert "invalid YAML" in invalid_yaml.json()["detail"]

    invalid_shape = client.post(
        "/api/v1/playbooks/validate",
        headers=headers,
        json={"content": "name: not-a-list\n"},
    )
    assert invalid_shape.status_code == 200
    assert invalid_shape.json()["valid"] is False
    assert "YAML list" in invalid_shape.json()["detail"]


def test_viewer_cannot_validate_playbook(client: TestClient, csrf_headers):
    response = client.post(
        "/api/v1/playbooks/validate",
        headers=csrf_headers("viewer", "viewer-test-password-123"),
        json={"content": "- name: Check\n  hosts: all\n"},
    )
    assert response.status_code == 403


def test_viewer_cannot_create_playbook(client: TestClient, csrf_headers):
    headers = csrf_headers("viewer", "viewer-test-password-123")
    response = create_playbook(client, headers, filename="viewer.yml")
    assert response.status_code == 403
