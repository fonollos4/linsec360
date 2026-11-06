from fastapi.testclient import TestClient

from .conftest import create_playbook


def test_bundled_playbooks_are_seeded(client: TestClient, login):
    login()
    response = client.get("/api/v1/playbooks")
    assert response.status_code == 200
    filenames = {item["filename"] for item in response.json()}
    assert "connectivity.yml" in filenames
    assert "system-audit.yml" in filenames
    assert "ansible.cfg" not in filenames


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


def test_viewer_cannot_create_playbook(client: TestClient, csrf_headers):
    headers = csrf_headers("viewer", "viewer-test-password-123")
    response = create_playbook(client, headers, filename="viewer.yml")
    assert response.status_code == 403
