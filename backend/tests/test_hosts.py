from fastapi.testclient import TestClient

from .conftest import create_host


def test_create_list_update_delete_host(client: TestClient, csrf_headers):
    headers = csrf_headers()
    response = create_host(client, headers)
    assert response.status_code == 201, response.text
    host = response.json()
    assert host["environment"] == "production"
    assert host["groups"] == ["web"]
    assert host["security_level"] == "high"

    response = client.get("/api/v1/hosts")
    assert response.status_code == 200
    assert [item["name"] for item in response.json()] == ["web01"]

    response = client.get("/api/v1/hosts?environment=production")
    assert len(response.json()) == 1

    response = client.get("/api/v1/hosts?environment=staging")
    assert response.json() == []

    response = client.patch(
        f"/api/v1/hosts/{host['id']}",
        headers=headers,
        json={"ip": "10.0.0.11", "status": "secured"},
    )
    assert response.status_code == 200
    assert response.json()["ip"] == "10.0.0.11"
    assert response.json()["status"] == "secured"

    response = client.delete(f"/api/v1/hosts/{host['id']}", headers=headers)
    assert response.status_code == 200
    assert client.get(f"/api/v1/hosts/{host['id']}").status_code == 404


def test_duplicate_host_is_rejected(client: TestClient, csrf_headers):
    headers = csrf_headers()
    assert create_host(client, headers).status_code == 201
    response = create_host(client, headers)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"


def test_invalid_host_payload_is_rejected(client: TestClient, csrf_headers):
    headers = csrf_headers()
    response = create_host(client, headers, ip="not-an-ip")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"

    response = create_host(client, headers, name="../etc/passwd")
    assert response.status_code == 422

    response = create_host(client, headers, security_level="extreme")
    assert response.status_code == 422


def test_host_filters(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers, name="web01", ip="10.0.0.10")
    create_host(client, headers, name="db01", ip="10.0.0.20", groups=["database"])

    response = client.get("/api/v1/hosts?q=db")
    assert response.status_code == 200
    assert [item["name"] for item in response.json()] == ["db01"]

    response = client.get("/api/v1/hosts?status=secured")
    assert response.json() == []


def test_unknown_host_returns_404(client: TestClient, login):
    login()
    response = client.get("/api/v1/hosts/9999")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
