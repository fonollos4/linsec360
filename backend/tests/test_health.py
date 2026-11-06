from fastapi.testclient import TestClient


def test_health_and_readiness(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["checks"]["database"] == "ok"


def test_root_reports_api_version(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["api"] == "/api/v1"
