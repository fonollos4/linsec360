from fastapi.testclient import TestClient

from backend.db import session_scope
from backend.services import kpi_service

from .conftest import create_host


def test_kpis_start_with_explicit_unknowns(client: TestClient, login):
    login()
    response = client.get("/api/v1/kpis/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["hosts_total"]["value"] == 0
    assert data["open_vulnerabilities"]["value"] is None
    assert data["open_vulnerabilities"]["status"] == "unknown"
    assert data["open_vulnerabilities"]["source"] == "wazuh"
    assert data["compliance_score"]["status"] == "unknown"


def test_kpis_reflect_database_state(client: TestClient, csrf_headers, login):
    headers = csrf_headers()
    response = create_host(client, headers)
    host_id = response.json()["id"]
    client.patch(
        f"/api/v1/hosts/{host_id}",
        headers=headers,
        json={"status": "secured"},
    )
    create_host(
        client,
        headers,
        name="db01",
        ip="10.0.0.20",
        groups=["database"],
    )

    login()
    data = client.get("/api/v1/kpis/overview").json()
    assert data["hosts_total"]["value"] == 2
    assert data["hosts_secured"]["value"] == 1
    assert data["hosts_deploying"]["value"] == 0
    assert data["deployment_success_rate"]["status"] == "unknown"


def test_kpi_history_is_filterable(client: TestClient, login):
    login()

    with session_scope() as db:
        assert kpi_service.capture_snapshot(db) > 0

    response = client.get(
        "/api/v1/kpis/history",
        params={"metric": "hosts_total", "days": 30, "limit": 10},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data
    assert {item["metric"] for item in data} == {"hosts_total"}
    assert data[0]["scope_type"] == "global"
    assert data[0]["value"] == 0.0


def test_kpi_history_rejects_invalid_filters(client: TestClient, login):
    login()
    response = client.get("/api/v1/kpis/history", params={"days": 0})
    assert response.status_code == 422
