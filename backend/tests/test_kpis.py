from fastapi.testclient import TestClient

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
