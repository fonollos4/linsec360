from fastapi.testclient import TestClient

from backend import models
from backend.db import session_scope
from backend.security import create_session, decode_session_token


def test_session_id_fits_database_column(client: TestClient):
    with session_scope() as db:
        user = db.query(models.User).filter_by(username="admin").one()
        token, _, _ = create_session(db, user)
        payload = decode_session_token(token)
        assert payload is not None
        column_length = models.UserSession.__table__.c.id.type.length
        assert len(payload["jti"]) <= column_length


def test_login_sets_session_and_returns_user(client: TestClient, login):
    csrf = login()
    assert csrf
    assert client.cookies.get("linsec_session")
    assert client.cookies.get("linsec_csrf") == csrf

    response = client.get("/api/v1/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
    assert response.json()["role"] == "admin"


def test_login_rejects_bad_password(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "http_error"


def test_unauthenticated_requests_are_rejected(client: TestClient):
    response = client.get("/api/v1/hosts")
    assert response.status_code == 401


def test_state_changing_request_requires_csrf(client: TestClient, login):
    login()
    payload = {
        "name": "web01",
        "ip": "10.0.0.10",
        "environment": "production",
        "security_level": "high",
    }
    response = client.post("/api/v1/hosts", json=payload)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"

    csrf = client.cookies.get("linsec_csrf")
    response = client.post(
        "/api/v1/hosts",
        json=payload,
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201


def test_csrf_mismatch_is_rejected(client: TestClient, login):
    login()
    response = client.post(
        "/api/v1/hosts",
        json={
            "name": "web01",
            "ip": "10.0.0.10",
            "environment": "production",
        },
        headers={"X-CSRF-Token": "not-the-cookie"},
    )
    assert response.status_code == 403


def test_logout_revokes_session(client: TestClient, login):
    csrf = login()
    response = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401
    assert "linsec_session" not in client.cookies
    assert "linsec_csrf" not in client.cookies


def test_password_can_be_changed_with_current_password(client: TestClient, login):
    csrf = login()
    response = client.put(
        "/api/v1/auth/password",
        headers={"X-CSRF-Token": csrf},
        json={
            "current_password": "admin-test-password-123",
            "new_password": "new-strong-password-123",
        },
    )
    assert response.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin-test-password-123"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "new-strong-password-123"},
        ).status_code
        == 200
    )


def test_password_change_requires_current_password(client: TestClient, login):
    csrf = login()
    response = client.put(
        "/api/v1/auth/password",
        headers={"X-CSRF-Token": csrf},
        json={
            "current_password": "wrong-password",
            "new_password": "new-strong-password-123",
        },
    )
    assert response.status_code == 400


def test_password_change_requires_csrf(client: TestClient, login):
    login()
    response = client.put(
        "/api/v1/auth/password",
        json={
            "current_password": "admin-test-password-123",
            "new_password": "new-strong-password-123",
        },
    )
    assert response.status_code == 403


def test_viewer_cannot_mutate(client: TestClient, csrf_headers):
    headers = csrf_headers("viewer", "viewer-test-password-123")
    response = client.post(
        "/api/v1/hosts",
        headers=headers,
        json={
            "name": "web01",
            "ip": "10.0.0.10",
            "environment": "production",
        },
    )
    assert response.status_code == 403
    assert client.get("/api/v1/hosts").status_code == 200
