"""Tests for encrypted native-tool credentials exposed in Settings."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from backend import models
from backend.db import session_scope
from backend.services import credential_service
from backend.workers.deployment_worker import _native_tool_vars

from .conftest import VIEWER_PASSWORD

SECRETS_URL = "/api/v1/integrations/native-secrets"


def test_native_secrets_are_masked_and_stored_encrypted(
    client: TestClient, csrf_headers
) -> None:
    headers = csrf_headers()

    response = client.put(
        SECRETS_URL,
        headers=headers,
        json={"secrets": {"ubuntu_pro_token": "UbuntuProSecret123"}},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "UbuntuProSecret123" not in json.dumps(payload)

    token = next(
        item for item in payload["secrets"] if item["key"] == "ubuntu_pro_token"
    )
    assert token["configured"] is True
    assert token["updated_at"] is not None
    assert "value" not in token

    with session_scope() as db:
        row = db.get(models.PlatformSecret, "ubuntu_pro_token")
        assert row is not None
        assert "UbuntuProSecret123" not in row.value_encrypted
        assert credential_service.decrypt_secret(row.value_encrypted) == (
            "UbuntuProSecret123"
        )

    response = client.get(SECRETS_URL, headers=headers)
    assert response.status_code == 200
    assert "UbuntuProSecret123" not in response.text
    token = next(
        item for item in response.json()["secrets"] if item["key"] == "ubuntu_pro_token"
    )
    assert token["configured"] is True


def test_clearing_a_native_secret_does_not_need_its_previous_value(
    client: TestClient, csrf_headers
) -> None:
    headers = csrf_headers()
    assert client.put(
        SECRETS_URL,
        headers=headers,
        json={"secrets": {"canonical_livepatch_token": "LegacyToken"}},
    ).status_code == 200

    response = client.put(
        SECRETS_URL,
        headers=headers,
        json={"secrets": {"canonical_livepatch_token": None}},
    )
    assert response.status_code == 200, response.text
    token = next(
        item
        for item in response.json()["secrets"]
        if item["key"] == "canonical_livepatch_token"
    )
    assert token["configured"] is False
    with session_scope() as db:
        assert db.get(models.PlatformSecret, "canonical_livepatch_token") is None


def test_native_secret_update_rejects_unknown_keys(client: TestClient, csrf_headers):
    response = client.put(
        SECRETS_URL,
        headers=csrf_headers(),
        json={"secrets": {"unknown_token": "value"}},
    )
    assert response.status_code == 422


def test_native_secret_update_requires_admin(client: TestClient, csrf_headers):
    response = client.put(
        SECRETS_URL,
        headers=csrf_headers("viewer", VIEWER_PASSWORD),
        json={"secrets": {"ubuntu_pro_token": "value"}},
    )
    assert response.status_code == 403


def test_audit_log_never_contains_native_secret_values(
    client: TestClient, csrf_headers
) -> None:
    headers = csrf_headers()
    assert client.put(
        SECRETS_URL,
        headers=headers,
        json={"secrets": {"ubuntu_pro_token": "AuditSecretValue"}},
    ).status_code == 200

    audit = client.get("/api/v1/audit?limit=20", headers=headers)
    assert audit.status_code == 200
    assert "AuditSecretValue" not in audit.text
    assert any(
        entry["action"] == "integrations.native_secrets.update"
        for entry in audit.json()
    )


def test_worker_injects_native_tool_tokens_after_user_vars(client: TestClient) -> None:
    with session_scope() as db:
        db.add(
            models.PlatformSecret(
                key="ubuntu_pro_token",
                value_encrypted=credential_service.encrypt_secret("ProToken"),
            )
        )
        db.add(
            models.PlatformSecret(
                key="canonical_livepatch_token",
                value_encrypted=credential_service.encrypt_secret("LivepatchToken"),
            )
        )
        db.commit()
        values = _native_tool_vars(db)

    assert values == {
        "ubuntu_pro_token": "ProToken",
        "patching_ubuntu_pro_token": "ProToken",
        "canonical_livepatch_token": "LivepatchToken",
    }
