"""Shared pytest fixtures for the FastAPI backend."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_ROOT = Path(tempfile.mkdtemp(prefix="linsec-tests-"))

os.environ["LINSEC_ENVIRONMENT"] = "test"
os.environ["LINSEC_SECRET_KEY"] = "test-secret-key-that-is-at-least-32-bytes"
os.environ["LINSEC_CREDENTIAL_ENCRYPTION_KEY"] = Fernet.generate_key().decode("ascii")
os.environ["LINSEC_AUTO_CREATE_TABLES"] = "true"
os.environ["LINSEC_COOKIE_SECURE"] = "false"
os.environ["LINSEC_REDIS_URL"] = ""
os.environ["LINSEC_BOOTSTRAP_ADMIN_PASSWORD"] = ""
os.environ["LINSEC_LOG_DIR"] = str(TEST_ROOT / "logs")
os.environ["LINSEC_TASKENGINE_DIR"] = str(TEST_ROOT / "taskengine")
os.environ["LINSEC_PLAYBOOK_DIR"] = str(TEST_ROOT / "var" / "playbooks")
os.environ["LINSEC_INVENTORY_DIR"] = str(TEST_ROOT / "var" / "inventories")
os.environ["LINSEC_BUNDLED_PLAYBOOKS_DIR"] = str(TEST_ROOT / "taskengine" / "playbooks")

shutil.copytree(
    REPO_ROOT / "taskengine" / "playbooks",
    TEST_ROOT / "taskengine" / "playbooks",
    dirs_exist_ok=True,
)
(TEST_ROOT / "logs").mkdir(parents=True, exist_ok=True)

from backend import models  # noqa: E402
from backend.db import create_all, reset_database, session_scope  # noqa: E402
from backend.main import app  # noqa: E402
from backend.queue import set_queue  # noqa: E402
from backend.security import hash_password  # noqa: E402

ADMIN_PASSWORD = "admin-test-password-123"
VIEWER_PASSWORD = "viewer-test-password-123"


class RecordingQueue:
    def __init__(self) -> None:
        self.enqueued: list[str] = []

    def enqueue_deployment(self, deployment_id: str) -> None:
        self.enqueued.append(deployment_id)


@pytest.fixture(autouse=True)
def queue():
    recording = RecordingQueue()
    set_queue(recording)
    yield recording
    set_queue(None)


@pytest.fixture
def client(tmp_path: Path):
    reset_database(f"sqlite:///{tmp_path / 'linsec.db'}")
    create_all()
    with session_scope() as db:
        db.add(
            models.User(
                username="admin",
                password_hash=hash_password(ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            )
        )
        db.add(
            models.User(
                username="viewer",
                password_hash=hash_password(VIEWER_PASSWORD),
                role="viewer",
                is_active=True,
            )
        )
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def login(client: TestClient):
    def _login(username: str = "admin", password: str = ADMIN_PASSWORD) -> str:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        assert response.status_code == 200, response.text
        csrf = client.cookies.get("linsec_csrf")
        assert csrf
        return csrf

    return _login


@pytest.fixture
def csrf_headers(login):
    def _headers(
        username: str = "admin", password: str = ADMIN_PASSWORD
    ) -> dict[str, str]:
        return {"X-CSRF-Token": login(username, password)}

    return _headers


def create_host(
    client: TestClient,
    headers: dict[str, str],
    *,
    name: str = "web01",
    ip: str = "10.0.0.10",
    environment: str = "production",
    security_level: str = "high",
    groups: list[str] | None = None,
    ansible_user: str = "linsec-ansible",
    ssh_fingerprint: str | None = None,
):
    payload = {
        "name": name,
        "ip": ip,
        "environment": environment,
        "security_level": security_level,
        "groups": groups or ["web"],
        "ansible_user": ansible_user,
    }
    if ssh_fingerprint is not None:
        payload["ssh_fingerprint"] = ssh_fingerprint
    return client.post(
        "/api/v1/hosts",
        headers=headers,
        json=payload,
    )


def create_playbook(
    client: TestClient,
    headers: dict[str, str],
    *,
    filename: str = "custom.yml",
    content: str = "- name: Ping\n  hosts: all\n  tasks:\n    - ansible.builtin.ping:\n",
):
    return client.post(
        "/api/v1/playbooks",
        headers=headers,
        json={"filename": filename, "content": content},
    )
