import os
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.api import hosts as hosts_api
from backend.errors import ForbiddenError
from backend.schemas import SSHHostEnrollment
from backend.services import ssh_enrollment_service, ssh_service

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


def test_changing_host_ssh_target_clears_the_pinned_fingerprint(
    client: TestClient, csrf_headers
):
    headers = csrf_headers()
    fingerprint = "SHA256:" + "N" * 43
    response = client.post(
        "/api/v1/hosts",
        headers=headers,
        json={
            "name": "pinned-edit",
            "ip": "10.0.0.21",
            "environment": "production",
            "ssh_fingerprint": fingerprint,
        },
    )
    assert response.status_code == 201
    host_id = response.json()["id"]

    updated = client.patch(
        f"/api/v1/hosts/{host_id}",
        headers=headers,
        json={"ip": "10.0.0.22"},
    )

    assert updated.status_code == 200
    assert updated.json()["ssh_fingerprint"] is None
    assert updated.json()["ssh_status"] == "pending"


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


def test_ssh_test_requires_out_of_band_fingerprint_approval(
    client: TestClient, csrf_headers, monkeypatch
):
    headers = csrf_headers()
    created = create_host(client, headers)
    host_id = created.json()["id"]
    fingerprint = "SHA256:" + "A" * 43
    monkeypatch.setattr(
        hosts_api.ssh_service,
        "scan_host_key",
        lambda ip, port: (f"{ip} ssh-ed25519 AAAA", fingerprint),
    )
    monkeypatch.setattr(
        hosts_api.ssh_service,
        "test_connection",
        lambda **kwargs: pytest.fail(
            "SSH auth must not run before fingerprint approval"
        ),
    )

    response = client.post(f"/api/v1/hosts/{host_id}/ssh/test", headers=headers)

    assert response.status_code == 200
    assert response.json()["reachable"] is False
    assert response.json()["ssh_status"] == "fingerprint_pending"
    assert response.json()["fingerprint"] == fingerprint
    host = client.get(f"/api/v1/hosts/{host_id}").json()
    assert host["ssh_fingerprint"] is None


def test_ssh_fingerprint_approval_requires_live_match(
    client: TestClient, csrf_headers, monkeypatch
):
    headers = csrf_headers()
    created = create_host(client, headers)
    host_id = created.json()["id"]
    fingerprint = "SHA256:" + "B" * 43
    monkeypatch.setattr(
        hosts_api.ssh_service,
        "scan_host_key",
        lambda ip, port: (f"{ip} ssh-ed25519 AAAA", fingerprint),
    )

    mismatch = client.post(
        f"/api/v1/hosts/{host_id}/ssh/accept-fingerprint",
        headers=headers,
        json={"fingerprint": "SHA256:" + "C" * 43},
    )
    assert mismatch.status_code == 409
    assert client.get(f"/api/v1/hosts/{host_id}").json()["ssh_fingerprint"] is None

    approved = client.post(
        f"/api/v1/hosts/{host_id}/ssh/accept-fingerprint",
        headers=headers,
        json={"fingerprint": fingerprint},
    )
    assert approved.status_code == 200
    assert approved.json()["fingerprint"] == fingerprint
    assert (
        client.get(f"/api/v1/hosts/{host_id}").json()["ssh_fingerprint"] == fingerprint
    )


def test_ssh_test_uses_only_pinned_host_key(
    client: TestClient, csrf_headers, monkeypatch
):
    headers = csrf_headers()
    fingerprint = "SHA256:" + "D" * 43
    created = client.post(
        "/api/v1/hosts",
        headers=headers,
        json={
            "name": "pinned01",
            "ip": "10.0.0.11",
            "environment": "production",
            "ssh_fingerprint": fingerprint,
        },
    )
    assert created.status_code == 201
    host_id = created.json()["id"]
    known_hosts_entry = "10.0.0.11 ssh-ed25519 AAAA"
    monkeypatch.setattr(
        hosts_api.ssh_service,
        "scan_host_key",
        lambda ip, port: (known_hosts_entry, fingerprint),
    )
    connection = {"known_hosts_entry": None}

    def fake_connection(**kwargs):
        connection["known_hosts_entry"] = kwargs["known_hosts_entry"]
        return True, "pong", "Reachable"

    monkeypatch.setattr(hosts_api.ssh_service, "test_connection", fake_connection)
    response = client.post(f"/api/v1/hosts/{host_id}/ssh/test", headers=headers)

    assert response.status_code == 200
    assert response.json()["reachable"] is True
    assert connection["known_hosts_entry"] == known_hosts_entry


def test_bulk_host_import_adds_metadata_without_credentials(
    client: TestClient, csrf_headers
):
    headers = csrf_headers()
    host = {
        "name": "bulk01",
        "ip": "10.0.0.30",
        "environment": "production",
        "ssh_fingerprint": "SHA256:" + "E" * 43,
    }
    response = client.post(
        "/api/v1/hosts/import",
        headers=headers,
        json={"hosts": [host, host]},
    )

    assert response.status_code == 200
    assert len(response.json()["imported"]) == 1
    assert response.json()["imported"][0]["ssh_fingerprint"] == host["ssh_fingerprint"]
    assert response.json()["failed"] == [
        {
            "row": 3,
            "name": "bulk01",
            "detail": "host already exists in this environment",
        }
    ]

    rejected = client.post(
        "/api/v1/hosts/import",
        headers=headers,
        json={
            "hosts": [{**host, "name": "bulk02", "password": "must-not-be-accepted"}]
        },
    )
    assert rejected.status_code == 422


def test_ansible_ssh_test_pins_known_hosts_and_enables_checking(
    monkeypatch, tmp_path: Path
):
    private_key = tmp_path / "id_ed25519"
    private_key.touch()
    public_key = tmp_path / "id_ed25519.pub"
    public_key.touch()
    monkeypatch.setattr(
        ssh_service, "ensure_keypair", lambda: (private_key, public_key)
    )
    captured = {}

    def fake_run(command, **kwargs):
        environment = kwargs["env"]
        ssh_args = shlex.split(environment["ANSIBLE_SSH_ARGS"])
        known_hosts_argument = next(
            arg for arg in ssh_args if arg.startswith("UserKnownHostsFile=")
        )
        known_hosts_path = Path(known_hosts_argument.split("=", 1)[1])
        inventory_path = Path(command[2])
        captured["known_hosts"] = known_hosts_path.read_text(encoding="utf-8").strip()
        captured["checking"] = environment["ANSIBLE_HOST_KEY_CHECKING"]
        captured["strict"] = "StrictHostKeyChecking=yes" in ssh_args
        captured["global_hosts"] = "GlobalKnownHostsFile=/dev/null" in ssh_args
        captured["inventory"] = inventory_path.read_text(encoding="utf-8")
        captured["temporary_paths"] = (known_hosts_path, inventory_path)
        return SimpleNamespace(returncode=0, stdout="pong", stderr="")

    monkeypatch.setattr(ssh_service.subprocess, "run", fake_run)
    known_hosts_entry = "10.0.0.40 ssh-ed25519 AAAA"

    reachable, output, message = ssh_service.test_connection(
        host_name="test01",
        ip="10.0.0.40",
        ansible_user="linsec-ansible",
        ansible_port=22,
        known_hosts_entry=known_hosts_entry,
    )

    assert reachable is True
    assert output == "pong"
    assert message == "Reachable"
    assert captured["known_hosts"] == known_hosts_entry
    assert captured["checking"] == "true"
    assert captured["strict"] is True
    assert captured["global_hosts"] is True
    assert "ansible_private_key_file" in captured["inventory"]
    assert all(not path.exists() for path in captured["temporary_paths"])


def _enrollment_payload(
    *,
    name: str = "enrolled01",
    ip: str = "10.0.0.50",
    password: str = "temporary-secret",
    fingerprint: str = "SHA256:" + "F" * 43,
):
    return {
        "name": name,
        "ip": ip,
        "environment": "production",
        "security_level": "high",
        "groups": ["linux"],
        "ansible_user": "linsec-ansible",
        "ansible_port": 22,
        "password": password,
        "verified_fingerprint": fingerprint,
    }


def test_fingerprint_scan_returns_candidate_without_credentials(
    client: TestClient, csrf_headers, monkeypatch
):
    fingerprint = "SHA256:" + "G" * 43
    monkeypatch.setattr(ssh_service, "scan_fingerprint", lambda ip, port: fingerprint)

    response = client.post(
        "/api/v1/hosts/ssh/fingerprint",
        headers=csrf_headers(),
        json={"ip": "10.0.0.51", "ansible_port": 2222},
    )

    assert response.status_code == 200
    assert response.json() == {"fingerprint": fingerprint}


def test_enrollment_verifies_host_and_installs_key_in_background(
    client: TestClient, csrf_headers, monkeypatch
):
    headers = csrf_headers()
    fingerprint = "SHA256:" + "H" * 43
    known_hosts_entry = "10.0.0.52 ssh-ed25519 AAAA"
    monkeypatch.setattr(
        ssh_service, "scan_host_key", lambda ip, port: (known_hosts_entry, fingerprint)
    )
    password_checks = []
    key_installs = []
    monkeypatch.setattr(
        ssh_service,
        "test_password_connection",
        lambda **kwargs: password_checks.append(kwargs) or True,
    )
    monkeypatch.setattr(
        ssh_enrollment_service.ssh_service,
        "install_public_key_with_password",
        lambda **kwargs: key_installs.append(kwargs) or True,
    )
    monkeypatch.setattr(
        ssh_enrollment_service.ssh_service,
        "test_connection",
        lambda **kwargs: (True, "pong", "Reachable"),
    )

    response = client.post(
        "https://testserver/api/v1/hosts/enroll",
        headers=headers,
        json=_enrollment_payload(ip="10.0.0.52", fingerprint=fingerprint),
    )

    assert response.status_code == 201
    assert response.json()["ssh_status"] == "enrolling"
    assert response.json()["ssh_fingerprint"] == fingerprint
    assert "password" not in response.json()
    assert password_checks[0]["password"] == "temporary-secret"
    assert password_checks[0]["known_hosts_entry"] == known_hosts_entry
    assert key_installs[0]["password"] == "temporary-secret"
    assert key_installs[0]["known_hosts_entry"] == known_hosts_entry
    host = client.get(f"/api/v1/hosts/{response.json()['id']}").json()
    assert host["ssh_status"] == "reachable"
    assert host["ssh_error"] is None


def test_failed_password_authentication_does_not_add_host(
    client: TestClient, csrf_headers, monkeypatch
):
    fingerprint = "SHA256:" + "J" * 43
    monkeypatch.setattr(
        ssh_service,
        "scan_host_key",
        lambda ip, port: (f"{ip} ssh-ed25519 AAAA", fingerprint),
    )
    monkeypatch.setattr(ssh_service, "test_password_connection", lambda **kwargs: False)

    response = client.post(
        "https://testserver/api/v1/hosts/enroll",
        headers=csrf_headers(),
        json=_enrollment_payload(name="badpassword01", fingerprint=fingerprint),
    )

    assert response.status_code == 409
    assert "authentication failed" in response.json()["error"]["message"]
    assert client.get("/api/v1/hosts").json() == []


def test_enrollment_fingerprint_mismatch_never_uses_password(
    client: TestClient, csrf_headers, monkeypatch
):
    live_fingerprint = "SHA256:" + "K" * 43
    supplied_fingerprint = "SHA256:" + "L" * 43
    monkeypatch.setattr(
        ssh_service,
        "scan_host_key",
        lambda ip, port: (f"{ip} ssh-ed25519 AAAA", live_fingerprint),
    )
    monkeypatch.setattr(
        ssh_service,
        "test_password_connection",
        lambda **kwargs: pytest.fail(
            "password must not be sent on fingerprint mismatch"
        ),
    )

    response = client.post(
        "https://testserver/api/v1/hosts/enroll",
        headers=csrf_headers(),
        json=_enrollment_payload(name="mismatch01", fingerprint=supplied_fingerprint),
    )

    assert response.status_code == 409
    assert client.get("/api/v1/hosts").json() == []


def test_enrollment_requires_https_off_loopback():
    from fastapi import Request

    request = Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/hosts/enroll",
            "raw_path": b"/api/v1/hosts/enroll",
            "query_string": b"",
            "headers": [
                (b"host", b"linsec.example"),
                (b"origin", b"https://linsec.example"),
            ],
            "client": ("192.0.2.20", 50000),
            "server": ("linsec.example", 80),
        }
    )

    with pytest.raises(ForbiddenError, match="requires HTTPS"):
        hosts_api._require_secure_enrollment_transport(request)

    local_request = Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/hosts/enroll",
            "raw_path": b"/api/v1/hosts/enroll",
            "query_string": b"",
            "headers": [
                (b"host", b"localhost"),
                (b"origin", b"http://localhost"),
            ],
            "client": ("172.20.0.1", 50000),
            "server": ("localhost", 80),
        }
    )
    hosts_api._require_secure_enrollment_transport(local_request)


def test_enrollment_password_and_fingerprint_are_strictly_validated():
    with pytest.raises(ValueError, match="single line"):
        SSHHostEnrollment(**_enrollment_payload(password="not\nsingle-line"))

    with pytest.raises(ValueError):
        SSHHostEnrollment(
            **{
                **_enrollment_payload(),
                "ssh_fingerprint": "SHA256:" + "M" * 43,
            }
        )


def test_invalid_enrollment_password_is_not_reflected_in_api_errors(
    client: TestClient, csrf_headers
):
    response = client.post(
        "https://testserver/api/v1/hosts/enroll",
        headers=csrf_headers(),
        json=_enrollment_payload(
            name="invalidpassword01", password="do-not-echo\nthis"
        ),
    )

    assert response.status_code == 422
    assert "do-not-echo" not in response.text
    assert client.get("/api/v1/hosts").json() == []


def test_password_ssh_uses_pinned_host_key_without_command_line_password(
    monkeypatch, tmp_path: Path
):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["password"] = os.read(kwargs["pass_fds"][0], 1024)
        known_hosts_argument = next(
            arg for arg in command if arg.startswith("UserKnownHostsFile=")
        )
        known_hosts_path = Path(known_hosts_argument.split("=", 1)[1])
        captured["known_hosts"] = known_hosts_path.read_text(encoding="utf-8").strip()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ssh_service.subprocess, "run", fake_run)
    known_hosts_entry = "10.0.0.53 ssh-ed25519 AAAA"

    assert ssh_service.test_password_connection(
        ip="10.0.0.53",
        port=22,
        user="linsec-ansible",
        password="one-time-password",
        known_hosts_entry=known_hosts_entry,
    )

    assert "one-time-password" not in captured["command"]
    assert captured["password"] == b"one-time-password\n"
    assert captured["known_hosts"] == known_hosts_entry
    assert "StrictHostKeyChecking=yes" in captured["command"]


def test_key_installation_is_idempotent_and_sets_private_permissions(
    monkeypatch, tmp_path: Path
):
    private_key = tmp_path / "id_ed25519"
    public_key = tmp_path / "id_ed25519.pub"
    public_key.write_text("ssh-ed25519 AAAA linsec-ansible\n", encoding="utf-8")
    monkeypatch.setattr(
        ssh_service, "ensure_keypair", lambda: (private_key, public_key)
    )
    monkeypatch.setattr(
        ssh_service, "public_key", lambda: "ssh-ed25519 AAAA linsec-ansible"
    )
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["password"] = os.read(kwargs["pass_fds"][0], 1024)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ssh_service.subprocess, "run", fake_run)

    installed = ssh_service.install_public_key_with_password(
        ip="10.0.0.54",
        port=22,
        user="linsec-ansible",
        password="temporary-secret",
        known_hosts_entry="10.0.0.54 ssh-ed25519 AAAA",
    )

    assert installed is True
    assert captured["password"] == b"temporary-secret\n"
    assert "temporary-secret" not in captured["command"]
    remote_command = captured["command"][-1]
    assert "grep -Fqx" in remote_command
    assert "chmod 700 ~/.ssh" in remote_command
    assert "chmod 600 ~/.ssh/authorized_keys" in remote_command
