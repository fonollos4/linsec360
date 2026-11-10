import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.errors import IntegrationUnavailable
from backend.services import ssh_service


def _configured_key(monkeypatch, key_path: Path) -> None:
    monkeypatch.setattr(
        ssh_service,
        "get_settings",
        lambda: SimpleNamespace(ansible_ssh_private_key_path=key_path),
    )
    monkeypatch.setattr(ssh_service, "_ssh_dir", lambda: key_path.parent / "default")


def test_ensure_keypair_uses_a_mounted_private_key(monkeypatch, tmp_path: Path):
    private_key = tmp_path / "team-key"
    private_key.write_text("private key material", encoding="utf-8")
    private_key.chmod(0o600)
    _configured_key(monkeypatch, private_key)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample",
            stderr="",
        )

    monkeypatch.setattr(ssh_service.subprocess, "run", fake_run)

    key_path, public_path = ssh_service.ensure_keypair()

    assert key_path == private_key
    assert public_path == tmp_path / "team-key.pub"
    assert commands[0][:5] == ["ssh-keygen", "-y", "-P", "", "-f"]


def test_ensure_keypair_does_not_change_permissions_on_existing_default_key(
    monkeypatch, tmp_path: Path
):
    private_key = tmp_path / "id_ed25519"
    private_key.write_text("private key material", encoding="utf-8")
    private_key.chmod(0o600)
    monkeypatch.setattr(ssh_service, "_ssh_dir", lambda: tmp_path)
    monkeypatch.setattr(ssh_service, "private_key_path", lambda: private_key)
    monkeypatch.setattr(
        ssh_service,
        "_derive_public_key",
        lambda path: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample",
    )
    monkeypatch.setattr(
        ssh_service.os,
        "chmod",
        lambda *args, **kwargs: pytest.fail("existing mounted key must not be changed"),
    )

    key_path, public_path = ssh_service.ensure_keypair()

    assert key_path == private_key
    assert public_path == tmp_path / "id_ed25519.pub"


def test_ensure_keypair_rejects_group_or_world_readable_private_key(
    monkeypatch, tmp_path: Path
):
    private_key = tmp_path / "team-key"
    private_key.write_text("private key material", encoding="utf-8")
    private_key.chmod(0o644)
    _configured_key(monkeypatch, private_key)

    with pytest.raises(IntegrationUnavailable, match="permissions"):
        ssh_service.ensure_keypair()


def test_ensure_keypair_rejects_invalid_or_encrypted_key(
    monkeypatch, tmp_path: Path
):
    private_key = tmp_path / "team-key"
    private_key.write_text("private key material", encoding="utf-8")
    private_key.chmod(0o600)
    _configured_key(monkeypatch, private_key)
    monkeypatch.setattr(
        ssh_service.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr=""),
    )

    with pytest.raises(IntegrationUnavailable, match="invalid or passphrase-protected"):
        ssh_service.ensure_keypair()


def test_scan_host_key_prefers_approved_key_and_is_order_independent(monkeypatch):
    rsa_blob = "AQID"
    rsa_digest = base64.b64encode(
        hashlib.sha256(base64.b64decode(rsa_blob)).digest()
    ).decode("ascii").rstrip("=")
    monkeypatch.setattr(
        ssh_service.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                f"192.0.2.10 ssh-rsa {rsa_blob}\n"
                "192.0.2.10 ssh-ed25519 AAAA\n"
            ),
        ),
    )

    preferred = ssh_service.scan_host_key("192.0.2.10", 22)
    approved = ssh_service.scan_host_key(
        "192.0.2.10",
        22,
        expected_fingerprint=f"SHA256:{rsa_digest}",
    )

    assert preferred is not None
    assert preferred[0].split()[1] == "ssh-ed25519"
    assert approved is not None
    assert approved[0] == f"192.0.2.10 ssh-rsa {rsa_blob}"
    assert approved[1] == f"SHA256:{rsa_digest}"
