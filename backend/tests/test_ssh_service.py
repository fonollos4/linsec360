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
