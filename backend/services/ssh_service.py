"""SSH key and Ansible connectivity helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

import yaml

from ..errors import IntegrationUnavailable


def _ssh_dir() -> Path:
    return Path(__file__).resolve().parents[2] / ".ssh"


def ensure_keypair() -> tuple[Path, Path]:
    ssh_dir = _ssh_dir()
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ssh_dir, 0o700)
    private_key = ssh_dir / "id_ed25519"
    public_key = ssh_dir / "id_ed25519.pub"

    if not private_key.exists():
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-a",
                "64",
                "-N",
                "",
                "-C",
                "linsec-ansible",
                "-f",
                str(private_key),
            ],
            check=True,
            timeout=30,
        )
        os.chmod(private_key, 0o600)
        os.chmod(public_key, 0o644)
    if not public_key.exists():
        raise IntegrationUnavailable("SSH public key is missing")
    return private_key, public_key


def public_key() -> str:
    try:
        _, public_key_path = ensure_keypair()
        return public_key_path.read_text(encoding="utf-8").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise IntegrationUnavailable("unable to provision the Ansible SSH key") from exc


def scan_host_key(ip: str, port: int) -> tuple[str, str] | None:
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", "5", "-p", str(port), "-t", "ed25519,rsa", ip],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            encoded = parts[2].encode("ascii")
            blob = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error):
            continue
        digest = (
            base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
        )
        host = ip if port == 22 else f"[{ip}]:{port}"
        return f"{host} {parts[1]} {parts[2]}", f"SHA256:{digest}"
    return None


def scan_fingerprint(ip: str, port: int) -> str | None:
    scanned = scan_host_key(ip, port)
    return scanned[1] if scanned else None


def test_connection(
    *,
    host_name: str,
    ip: str,
    ansible_user: str,
    ansible_port: int,
    known_hosts_entry: str,
) -> tuple[bool, str, str]:
    private_key, _ = ensure_keypair()
    known_hosts_path: Path | None = None
    inventory_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".known_hosts", delete=False
        ) as known_hosts_handle:
            known_hosts_handle.write(known_hosts_entry + "\n")
            known_hosts_path = Path(known_hosts_handle.name)
        os.chmod(known_hosts_path, 0o600)

        inventory = {
            "all": {
                "hosts": {
                    host_name: {
                        "ansible_host": ip,
                        "ansible_user": ansible_user,
                        "ansible_port": ansible_port,
                        "ansible_private_key_file": str(private_key),
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".yml", delete=False
        ) as handle:
            yaml.safe_dump(inventory, handle, sort_keys=False)
            inventory_path = Path(handle.name)
        os.chmod(inventory_path, 0o600)

        environment = os.environ.copy()
        environment["ANSIBLE_HOST_KEY_CHECKING"] = "true"
        environment["ANSIBLE_SSH_ARGS"] = (
            f"-o UserKnownHostsFile={known_hosts_path} "
            "-o GlobalKnownHostsFile=/dev/null "
            "-o StrictHostKeyChecking=yes"
        )
        environment["ANSIBLE_TIMEOUT"] = "10"
        result = subprocess.run(
            [
                "ansible",
                "-i",
                str(inventory_path),
                "-m",
                "ansible.builtin.ping",
                host_name,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode == 0:
            return True, output[-2000:], "Reachable"
        return False, output[-2000:], "SSH connection failed"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc), "SSH connection failed"
    finally:
        if inventory_path is not None:
            inventory_path.unlink(missing_ok=True)
        if known_hosts_path is not None:
            known_hosts_path.unlink(missing_ok=True)


def _password_ssh(
    *,
    ip: str,
    port: int,
    user: str,
    password: str,
    known_hosts_entry: str,
    remote_command: str,
) -> bool:
    known_hosts_path: Path | None = None
    read_fd: int | None = None
    write_fd: int | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".known_hosts", delete=False
        ) as handle:
            handle.write(known_hosts_entry + "\n")
            known_hosts_path = Path(handle.name)
        os.chmod(known_hosts_path, 0o600)

        read_fd, write_fd = os.pipe()
        os.write(write_fd, password.encode("utf-8") + b"\n")
        os.close(write_fd)
        write_fd = None

        result = subprocess.run(
            [
                "sshpass",
                "-d",
                str(read_fd),
                "ssh",
                "-p",
                str(port),
                "-o",
                f"UserKnownHostsFile={known_hosts_path}",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "NumberOfPasswordPrompts=1",
                f"{user}@{ip}",
                remote_command,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            pass_fds=(read_fd,),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    else:
        return result.returncode == 0
    finally:
        if write_fd is not None:
            os.close(write_fd)
        if read_fd is not None:
            os.close(read_fd)
        if known_hosts_path is not None:
            known_hosts_path.unlink(missing_ok=True)


def test_password_connection(
    *,
    ip: str,
    port: int,
    user: str,
    password: str,
    known_hosts_entry: str,
) -> bool:
    return _password_ssh(
        ip=ip,
        port=port,
        user=user,
        password=password,
        known_hosts_entry=known_hosts_entry,
        remote_command="true",
    )


def install_public_key_with_password(
    *,
    ip: str,
    port: int,
    user: str,
    password: str,
    known_hosts_entry: str,
) -> bool:
    _, public_key_path = ensure_keypair()
    public_key = public_key_path.read_text(encoding="utf-8").strip()
    quoted_key = shlex.quote(public_key)
    remote_command = (
        "umask 077; mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        "touch ~/.ssh/authorized_keys && "
        f"if ! grep -Fqx -- {quoted_key} ~/.ssh/authorized_keys; then "
        f"printf '%s\\n' {quoted_key} >> ~/.ssh/authorized_keys; fi && "
        "chmod 600 ~/.ssh/authorized_keys"
    )
    return _password_ssh(
        ip=ip,
        port=port,
        user=user,
        password=password,
        known_hosts_entry=known_hosts_entry,
        remote_command=remote_command,
    )
