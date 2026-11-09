"""SSH key and Ansible connectivity helpers."""

from __future__ import annotations

import base64
import hashlib
import os
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


def scan_fingerprint(ip: str, port: int) -> str | None:
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
        encoded = parts[2].encode("ascii")
        blob = base64.b64decode(encoded, validate=True)
        digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
        return f"SHA256:{digest}"
    return None


def test_connection(
    *,
    host_name: str,
    ip: str,
    ansible_user: str,
    ansible_port: int,
) -> tuple[bool, str, str]:
    private_key, _ = ensure_keypair()
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

    try:
        environment = os.environ.copy()
        # Fingerprints are detected and persisted separately before each test.
        # This keeps first enrollment usable while mismatches are blocked by
        # the host SSH workflow above.
        environment["ANSIBLE_HOST_KEY_CHECKING"] = "false"
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
        inventory_path.unlink(missing_ok=True)
