#!/usr/bin/env python3
"""Initialize missing Wazuh secrets in the repository .env file."""

from pathlib import Path
import secrets

try:
    import bcrypt
except ImportError as exc:
    raise SystemExit(
        "Missing Python dependency 'bcrypt'. Install it with: "
        "python3 -m pip install --user bcrypt"
    ) from exc


ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = ROOT / ".env"

PASSWORD_KEYS = (
    "WAZUH_ADMIN_PASSWORD",
    "WAZUH_DASHBOARD_PASSWORD",
    "WAZUH_API_PASSWORD",
)

RANDOM_SECRET_KEYS = (
    "LINSEC_SECRET_KEY",
    "LINSEC_BOOTSTRAP_ADMIN_PASSWORD",
    "POSTGRES_PASSWORD",
)


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def write_env_value(path: Path, key: str, value: str) -> None:
    quoted = "'" + value.replace("'", "'\"'\"'") + "'"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    updated = False
    output: list[str] = []
    for line in lines:
        if line.startswith(f"{key}="):
            output.append(f"{key}={quoted}")
            updated = True
        else:
            output.append(line)
    if not updated:
        output.append(f"{key}={quoted}")
    path.write_text("\n".join(output) + "\n", encoding="utf-8")
    path.chmod(0o600)


def initialize(path: Path = ENV_PATH) -> list[str]:
    values = read_env(path)
    initialized: list[str] = []

    for key in RANDOM_SECRET_KEYS:
        if not values.get(key):
            value = (
                secrets.token_hex(32)
                if key == "LINSEC_SECRET_KEY"
                else secrets.token_urlsafe(24)
            )
            write_env_value(path, key, value)
            values[key] = value
            initialized.append(key)

    for key in PASSWORD_KEYS:
        if not values.get(key):
            value = secrets.token_urlsafe(24)
            write_env_value(path, key, value)
            values[key] = value
            initialized.append(key)

    if not values.get("WAZUH_API_USERNAME"):
        write_env_value(path, "WAZUH_API_USERNAME", "wazuh-wui")
        initialized.append("WAZUH_API_USERNAME")

    for password_key, hash_key in (
        ("WAZUH_ADMIN_PASSWORD", "WAZUH_ADMIN_PASSWORD_HASH"),
        ("WAZUH_DASHBOARD_PASSWORD", "WAZUH_DASHBOARD_PASSWORD_HASH"),
    ):
        if not values.get(hash_key):
            password = values[password_key].encode("utf-8")
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12)).decode()
            write_env_value(path, hash_key, password_hash)
            initialized.append(hash_key)

    return initialized


if __name__ == "__main__":
    print("Initialized: " + ", ".join(initialize()))
