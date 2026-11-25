#!/usr/bin/env python3
"""Initialize missing secrets in a LinSec360 .env file."""

from pathlib import Path
import argparse
import secrets
import string

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

# Wazuh rejects passwords without lower/upper/digit/special characters. The
# special set avoids shell/dotenv delimiters such as quotes and backslashes.
SPECIAL_CHARACTERS = "!@#%^&*-_=+?"
PASSWORD_ALPHABETS = (
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    SPECIAL_CHARACTERS,
)
PASSWORD_LENGTH = 24

RANDOM_SECRET_KEYS = (
    "LINSEC_SECRET_KEY",
    "LINSEC_CREDENTIAL_ENCRYPTION_KEY",
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


def is_secure_wazuh_password(value: str) -> bool:
    return (
        8 <= len(value) <= 64
        and any(char in string.ascii_lowercase for char in value)
        and any(char in string.ascii_uppercase for char in value)
        and any(char in string.digits for char in value)
        and any(char in SPECIAL_CHARACTERS for char in value)
    )


def generate_wazuh_password() -> str:
    random = secrets.SystemRandom()
    characters = [random.choice(alphabet) for alphabet in PASSWORD_ALPHABETS]
    all_characters = "".join(PASSWORD_ALPHABETS)
    characters.extend(
        random.choice(all_characters)
        for _ in range(PASSWORD_LENGTH - len(characters))
    )
    random.shuffle(characters)
    return "".join(characters)


def initialize(path: Path = ENV_PATH) -> list[str]:
    values = read_env(path)
    initialized: list[str] = []

    for key in RANDOM_SECRET_KEYS:
        if not values.get(key):
            if key == "LINSEC_SECRET_KEY":
                value = secrets.token_hex(32)
            elif key == "LINSEC_CREDENTIAL_ENCRYPTION_KEY":
                # Fernet expects 32 url-safe base64 encoded random bytes.
                value = secrets.token_urlsafe(32)
            else:
                value = secrets.token_urlsafe(24)
            write_env_value(path, key, value)
            values[key] = value
            initialized.append(key)

    regenerated: set[str] = set()
    for key in PASSWORD_KEYS:
        if not values.get(key) or not is_secure_wazuh_password(values[key]):
            value = generate_wazuh_password()
            write_env_value(path, key, value)
            values[key] = value
            regenerated.add(key)
            initialized.append(key)

    if not values.get("WAZUH_API_USERNAME"):
        write_env_value(path, "WAZUH_API_USERNAME", "wazuh-wui")
        initialized.append("WAZUH_API_USERNAME")

    for password_key, hash_key in (
        ("WAZUH_ADMIN_PASSWORD", "WAZUH_ADMIN_PASSWORD_HASH"),
        ("WAZUH_DASHBOARD_PASSWORD", "WAZUH_DASHBOARD_PASSWORD_HASH"),
    ):
        if not values.get(hash_key) or password_key in regenerated:
            password = values[password_key].encode("utf-8")
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12)).decode()
            write_env_value(path, hash_key, password_hash)
            initialized.append(hash_key)

    return initialized


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=ENV_PATH,
        help=f"environment file to initialize (default: {ENV_PATH})",
    )
    args = parser.parse_args()
    initialized = initialize(args.env_file)
    print("Initialized: " + (", ".join(initialized) if initialized else "nothing"))


if __name__ == "__main__":
    main()
