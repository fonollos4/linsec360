#!/usr/bin/env python3
"""Synchronize Wazuh Indexer internal users with the current dotenv file.

The bind-mounted internal_users.yml is only read when the security index is
first initialized. Existing installations therefore keep old credentials until
they are updated through the Security API. This helper uses the generated admin
certificate so it works even when password authentication is stale. Hostname
checking is disabled because the request goes to the local published port; the
certificate chain is still verified against the generated root CA.
"""

from pathlib import Path
import argparse
import json
import re
import shlex
import ssl
import urllib.request


KEY_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if not separator or not KEY_PATTERN.fullmatch(key.strip()):
            continue
        try:
            parsed = shlex.split(raw_value, comments=True, posix=True)
        except ValueError as exc:
            raise ValueError(f"invalid dotenv value for {key}") from exc
        values[key.strip()] = " ".join(parsed)
    return values


def user_payloads(values: dict[str, str]) -> dict[str, dict]:
    required = (
        "WAZUH_ADMIN_PASSWORD_HASH",
        "WAZUH_DASHBOARD_PASSWORD_HASH",
    )
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise ValueError(f"missing required settings: {', '.join(missing)}")
    return {
        "admin": {
            "hash": values["WAZUH_ADMIN_PASSWORD_HASH"],
            "reserved": True,
            "backend_roles": ["admin"],
            "description": "LinSec360 administrator",
        },
        "kibanaserver": {
            "hash": values["WAZUH_DASHBOARD_PASSWORD_HASH"],
            "reserved": True,
            "description": "LinSec360 dashboard service user",
        },
    }


def sync_users(env_file: Path, cert_dir: Path, indexer_url: str) -> list[str]:
    values = read_env(env_file)
    payloads = user_payloads(values)

    context = ssl.create_default_context(cafile=str(cert_dir / "root-ca.pem"))
    context.check_hostname = False
    context.load_cert_chain(
        certfile=str(cert_dir / "admin.pem"),
        keyfile=str(cert_dir / "admin-key.pem"),
    )

    for user, payload in payloads.items():
        request = urllib.request.Request(
            f"{indexer_url.rstrip('/')}/_plugins/_security/api/internalusers/{user}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            status = getattr(response, "status", 200)
            if status >= 400:
                raise RuntimeError(f"failed to synchronize Wazuh user {user}: {status}")
    return sorted(payloads)


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument(
        "--cert-dir",
        type=Path,
        default=root / "config" / "wazuh" / "indexer_ssl_certs",
    )
    parser.add_argument("--indexer-url", default="https://127.0.0.1:9200")
    args = parser.parse_args()

    updated = sync_users(args.env_file, args.cert_dir, args.indexer_url)
    print("Synchronized Wazuh users: " + ", ".join(updated))


if __name__ == "__main__":
    main()
