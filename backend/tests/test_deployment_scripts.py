"""Regression tests for the automated environment deployment helpers."""

from __future__ import annotations

import importlib.util
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "config" / "scripts"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_update_env_sets_values_preserves_other_entries_and_secures_file(
    tmp_path: Path,
):
    module = _load_module("linsec_update_env", SCRIPTS / "update-env.py")
    env_file = tmp_path / ".env"
    env_file.write_text(
        "EXISTING=old value\n# keep this comment\nUNTOUCHED='keep me'\n",
        encoding="utf-8",
    )

    updated = module.set_values(
        env_file,
        {
            "EXISTING": "new value",
            "WITH_QUOTE": "it's fine",
        },
    )

    assert updated == ["EXISTING", "WITH_QUOTE"]
    content = env_file.read_text(encoding="utf-8")
    assert "EXISTING='new value'" in content
    assert "# keep this comment" in content
    assert "UNTOUCHED='keep me'" in content
    assert "WITH_QUOTE='it'\"'\"'s fine'" in content
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_update_env_rejects_symlinked_env_file(tmp_path: Path):
    module = _load_module("linsec_update_env_symlink", SCRIPTS / "update-env.py")
    target = tmp_path / "real.env"
    target.write_text("A=1\n", encoding="utf-8")
    link = tmp_path / ".env"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        module.set_values(link, {"A": "2"})


def test_render_wazuh_config_honors_env_file_and_output_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    module = _load_module("linsec_render_wazuh", SCRIPTS / "render-wazuh-config.py")
    for key in (
        "WAZUH_ADMIN_PASSWORD",
        "WAZUH_ADMIN_PASSWORD_HASH",
        "WAZUH_DASHBOARD_PASSWORD",
        "WAZUH_DASHBOARD_PASSWORD_HASH",
        "WAZUH_API_USERNAME",
        "WAZUH_API_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)

    indexer_template = (
        tmp_path / "config" / "wazuh" / "indexer" / "internal_users.yml.template"
    )
    dashboard_template = (
        tmp_path / "config" / "wazuh" / "dashboard" / "wazuh.yml.template"
    )
    indexer_template.parent.mkdir(parents=True)
    dashboard_template.parent.mkdir(parents=True)
    indexer_template.write_text("hash: __ADMIN_HASH__\n", encoding="utf-8")
    dashboard_template.write_text(
        "user: __API_USERNAME__\npassword: __API_PASSWORD__\n", encoding="utf-8"
    )

    valid_hash = "$2b$12$" + "a" * 53
    env_file = tmp_path / ".env.development"
    env_file.write_text(
        "\n".join(
            [
                "WAZUH_ADMIN_PASSWORD=admin-secret",
                f"WAZUH_ADMIN_PASSWORD_HASH={valid_hash}",
                "WAZUH_DASHBOARD_PASSWORD=dashboard-secret",
                f"WAZUH_DASHBOARD_PASSWORD_HASH={valid_hash}",
                "WAZUH_API_USERNAME=dev-user",
                "WAZUH_API_PASSWORD=dev-secret",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "generated-development"

    module.render_config(
        tmp_path,
        env_file=env_file,
        output_dir=output_dir,
    )

    internal_users = (output_dir / "internal_users.yml").read_text(encoding="utf-8")
    wazuh = (output_dir / "wazuh.yml").read_text(encoding="utf-8")
    assert valid_hash in internal_users
    assert "user: \"dev-user\"" in wazuh
    assert "password: \"dev-secret\"" in wazuh
    assert not (tmp_path / "config" / "wazuh" / "generated").exists()


def test_init_wazuh_env_generates_policy_compliant_passwords():
    module = _load_module("linsec_init_wazuh_env", SCRIPTS / "init-wazuh-env.py")

    password = module.generate_wazuh_password()

    assert module.is_secure_wazuh_password(password)
    assert not module.is_secure_wazuh_password("short")
    assert not module.is_secure_wazuh_password("nouppercase1!")
    assert not module.is_secure_wazuh_password("NoSpecial123")


def test_init_wazuh_env_replaces_insecure_password_and_its_hash(tmp_path: Path):
    module = _load_module("linsec_init_wazuh_env_replace", SCRIPTS / "init-wazuh-env.py")
    env_file = tmp_path / ".env"
    valid_hash = "$2b$12$" + "a" * 53
    original_admin_hash = "$2b$12$" + "b" * 53
    env_file.write_text(
        "\n".join(
            [
                "WAZUH_ADMIN_PASSWORD='AdminPass1!'",
                f"WAZUH_ADMIN_PASSWORD_HASH='{original_admin_hash}'",
                "WAZUH_DASHBOARD_PASSWORD='Dashboard1!'",
                f"WAZUH_DASHBOARD_PASSWORD_HASH='{valid_hash}'",
                "WAZUH_API_USERNAME=wazuh-wui",
                "WAZUH_API_PASSWORD=no-special-characters-here",
                "LINSEC_SECRET_KEY=secret",
                "LINSEC_BOOTSTRAP_ADMIN_PASSWORD=adminpass",
                "POSTGRES_PASSWORD=postgrespass",
                "LINSEC_CREDENTIAL_ENCRYPTION_KEY=fernetkey",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    initialized = module.initialize(env_file)
    values = {
        key: value.strip().strip("'\"")
        for key, value in (
            line.split("=", 1)
            for line in env_file.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )
    }

    assert "WAZUH_API_PASSWORD" in initialized
    assert module.is_secure_wazuh_password(values["WAZUH_API_PASSWORD"])
    assert values["WAZUH_ADMIN_PASSWORD_HASH"] == original_admin_hash
    assert values["WAZUH_DASHBOARD_PASSWORD_HASH"] == valid_hash


def test_sync_wazuh_users_builds_payloads_from_env_file(tmp_path: Path):
    module = _load_module("linsec_sync_wazuh_users", SCRIPTS / "sync-wazuh-users.py")
    env_file = tmp_path / ".env"
    env_file.write_text(
        "WAZUH_ADMIN_PASSWORD_HASH=admin-hash\n"
        "WAZUH_DASHBOARD_PASSWORD_HASH=dashboard-hash\n",
        encoding="utf-8",
    )

    values = module.read_env(env_file)
    payloads = module.user_payloads(values)

    assert payloads["admin"]["hash"] == "admin-hash"
    assert payloads["admin"]["backend_roles"] == ["admin"]
    assert payloads["kibanaserver"]["hash"] == "dashboard-hash"


def test_deploy_script_uses_distinct_projects_and_ip_bind(tmp_path: Path):
    script = (SCRIPTS / "deploy-stack.sh").read_text(encoding="utf-8")

    assert 'PROJECT="linsec360"' in script
    assert 'PROJECT="linsec360-dev"' in script
    assert "LINSEC_BIND_ADDRESS=0.0.0.0" in script
    assert "http://$SERVER_IP:$API_PORT/health" in script
    assert 'ENV_FILE_REL=".env"' in script
    assert 'ENV_FILE_REL=".env.development"' in script

    compose = (ROOT / "docker-compose.v2.yml").read_text(encoding="utf-8")
    # Wazuh's init script appends to /etc/filebeat/filebeat.yml on every start;
    # a persistent volume turns that into corrupt YAML after a redeploy.
    assert "filebeat_etc" not in compose
