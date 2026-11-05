import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RENDERER_PATH = ROOT / "config" / "scripts" / "render-wazuh-config.py"
SPEC = importlib.util.spec_from_file_location("wazuh_config_renderer", RENDERER_PATH)
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


def build_template_tree(root):
    wazuh_dir = root / "config" / "wazuh"
    indexer_dir = wazuh_dir / "indexer"
    dashboard_dir = wazuh_dir / "dashboard"
    indexer_dir.mkdir(parents=True)
    dashboard_dir.mkdir(parents=True)
    (indexer_dir / "internal_users.yml.template").write_text(
        'admin:\n  hash: __ADMIN_HASH__\n'
        'kibanaserver:\n  hash: __DASHBOARD_HASH__\n'
    )
    (dashboard_dir / "wazuh.yml.template").write_text(
        'username: __API_USERNAME__\npassword: __API_PASSWORD__\n'
    )


def valid_environment():
    return {
        "WAZUH_ADMIN_PASSWORD": "admin-secret",
        "WAZUH_ADMIN_PASSWORD_HASH": "$2y$12$" + "a" * 53,
        "WAZUH_DASHBOARD_PASSWORD": "dashboard-secret",
        "WAZUH_DASHBOARD_PASSWORD_HASH": "$2b$12$" + "b" * 53,
        "WAZUH_API_USERNAME": "wazuh-wui",
        "WAZUH_API_PASSWORD": 'api-"secret',
    }


def test_renderer_writes_quoted_private_runtime_config(tmp_path):
    build_template_tree(tmp_path)
    renderer.render_config(tmp_path, valid_environment())
    generated_dir = tmp_path / "config" / "wazuh" / "generated"
    indexer_config = generated_dir / "internal_users.yml"
    dashboard_config = generated_dir / "wazuh.yml"

    assert indexer_config.exists()
    assert '"$2y$12$' in indexer_config.read_text()
    assert '"api-\\"secret"' in dashboard_config.read_text()
    assert os.stat(generated_dir).st_mode & 0o777 == 0o700
    assert os.stat(dashboard_config).st_mode & 0o777 == 0o644


def test_renderer_requires_passwords_and_bcrypt_hashes(tmp_path):
    build_template_tree(tmp_path)
    with pytest.raises(ValueError, match="Missing required"):
        renderer.render_config(tmp_path, {})

    environment = valid_environment()
    environment["WAZUH_ADMIN_PASSWORD_HASH"] = "not-a-hash"
    with pytest.raises(ValueError, match="bcrypt hash"):
        renderer.render_config(tmp_path, environment)


def test_renderer_loads_quoted_values_from_root_env_file(monkeypatch, tmp_path):
    build_template_tree(tmp_path)
    environment = valid_environment()
    for key in environment:
        monkeypatch.delenv(key, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(f"{key}='{value}'" for key, value in environment.items())
    )

    renderer.render_config(tmp_path)
    generated_dashboard = (
        tmp_path / "config" / "wazuh" / "generated" / "wazuh.yml"
    )
    assert '"api-\\"secret"' in generated_dashboard.read_text()
    assert os.stat(env_file).st_mode & 0o777 == 0o600
