"""Regression tests for frontend contracts that protect the operator workflow."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_TS = ROOT / "web" / "src" / "api.ts"
APP_TSX = ROOT / "web" / "src" / "App.tsx"


def test_unauthorized_responses_reset_frontend_auth_state() -> None:
    api_source = API_TS.read_text(encoding="utf-8")
    app_source = APP_TSX.read_text(encoding="utf-8")

    assert "response.status === 401" in api_source
    assert "linsec:unauthorized" in api_source
    assert "window.addEventListener('linsec:unauthorized'" in app_source
    assert "setAuthenticated(false)" in app_source
    assert "client.clear()" in app_source


def test_frontend_does_not_expose_ssh_fingerprint_workflow() -> None:
    api_source = API_TS.read_text(encoding="utf-8")
    app_source = APP_TSX.read_text(encoding="utf-8")

    assert "ssh_fingerprint" not in api_source
    assert "fingerprint_changed" not in api_source
    assert "fingerprint_pending" not in app_source
    assert "fingerprint_changed" not in app_source


def test_frontend_points_compliance_and_patching_to_current_playbooks() -> None:
    source = APP_TSX.read_text(encoding="utf-8")

    for playbook in (
        "openscap-scan.yml",
        "openscap-remediate.yml",
        "compliance-verify.yml",
        "patch-security.yml",
        "patch-verify.yml",
        "livepatch-check.yml",
    ):
        assert playbook in source

    assert "Option 2" not in source
    assert "Patching — Option 2" not in source
    assert "refreshAfterDeployment" in source
