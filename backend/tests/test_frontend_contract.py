"""Regression tests for frontend contracts that protect the operator workflow."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_TS = ROOT / "web" / "src" / "api.ts"
APP_TSX = ROOT / "web" / "src" / "App.tsx"
INDEX_CSS = ROOT / "web" / "src" / "index.css"
NGINX_LOCATIONS = ROOT / "web" / "snippets" / "linsec-locations.conf"


def test_hosts_collection_path_is_not_redirected_by_nginx() -> None:
    source = NGINX_LOCATIONS.read_text(encoding="utf-8")

    # A broad prefix location redirects /api/v1/hosts to /api/v1/hosts/, while
    # FastAPI redirects that back to /api/v1/hosts. Scope the WebSocket location
    # to a concrete host id so the collection route reaches the generic proxy.
    assert "location /api/v1/hosts/ {" not in source
    assert "location ~ ^/api/v1/hosts/[0-9]+/terminal/ws$" in source


def test_unauthorized_responses_reset_frontend_auth_state() -> None:
    api_source = API_TS.read_text(encoding="utf-8")
    app_source = APP_TSX.read_text(encoding="utf-8")

    assert "response.status === 401" in api_source
    assert "linsec:unauthorized" in api_source
    assert "window.addEventListener('linsec:unauthorized'" in app_source
    assert "setAuthenticated(false)" in app_source
    assert "client.clear()" in app_source


def test_deployments_page_paginates_without_losing_scroll_position() -> None:
    api_source = API_TS.read_text(encoding="utf-8")
    app_source = APP_TSX.read_text(encoding="utf-8")

    assert "X-Total-Count" in api_source
    assert "keepPreviousData" in app_source
    assert "setOffset(0)" in app_source
    assert "window.scrollTo(0, 0)" in app_source


def test_frontend_sends_patch_target_pairs() -> None:
    app_source = APP_TSX.read_text(encoding="utf-8")

    assert "patch_target_packages" not in app_source
    assert "patch_target_cves" not in app_source
    assert "buildPatchTargets" in app_source
    assert "patch_targets: JSON.stringify(targets)" in app_source


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


def test_sidebar_can_be_collapsed_and_expanded() -> None:
    source = APP_TSX.read_text(encoding="utf-8")
    css = INDEX_CSS.read_text(encoding="utf-8")

    assert "linsec:sidebar-collapsed" in source
    assert "data-sidebar" in source
    assert 'aria-controls="main-nav"' in source
    assert 'id="main-nav"' in source
    assert "--sidebar-width" in css
    assert '.app[data-sidebar="collapsed"]' in css


def test_long_forms_open_in_an_accessible_modal() -> None:
    source = APP_TSX.read_text(encoding="utf-8")

    assert "createPortal" in source
    assert 'role="dialog"' in source
    assert 'aria-modal="true"' in source
    assert "'Escape'" in source
    assert "modal-backdrop" in source


def test_playbook_editor_opens_beside_the_library() -> None:
    source = APP_TSX.read_text(encoding="utf-8")
    css = INDEX_CSS.read_text(encoding="utf-8")

    assert 'className="playbook-workspace"' in source
    assert 'className="playbook-editor-area"' in source
    assert ".playbook-workspace" in css
    assert ".playbook-editor-area" in css


def test_patch_actions_explain_and_track_their_deployments() -> None:
    source = APP_TSX.read_text(encoding="utf-8")

    assert "Suivre l\u2019exécution" in source
    assert "patchBusy" in source
    assert "/deployments/${" in source
    assert "Vérification en lecture seule" in source
