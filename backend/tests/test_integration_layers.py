"""Tests for the Wazuh/OpenSCAP/Uyuni/hardening integration layers."""

from __future__ import annotations

import xmlrpc.client
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from backend import models
from backend.api import integrations as integrations_api
from backend.db import session_scope
from backend.errors import IntegrationUnavailable
from backend.ratelimit import login_rate_limiter
from backend.services import uyuni_service, wazuh_service

from .conftest import create_host

XCCDF_RESULT = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="linsec-test">
  <Profile id="cis">
    <title>CIS baseline</title>
  </Profile>
  <Group id="rules">
    <Rule id="rule-ssh" severity="high">
      <title>Disable root SSH login</title>
      <description>Root must not log in over SSH.</description>
      <fixtext>Set PermitRootLogin no.</fixtext>
    </Rule>
    <Rule id="rule-audit" severity="medium">
      <title>Enable auditd</title>
      <description>Audit daemon must be running.</description>
      <fixtext>systemctl enable --now auditd</fixtext>
    </Rule>
  </Group>
  <TestResult id="result" profile="cis">
    <score>50.0</score>
    <rule-result idref="rule-ssh"><result>pass</result></rule-result>
    <rule-result idref="rule-audit"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>
"""


def test_wazuh_agent_playbook_defaults_are_not_recursive():
    playbook_path = (
        Path(__file__).resolve().parents[2]
        / "taskengine"
        / "playbooks"
        / "wazuh-agent.yml"
    )
    play = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))[0]

    assert play["vars"]["wazuh_manager_address"] == (
        "{{ linsec_wazuh_manager_address | default('', true) }}"
    )
    assert play["vars"]["wazuh_agent_groups"] == (
        "{{ linsec_wazuh_agent_groups | default('default', true) }}"
    )
    assert play["vars"]["wazuh_manager_agent_port"] == (
        "{{ linsec_wazuh_manager_agent_port | default(1514) }}"
    )
    assert play["vars"]["wazuh_manager_enrollment_port"] == (
        "{{ linsec_wazuh_manager_enrollment_port | default(1515) }}"
    )


def test_openscap_playbook_discovers_a_distribution_specific_data_stream():
    playbook_path = (
        Path(__file__).resolve().parents[2]
        / "taskengine"
        / "playbooks"
        / "openscap-scan.yml"
    )
    play = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))[0]
    tasks = play["tasks"]

    assert any("ansible.builtin.find" in task for task in tasks)
    assert any(
        task.get("name") == "Validate that a matching SCAP data stream was installed"
        for task in tasks
    )
    scan_task = next(
        task
        for task in tasks
        if task.get("name") == "Run the OpenSCAP XCCDF evaluation"
    )
    assert "{{ openscap_ssg_datastream }}" in scan_task["ansible.builtin.command"]
    assert "ssg-rhel9-ds.xml" not in repr(play)


def _post_scan(client: TestClient, headers: dict[str, str], host_name: str = "web01"):
    return client.post(
        "/api/v1/compliance/scans",
        headers=headers,
        json={
            "host_name": host_name,
            "profile": "cis",
            "content": XCCDF_RESULT,
        },
    )


def test_openscap_scan_ingestion_and_summary(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)

    response = _post_scan(client, headers)
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["host_name"] == "web01"
    assert scan["profile"] == "cis"
    assert scan["score"] == 50.0
    assert {item["result"] for item in scan["findings"]} == {"pass", "fail"}
    fail = next(item for item in scan["findings"] if item["result"] == "fail")
    assert fail["title"] == "Enable auditd"
    assert fail["remediation"] == "systemctl enable --now auditd"

    response = client.get(f"/api/v1/compliance/scans/{scan['id']}")
    assert response.status_code == 200
    assert len(response.json()["findings"]) == 2

    response = client.get("/api/v1/compliance/summary")
    assert response.status_code == 200
    assert response.json()["hosts_scanned"] == 1
    assert response.json()["average_score"] == 50.0


def test_openscap_rejects_invalid_xml(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)
    response = client.post(
        "/api/v1/compliance/scans",
        headers=headers,
        json={"host_name": "web01", "content": "<not-xml"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "domain_error"


def test_openscap_json_export(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)
    scan_response = _post_scan(client, headers)
    assert scan_response.status_code == 201

    response = client.get("/api/v1/compliance/scans/export?format=json")
    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["host_name"] == "web01"
    assert len(payload[0]["findings"]) == 2


def test_openscap_csv_export(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)
    scan_response = _post_scan(client, headers)
    assert scan_response.status_code == 201

    response = client.get("/api/v1/compliance/scans/export?format=csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "scan_id,host_name,profile,status,score" in response.text
    assert "rule-ssh" in response.text
    assert "Disable root SSH login" in response.text


def test_hardening_ingestion_and_drift_summary(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)

    response = client.post(
        "/api/v1/hardening/results",
        headers=headers,
        json={
            "host_name": "web01",
            "checks": [
                {
                    "category": "selinux",
                    "control": "selinux.enforcing",
                    "expected": "Enforcing",
                    "actual": "Permissive",
                    "status": "fail",
                },
                {
                    "category": "ssh",
                    "control": "ssh.permit_root_login",
                    "expected": "no",
                    "actual": "no",
                    "status": "pass",
                },
            ],
        },
    )
    assert response.status_code == 201, response.text
    assert len(response.json()) == 2

    summary = client.get("/api/v1/hardening/summary").json()
    assert summary["checked_controls"] == 2
    assert summary["counts"]["fail"] == 1
    assert summary["score"] == 50.0
    assert summary["drifted_hosts"] == ["web01"]

    baseline = client.get("/api/v1/hardening/baseline").json()
    assert baseline["name"] == "linsec360-baseline"
    assert any(
        control["id"] == "selinux.enforcing" for control in baseline["controls"]
    )


def test_livepatch_ingestion_and_patch_summary(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)

    response = client.post(
        "/api/v1/patching/livepatch",
        headers=headers,
        json={
            "host_name": "web01",
            "kernel": "5.14.0-427.el9",
            "livepatch_state": "pending",
            "patch_available": True,
            "exposure_days": 12,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["patch_available"] is True

    response = client.get("/api/v1/patching/livepatch")
    assert response.status_code == 200
    assert response.json()[0]["exposure_days"] == 12

    summary = client.get("/api/v1/patching/summary").json()
    assert summary["livepatch"]["hosts"] == 1
    assert summary["livepatch"]["pending"] == 1
    assert summary["livepatch"]["max_exposure_days"] == 12


def test_alert_acknowledgement_is_audited(client: TestClient, csrf_headers):
    headers = csrf_headers()
    with session_scope() as db:
        alert = models.Alert(
            alert_id="alert-1",
            timestamp=datetime.now(UTC),
            rule_id="5710",
            rule_level=12,
            severity="critical",
            agent_name="web01",
            description="Possible rootkit",
        )
        db.add(alert)
        db.flush()
        alert_pk = alert.id

    response = client.get("/api/v1/alerts", params={"severity": "critical"})
    assert response.status_code == 200
    assert response.json()[0]["alert_id"] == "alert-1"

    response = client.post(
        f"/api/v1/alerts/{alert_pk}/ack", headers=headers
    )
    assert response.status_code == 200, response.text
    assert response.json()["acknowledged"] is True
    assert response.json()["acknowledged_by"] == "admin"

    summary = client.get("/api/v1/alerts/summary").json()
    assert summary["by_severity"] == {"critical": 1}
    assert summary["unacknowledged"] == {}


def test_patch_finding_resolution(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)
    with session_scope() as db:
        finding = models.PatchFinding(
            host_name="web01",
            package="openssl",
            cve="CVE-2026-0001",
            severity="critical",
            source="wazuh",
            status="open",
        )
        db.add(finding)
        db.flush()
        finding_id = finding.id

    response = client.get("/api/v1/patching/findings")
    assert response.status_code == 200
    assert response.json()[0]["package"] == "openssl"

    response = client.post(
        f"/api/v1/patching/findings/{finding_id}/resolve", headers=headers
    )
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"

    summary = client.get("/api/v1/patching/summary").json()
    assert summary["patches"]["open"] == 0


def test_posture_aggregates_local_layers(client: TestClient, csrf_headers):
    headers = csrf_headers()
    host = create_host(client, headers).json()
    _post_scan(client, headers)
    client.post(
        "/api/v1/hardening/results",
        headers=headers,
        json={
            "host_name": "web01",
            "checks": [
                {
                    "category": "selinux",
                    "control": "selinux.enforcing",
                    "status": "pass",
                }
            ],
        },
    )
    client.post(
        "/api/v1/patching/livepatch",
        headers=headers,
        json={
            "host_name": "web01",
            "kernel": "6.6.0",
            "livepatch_state": "applied",
        },
    )

    response = client.get(f"/api/v1/hosts/{host['id']}/posture")
    assert response.status_code == 200, response.text
    posture = response.json()
    assert posture["host_name"] == "web01"
    assert posture["compliance"]["score"] == 50.0
    assert posture["hardening"][0]["control"] == "selinux.enforcing"
    assert posture["livepatch"]["livepatch_state"] == "applied"
    # Wazuh is intentionally not configured in tests.
    assert posture["agent"] is None


def test_api_token_authentication_and_revocation(client: TestClient, csrf_headers):
    headers = csrf_headers()
    response = client.post(
        "/api/v1/auth/tokens",
        headers=headers,
        json={"name": "ci-runner", "expires_in_days": 30},
    )
    assert response.status_code == 201, response.text
    created = response.json()
    token = created["token"]
    assert token.startswith("linsec_")

    client.cookies.clear()
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["username"] == "admin"

    headers = csrf_headers()
    response = client.delete(
        f"/api/v1/auth/tokens/{created['id']}", headers=headers
    )
    assert response.status_code == 200

    client.cookies.clear()
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_login_rate_limit_blocks_repeated_failures(client: TestClient):
    login_rate_limiter.reset()
    try:
        for _ in range(5):
            response = client.post(
                "/api/v1/auth/login",
                json={"username": "nobody", "password": "wrong"},
            )
            assert response.status_code == 401
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "wrong"},
        )
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "rate_limited"
    finally:
        login_rate_limiter.reset()


def test_deployment_cancel_and_retry(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)
    client.post(
        "/api/v1/playbooks",
        headers=headers,
        json={
            "filename": "custom.yml",
            "content": "- name: Ping\n  hosts: all\n  tasks:\n    - ping:\n",
        },
    )
    response = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "environment": "production",
            "playbook": "custom.yml",
            "hosts": ["web01"],
        },
    )
    assert response.status_code == 202
    deployment_id = response.json()["id"]

    response = client.post(
        f"/api/v1/deployments/{deployment_id}/cancel", headers=headers
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "cancelled"

    response = client.post(
        f"/api/v1/deployments/{deployment_id}/retry", headers=headers
    )
    assert response.status_code == 202, response.text
    assert response.json()["id"] != deployment_id
    assert response.json()["status"] == "queued"


class FakeWazuhClient:
    def list_agents(self) -> list[dict]:
        return [
            wazuh_service.normalize_agent(
                {
                    "id": "001",
                    "name": "web01",
                    "ip": "10.0.0.10",
                    "status": "active",
                    "os": {"name": "Ubuntu", "version": "24.04"},
                    "version": "Wazuh v4.12.0",
                    "lastKeepAlive": "2026-11-06T10:00:00Z",
                }
            )
        ]

    def list_vulnerabilities(self, agent_id: str) -> list[dict]:
        assert agent_id == "001"
        return [
            wazuh_service.normalize_vulnerability(
                {
                    "package": {"name": "openssl", "version": "3.0.0"},
                    "cve": "CVE-2026-0001",
                    "severity": "High",
                    "status": "Active",
                }
            )
        ]


def test_wazuh_sync_matches_hosts_and_vulnerabilities(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)

    with session_scope() as db:
        agent_result = wazuh_service.sync_agents(db, client=FakeWazuhClient())
        assert agent_result["matched"] == 1
        vulnerability_result = wazuh_service.sync_vulnerabilities(
            db, client=FakeWazuhClient()
        )
        assert vulnerability_result["created"] == 1
        host = db.query(models.Host).filter(models.Host.name == "web01").one()
        assert host.agent_id == "001"
        assert host.os == "Ubuntu 24.04"

    data = client.get("/api/v1/kpis/overview").json()
    assert data["open_vulnerabilities"]["value"] == 1
    assert data["open_high_vulnerabilities"]["value"] == 1


class FakeUyuniClient:
    def list_systems(self) -> list[dict]:
        return [
            uyuni_service.normalize_system(
                {
                    "id": 42,
                    "name": "web01",
                    "status": "online",
                    "channelLabels": ["ubuntu-24.04-pool"],
                    "lastCheckin": "2026-11-06T10:00:00Z",
                }
            )
        ]

    def relevant_errata(self, system_id: int) -> list[dict]:
        assert system_id == 42
        return [
            uyuni_service.normalize_errata(
                {
                    "advisoryName": "USN-7000-1",
                    "packageName": "openssl",
                    "fixedVersion": "3.0.1",
                    "severity": "Important",
                    "rebootRequired": True,
                }
            )
        ]


def test_uyuni_client_uses_xmlrpc():
    settings = SimpleNamespace(
        uyuni_configured=True,
        uyuni_api_url="https://uyuni.example/rpc/api",
        uyuni_username="admin",
        uyuni_password="secret",
        uyuni_verify_tls=False,
        uyuni_timeout_seconds=10,
    )
    client = uyuni_service.UyuniClient(settings=settings)

    def handler(request: httpx.Request) -> httpx.Response:
        params, method = xmlrpc.client.loads(request.content)
        if method == "auth.login":
            assert params == ("admin", "secret")
            body = xmlrpc.client.dumps(("session-123",), methodresponse=True)
        elif method == "system.listSystems":
            assert params == ("session-123",)
            body = xmlrpc.client.dumps(
                ([{"id": 42, "name": "web01", "status": "online"}],),
                methodresponse=True,
            )
        elif method == "auth.logout":
            assert params == ("session-123",)
            body = xmlrpc.client.dumps((1,), methodresponse=True)
        else:
            raise AssertionError(method)
        return httpx.Response(200, content=body)

    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    systems = client.list_systems()
    assert systems[0]["uyuni_system_id"] == 42
    assert systems[0]["host_name"] == "web01"
    client.close()


def test_uyuni_sync_normalizes_systems_and_errata(client: TestClient, csrf_headers):
    headers = csrf_headers()
    create_host(client, headers)

    with session_scope() as db:
        systems = uyuni_service.sync_systems(db, client=FakeUyuniClient())
        assert systems["systems"] == 1
        assert systems["matched_hosts"] == 1
        errata = uyuni_service.sync_patch_findings(db, client=FakeUyuniClient())
        assert errata["created"] == 1
        finding = db.query(models.PatchFinding).one()
        assert finding.errata == "USN-7000-1"
        assert finding.reboot_required is True

    response = client.get("/api/v1/patching/uyuni")
    assert response.status_code == 200
    assert response.json()[0]["uyuni_system_id"] == 42


def test_integrations_report_unconfigured_without_fabricating(
    client: TestClient, login, monkeypatch
):
    monkeypatch.setattr(
        integrations_api,
        "get_settings",
        lambda: SimpleNamespace(
            wazuh_configured=False,
            uyuni_configured=False,
            ansible_playbook_bin="ansible-playbook",
        ),
    )
    login()
    response = client.get("/api/v1/integrations/status")
    assert response.status_code == 200
    assert response.json()["wazuh"]["configured"] is False
    assert response.json()["uyuni"]["configured"] is False
    assert response.json()["wazuh"]["reachable"] is None
    assert response.json()["uyuni"]["reachable"] is None
    assert response.json()["ansible"]["configured"] is True
    assert isinstance(response.json()["ansible"]["available"], bool)

    response = client.get("/api/v1/agents")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "integration_not_configured"


def test_integration_status_summarizes_addresses_without_exposing_credentials(
    client: TestClient, login, monkeypatch
):
    settings = SimpleNamespace(
        wazuh_configured=True,
        uyuni_configured=True,
        ansible_playbook_bin="ansible-playbook",
        wazuh_manager_address="",
        effective_wazuh_manager_address="siem.example",
        wazuh_manager_agent_port=1514,
        wazuh_manager_enrollment_port=1515,
        wazuh_api_url="https://api-user:secret@siem.example:55000/api",
        wazuh_indexer_url="https://indexer.example:9200",
        wazuh_dashboard_url="https://dashboard.example:5601",
        uyuni_api_url="https://admin:secret@uyuni.example/rpc/api",
        database_url="postgresql://db-user:secret@db.example:5432/linsec",
        redis_url="",
        ansible_ssh_private_key_path="/tmp/linsec-missing-key",
    )
    monkeypatch.setattr(integrations_api, "get_settings", lambda: settings)
    monkeypatch.setattr(
        integrations_api.stack_service,
        "resolve_addresses",
        lambda hostname: [f"192.0.2.{len(hostname or '')}"] if hostname else [],
    )
    monkeypatch.setattr(
        integrations_api.stack_service,
        "database_is_ready",
        lambda: True,
    )
    monkeypatch.setattr(
        integrations_api.shutil,
        "which",
        lambda binary: "/usr/bin/ansible-playbook",
    )

    login()
    response = client.get("/api/v1/integrations/status")

    assert response.status_code == 200
    components = {item["key"]: item for item in response.json()["stack"]}
    assert components["wazuh-api"]["endpoint"] == "https://siem.example:55000/api"
    assert components["wazuh-api"]["addresses"] == ["192.0.2.12"]
    assert components["wazuh-manager"]["configured"] is True
    assert components["wazuh-manager"]["endpoint"].startswith("TCP siem.example:1514")
    assert components["database"]["endpoint"] == "postgresql://db.example:5432"
    assert "secret" not in response.text


def test_stack_configuration_is_persisted_and_resettable(
    client: TestClient, csrf_headers
):
    headers = csrf_headers()
    payload = {
        "wazuh_manager_address": "192.0.2.40",
        "wazuh_manager_agent_port": 1514,
        "wazuh_manager_enrollment_port": 1516,
        "wazuh_api_url": "https://siem.example:55000",
        "wazuh_indexer_url": "https://indexer.example:9200",
        "wazuh_dashboard_url": "https://dashboard.example:5601",
        "uyuni_api_url": "https://uyuni.example/rpc/api",
    }

    invalid_payload = {**payload, "wazuh_api_url": "https://user:secret@siem.example"}
    response = client.put(
        "/api/v1/integrations/config",
        headers=headers,
        json=invalid_payload,
    )
    assert response.status_code == 422

    response = client.put(
        "/api/v1/integrations/config",
        headers=headers,
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == payload

    response = client.get("/api/v1/integrations/config")
    assert response.status_code == 200
    assert response.json() == payload

    response = client.get("/api/v1/integrations/status")
    components = {item["key"]: item for item in response.json()["stack"]}
    assert components["wazuh-manager"]["endpoint"].startswith("TCP 192.0.2.40:1514")
    assert "1516" in components["wazuh-manager"]["endpoint"]

    response = client.delete(
        "/api/v1/integrations/config",
        headers=headers,
    )
    assert response.status_code == 200
    from backend.config import get_settings

    assert (
        client.get("/api/v1/integrations/config").json()["wazuh_manager_address"]
        == get_settings().wazuh_manager_address
    )


def test_stack_configuration_hides_credentials_embedded_in_environment_urls(
    client: TestClient, monkeypatch
):
    from backend.config import get_settings
    from backend.services import runtime_configuration_service

    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "wazuh_api_url",
        "https://api-user:secret@siem.example:55000/api?token=hidden",
    )
    monkeypatch.setattr(runtime_configuration_service, "get_settings", lambda: settings)

    with session_scope() as db:
        configuration = runtime_configuration_service.read(db)

    assert configuration.wazuh_api_url == "https://siem.example:55000/api"
    assert "secret" not in configuration.model_dump_json()
    assert "hidden" not in configuration.model_dump_json()


def test_viewer_cannot_change_stack_configuration(client: TestClient, csrf_headers):
    headers = csrf_headers("viewer", "viewer-test-password-123")
    response = client.put(
        "/api/v1/integrations/config",
        headers=headers,
        json={
            "wazuh_manager_address": "",
            "wazuh_manager_agent_port": 1514,
            "wazuh_manager_enrollment_port": 1515,
            "wazuh_api_url": "",
            "wazuh_indexer_url": "",
            "wazuh_dashboard_url": "",
            "uyuni_api_url": "",
        },
    )
    assert response.status_code == 403


def test_manager_address_auto_detection_skips_docker_service_alias(monkeypatch):
    from backend.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "wazuh_manager_address", "")
    monkeypatch.setattr(
        settings,
        "wazuh_api_url",
        "https://wazuh.manager:55000",
    )
    assert settings.effective_wazuh_manager_address == ""

    monkeypatch.setattr(
        settings,
        "wazuh_api_url",
        "https://siem.example:55000",
    )
    assert settings.effective_wazuh_manager_address == "siem.example"


def test_wazuh_vulnerabilities_use_inventory_endpoint(monkeypatch):
    client = wazuh_service.WazuhClient(settings=SimpleNamespace())
    calls = []

    def fake_get(path, params):
        calls.append((path, params))
        return {
            "data": {
                "affected_items": [
                    {"package": {"name": "openssl"}, "cve": "CVE-2026-0001"}
                ]
            }
        }

    monkeypatch.setattr(client, "_get", fake_get)
    vulnerabilities = client.list_vulnerabilities("002")

    assert calls == [("/vulnerability/002/inventory", {"limit": 1000})]
    assert vulnerabilities[0]["cve"] == "CVE-2026-0001"


def test_wazuh_connection_test_reports_api_agent_count(
    client: TestClient, csrf_headers, monkeypatch
):
    monkeypatch.setattr(
        integrations_api,
        "get_settings",
        lambda: SimpleNamespace(wazuh_configured=True),
    )

    class FakeWazuhClient:
        def test_connection(self):
            return 3

    monkeypatch.setattr(
        integrations_api.wazuh_service,
        "get_client",
        lambda: FakeWazuhClient(),
    )

    response = client.post(
        "/api/v1/integrations/wazuh/test",
        headers=csrf_headers(),
    )

    assert response.status_code == 200
    assert response.json()["reachable"] is True
    assert response.json()["detail"] == "API accessible ; 3 agent(s) Wazuh récupéré(s)."


def test_wazuh_connection_test_exposes_safe_failure_detail(
    client: TestClient, csrf_headers, monkeypatch
):
    monkeypatch.setattr(
        integrations_api,
        "get_settings",
        lambda: SimpleNamespace(wazuh_configured=True),
    )

    class FakeWazuhClient:
        def test_connection(self):
            raise IntegrationUnavailable("certificate verification failed")

    monkeypatch.setattr(
        integrations_api.wazuh_service,
        "get_client",
        lambda: FakeWazuhClient(),
    )

    response = client.post(
        "/api/v1/integrations/wazuh/test",
        headers=csrf_headers(),
    )

    assert response.status_code == 200
    assert response.json()["reachable"] is False
    assert response.json()["detail"] == "certificate verification failed"


def test_uyuni_connection_test_reports_system_count(
    client: TestClient, csrf_headers, monkeypatch
):
    monkeypatch.setattr(
        integrations_api,
        "get_settings",
        lambda: SimpleNamespace(uyuni_configured=True),
    )

    class FakeUyuniClient:
        def test_connection(self):
            return 2

    monkeypatch.setattr(
        integrations_api.uyuni_service,
        "get_client",
        lambda: FakeUyuniClient(),
    )

    response = client.post(
        "/api/v1/integrations/uyuni/test",
        headers=csrf_headers(),
    )

    assert response.status_code == 200
    assert response.json()["reachable"] is True
    assert response.json()["detail"] == "XML-RPC accessible ; 2 système(s) Uyuni récupéré(s)."


def test_uyuni_connection_test_exposes_safe_failure_detail(
    client: TestClient, csrf_headers, monkeypatch
):
    monkeypatch.setattr(
        integrations_api,
        "get_settings",
        lambda: SimpleNamespace(uyuni_configured=True),
    )

    class FakeUyuniClient:
        def test_connection(self):
            raise IntegrationUnavailable("Uyuni XML-RPC login failed")

    monkeypatch.setattr(
        integrations_api.uyuni_service,
        "get_client",
        lambda: FakeUyuniClient(),
    )

    response = client.post(
        "/api/v1/integrations/uyuni/test",
        headers=csrf_headers(),
    )

    assert response.status_code == 200
    assert response.json()["reachable"] is False
    assert response.json()["detail"] == "Uyuni XML-RPC login failed"


def test_uyuni_client_reports_invalid_xml_as_integration_error():
    settings = SimpleNamespace(
        uyuni_configured=True,
        uyuni_api_url="http://uyuni/rpc/api",
        uyuni_username="admin",
        uyuni_password="secret",
        uyuni_verify_tls=True,
        uyuni_timeout_seconds=10,
    )
    client = uyuni_service.UyuniClient(settings=settings)
    client._session = "session-123"
    client._http = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"not XML")
        )
    )

    with pytest.raises(IntegrationUnavailable, match="Uyuni API request failed"):
        client._call("system.listSystems")
    client.close()


def test_ansible_test_checks_only_bounded_version_command(
    client: TestClient, csrf_headers, monkeypatch
):
    commands: list[tuple[list[str], int]] = []
    monkeypatch.setattr(integrations_api.shutil, "which", lambda binary: "/usr/bin/ansible-playbook")

    def fake_run(command, **kwargs):
        commands.append((command, kwargs["timeout"]))
        return SimpleNamespace(returncode=0, stdout="ansible-playbook [core 2.17.0]\n")

    monkeypatch.setattr(integrations_api.subprocess, "run", fake_run)
    response = client.post("/api/v1/integrations/ansible/test", headers=csrf_headers())
    assert response.status_code == 200
    assert response.json()["configured"] is True
    assert response.json()["available"] is True
    assert response.json()["reachable"] is True
    assert "2.17.0" in response.json()["detail"]
    assert commands == [(["/usr/bin/ansible-playbook", "--version"], 3)]

    viewer = client.post(
        "/api/v1/integrations/ansible/test",
        headers=csrf_headers("viewer", "viewer-test-password-123"),
    )
    assert viewer.status_code == 403
