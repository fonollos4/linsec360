"""Regression tests for the taskengine hardening automation."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKENGINE = ROOT / "taskengine"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _all_tasks(tasks: list[dict]) -> list[dict]:
    """Flatten tasks nested in blocks, rescues and always sections."""
    flattened: list[dict] = []
    for task in tasks:
        flattened.append(task)
        for section in ("block", "rescue", "always"):
            nested = task.get(section)
            if isinstance(nested, list):
                flattened.extend(_all_tasks(nested))
    return flattened


def _task_by_name(tasks: list[dict], name: str) -> dict:
    return next(task for task in _all_tasks(tasks) if task.get("name") == name)


def test_inventory_defines_required_os_family_groups():
    inventory = yaml.safe_load(_read(TASKENGINE / "inventories/production/hosts.yml"))
    children = inventory["all"]["children"]
    assert "redhat_family" in children
    assert "debian_family" in children
    assert children["redhat_family"]["hosts"]
    assert children["debian_family"]["hosts"]


def test_site_playbook_uses_all_four_roles_in_order():
    play = yaml.safe_load(_read(TASKENGINE / "playbooks/site.yml"))[0]
    roles = [
        role.get("role") if isinstance(role, dict) else role for role in play["roles"]
    ]
    assert roles == [
        "cleanup_uyuni",
        "hardening_mac",
        "hardening_openscap",
        "patching_option2",
    ]


def test_cleanup_role_removes_salt_and_keeps_ssh():
    tasks = yaml.safe_load(_read(TASKENGINE / "roles/cleanup_uyuni/tasks/main.yml"))
    names = [task.get("name") for task in tasks]
    assert "Remove Salt/Uyuni client packages" in names
    assert "Remove Salt/Uyuni configuration and cache directories" in names
    assert "Keep SSH reachable after agent removal" in names
    assert _task_by_name(tasks, "Keep SSH reachable after agent removal")[
        "ansible.builtin.service"
    ]["state"] == "started"


def test_openscap_role_audits_before_and_after_remediation():
    tasks = yaml.safe_load(_read(TASKENGINE / "roles/hardening_openscap/tasks/main.yml"))
    defaults = yaml.safe_load(
        _read(TASKENGINE / "roles/hardening_openscap/defaults/main.yml")
    )
    assert defaults["openscap_log_dir"] == "/var/log/linsec360"

    before = _task_by_name(tasks, "Run the initial OpenSCAP audit")
    after = _task_by_name(tasks, "Re-scan the host after remediation")
    for task, prefix in ((before, "before"), (after, "after")):
        command = task["ansible.builtin.command"]["cmd"]
        xml_var = f"openscap_{prefix}_xml"
        html_var = f"openscap_{prefix}_html"
        assert "oscap xccdf eval --profile" in command
        assert f"--results {{{{ {xml_var} }}}}" in command
        assert f"--report {{{{ {html_var} }}}}" in command
        assert defaults[xml_var] == f"{{{{ openscap_log_dir }}}}/oscap-{prefix}.xml"
        assert defaults[html_var] == f"{{{{ openscap_log_dir }}}}/oscap-{prefix}.html"
        assert task["failed_when"].endswith("not in [0, 2]")


def test_openscap_remediation_excludes_ssh_and_wazuh_ports():
    defaults = yaml.safe_load(
        _read(TASKENGINE / "roles/hardening_openscap/defaults/main.yml")
    )
    rules = defaults["openscap_denied_rule_patterns"]
    commands = defaults["openscap_denied_command_patterns"]
    assert any("sshd" in pattern for pattern in rules)
    assert any("1514" in pattern for pattern in rules)
    assert any("1515" in pattern for pattern in rules)
    assert any("sshd" in pattern for pattern in commands)
    assert any("1514" in pattern for pattern in commands)
    assert any("1515" in pattern for pattern in commands)


def test_remediation_filter_drops_dangerous_rule_blocks(tmp_path: Path):
    script = TASKENGINE / "roles/hardening_openscap/files/filter_oscap_remediation.py"
    results = tmp_path / "results.xml"
    results.write_text(
        """<?xml version="1.0"?>
<TestResult xmlns="urn:oasis:names:tc:xccdf-1.0:xccdf">
  <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_service_disabled">
    <result>fail</result>
  </rule-result>
  <rule-result idref="xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd">
    <result>fail</result>
  </rule-result>
</TestResult>
""",
        encoding="utf-8",
    )
    fix = tmp_path / "fix.sh"
    fix.write_text(
        """#!/bin/bash
# xccdf_org.ssgproject.content_rule_sshd_service_disabled
systemctl stop sshd
# xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd
chmod 0644 /etc/passwd
""",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "denied_rule_patterns": ["sshd.*(disable|stop|mask)"],
                "denied_command_patterns": ["systemctl\\s+(stop|disable|mask)\\s+sshd"],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "filtered.sh"

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--results",
            str(results),
            "--fix",
            str(fix),
            "--output",
            str(output),
            "--policy",
            str(policy),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    summary = json.loads(completed.stdout)
    assert summary["failed_rules"] == 2
    assert summary["excluded_rules"] == 1
    assert summary["included_rules"] == 1
    filtered = output.read_text(encoding="utf-8")
    assert "systemctl stop sshd" not in filtered
    assert "chmod 0644 /etc/passwd" in filtered


def test_patching_role_uses_native_update_mechanisms():
    tasks = yaml.safe_load(_read(TASKENGINE / "roles/patching_option2/tasks/main.yml"))
    names = [task.get("name") for task in _all_tasks(tasks)]
    assert "Enable the dnf-automatic timer" in names
    assert "Enable the apt-daily-upgrade timer" in names
    assert "Enable the Ubuntu Pro livepatch service" in names
    assert "Deploy the patching status check for Wazuh command monitoring" in names
    livepatch = _task_by_name(tasks, "Enable the Ubuntu Pro livepatch service")
    assert livepatch["ansible.builtin.command"] == "pro enable livepatch --assume-yes"
    attach = _task_by_name(tasks, "Attach the host to Ubuntu Pro with the vaulted token")
    assert attach["no_log"] is True
    assert "ubuntu_pro_token" in attach["ansible.builtin.command"]["cmd"]

    dnf_conf = _read(TASKENGINE / "roles/patching_option2/templates/dnf-automatic.conf.j2")
    assert "apply_updates = yes" in dnf_conf
    assert "upgrade_type = security" in dnf_conf
    unattended = _read(
        TASKENGINE / "roles/patching_option2/templates/50unattended-upgrades.j2"
    )
    assert "Unattended-Upgrade::Automatic-Reboot" in unattended


def test_wazuh_agent_monitors_linsec_sources():
    defaults = yaml.safe_load(
        _read(TASKENGINE / "roles/wazuh/ansible-wazuh-agent/defaults/main.yml")
    )
    linux = defaults["wazuh_agent_localfiles"]["linux"]
    assert any(
        item.get("location") == "/var/log/linsec360/openscap-status.log"
        for item in linux
    )
    assert any(
        item.get("command") == "/usr/local/bin/check_patching_status.sh"
        for item in linux
    )


def test_verify_playbook_checks_required_controls():
    content = _read(TASKENGINE / "playbooks/verify.yml")
    for expected in (
        "oscap-after.html",
        "wazuh-agent.service",
        "canonical-livepatch.service",
        "dnf-automatic.timer",
        "apt-daily-upgrade.timer",
        "SSH was not cut",
    ):
        assert expected in content


def test_compose_and_env_template_no_longer_deploy_uyuni():
    compose = _read(ROOT / "docker-compose.v2.yml")
    example = _read(ROOT / ".env.example")
    pattern = re.compile(r"(?i)uyuni|salt-minion|spacewalk", re.MULTILINE)
    assert pattern.search(compose) is None
    assert pattern.search(example) is None


def test_bundled_playbook_directory_matches_supported_workflow():
    filenames = {path.name for path in (TASKENGINE / "playbooks").glob("*.yml")}
    for expected in (
        "site.yml",
        "verify.yml",
        "openscap-scan.yml",
        "openscap-remediate.yml",
        "compliance-verify.yml",
        "hardening.yml",
        "patch-security.yml",
        "patch-verify.yml",
        "livepatch-check.yml",
        "wazuh-agent.yml",
        "connectivity.yml",
    ):
        assert expected in filenames
    for removed in (
        "site-legacy.yml",
        "system-audit.yml",
        "hardening-audit.yml",
        "system-update.yml",
        "disk-cleanup.yml",
    ):
        assert removed not in filenames


def test_compliance_and_patch_playbooks_ingest_their_results():
    for filename, endpoint in (
        ("openscap-scan.yml", "/api/v1/compliance/scans"),
        ("openscap-remediate.yml", "/api/v1/compliance/scans"),
        ("compliance-verify.yml", "/api/v1/compliance/scans"),
        ("patch-security.yml", "/api/v1/patching/results"),
        ("patch-verify.yml", "/api/v1/patching/results"),
    ):
        content = _read(TASKENGINE / "playbooks" / filename)
        assert endpoint in content
        assert "Authorization: \"Bearer {{" in content
        assert "no_log: true" in content

        plays = yaml.safe_load(content)
        tasks = [task for play in plays for task in play.get("tasks", [])]
        ingest_tasks = [
            task for task in _all_tasks(tasks) if "ansible.builtin.uri" in task
        ]
        assert ingest_tasks
        assert all("failed_when" not in task for task in ingest_tasks)
        # The callback URL is Docker-internal, so ingestion must run on the
        # controller/worker, never on the managed host.
        assert all(task.get("delegate_to") == "localhost" for task in ingest_tasks)
        assert all(task.get("become") is False for task in ingest_tasks)


def test_patch_playbooks_support_targeted_and_verified_packages():
    for filename in ("patch-security.yml", "patch-verify.yml"):
        play = yaml.safe_load(_read(TASKENGINE / "playbooks" / filename))[0]
        assert play["hosts"] == "all"
        assert "patch_targets" in play["vars"]
        assert "patch_ingest_url" in play["vars"]
        assert "patch_api_token" in play["vars"]
        assert "patch_target_packages" not in play["vars"]
        assert "patch_target_cves" not in play["vars"]
    security = yaml.safe_load(_read(TASKENGINE / "playbooks" / "patch-security.yml"))[0]
    names = [task.get("name") for task in _all_tasks(security["tasks"])]
    assert "Reboot only when required and explicitly allowed" in names
    for filename in ("patch-security.yml", "patch-verify.yml"):
        content = _read(TASKENGINE / "playbooks" / filename)
        assert "'package': item.package" in content
        assert "'cve': item.cve" in content
        assert "'fixed_version': item.fixed_version" in content
