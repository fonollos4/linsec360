"""Pydantic v2 request/response contracts for the v1 API."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
PLAYBOOK_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml$")
SECURITY_LEVELS = {"low", "medium", "high", "critical"}


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Message(BaseModel):
    message: str


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(ORMModel):
    id: int
    username: str
    email: str | None = None
    role: str
    is_active: bool
    last_login_at: datetime | None = None


class HostCreate(BaseModel):
    name: str
    ip: str
    environment: str
    security_level: Literal["low", "medium", "high", "critical"] = "medium"
    groups: list[str] = Field(default_factory=list)
    status: Literal["pending", "deploying", "secured", "error", "unknown"] = "pending"
    ansible_user: str = Field(default="linsec-ansible", min_length=1, max_length=64)
    ansible_port: int = Field(default=22, ge=1, le=65535)

    @field_validator("name", "environment")
    @classmethod
    def _identifier(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("invalid identifier")
        return value

    @field_validator("ip")
    @classmethod
    def _ipv4(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid IPv4 address") from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError("invalid IPv4 address")
        return value

    @field_validator("ansible_user")
    @classmethod
    def _ansible_user(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("invalid SSH username")
        return value

    @field_validator("groups")
    @classmethod
    def _groups(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            if not IDENTIFIER.fullmatch(value):
                raise ValueError(f"invalid group name: {value}")
            if value not in cleaned:
                cleaned.append(value)
        return cleaned


class HostUpdate(BaseModel):
    ip: str | None = None
    security_level: Literal["low", "medium", "high", "critical"] | None = None
    groups: list[str] | None = None
    status: Literal["pending", "deploying", "secured", "error", "unknown"] | None = None
    ansible_user: str | None = Field(default=None, min_length=1, max_length=64)
    ansible_port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("ansible_user")
    @classmethod
    def _ansible_user(cls, value: str | None) -> str | None:
        if value is not None and not IDENTIFIER.fullmatch(value):
            raise ValueError("invalid SSH username")
        return value

    @field_validator("ip")
    @classmethod
    def _ipv4(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid IPv4 address") from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError("invalid IPv4 address")
        return value

    @field_validator("groups")
    @classmethod
    def _groups(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return values
        cleaned = []
        for value in values:
            if not IDENTIFIER.fullmatch(value):
                raise ValueError(f"invalid group name: {value}")
            if value not in cleaned:
                cleaned.append(value)
        return cleaned


class HostOut(ORMModel):
    id: int
    name: str
    ip: str
    environment: str
    security_level: str
    groups: list[str]
    status: str
    agent_id: str | None = None
    os: str | None = None
    last_seen: datetime | None = None
    added_date: datetime
    ansible_user: str = "linsec-ansible"
    ansible_port: int = 22
    ssh_status: str = "pending"
    ssh_fingerprint: str | None = None
    ssh_error: str | None = None
    last_ssh_test_at: datetime | None = None


class SSHPublicKeyOut(BaseModel):
    public_key: str
    private_key_path: str


class SSHTestOut(BaseModel):
    reachable: bool
    ssh_status: str
    fingerprint: str | None = None
    fingerprint_changed: bool = False
    message: str


class PlaybookCreate(BaseModel):
    filename: str
    content: str = ""
    description: str | None = None

    @field_validator("filename")
    @classmethod
    def _filename(cls, value: str) -> str:
        if not PLAYBOOK_FILENAME.fullmatch(value):
            raise ValueError("playbook filename must end in .yml or .yaml")
        return value


class PlaybookUpdate(BaseModel):
    content: str
    description: str | None = None


class PlaybookOut(ORMModel):
    id: int
    filename: str
    description: str | None = None
    checksum: str | None = None
    is_allowlisted: bool
    updated_at: datetime


class PlaybookDetail(PlaybookOut):
    content: str


class DeploymentCreate(BaseModel):
    environment: str
    playbook: str
    hosts: list[str] = Field(default_factory=list)
    group: str | None = None
    check_mode: bool = False
    extra_vars: dict[str, str] = Field(default_factory=dict)

    @field_validator("environment", "playbook")
    @classmethod
    def _not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be empty")
        return value

    @field_validator("hosts")
    @classmethod
    def _host_names(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            if not IDENTIFIER.fullmatch(value):
                raise ValueError(f"invalid host name: {value}")
            if value not in cleaned:
                cleaned.append(value)
        return cleaned

    @field_validator("group")
    @classmethod
    def _group(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("invalid group name")
        return value


class DeploymentOut(BaseModel):
    id: str
    environment: str
    playbook: str
    target_hosts: list[str]
    status: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None
    log_url: str


class DeploymentEventOut(ORMModel):
    id: int
    level: str
    event: str
    message: str | None = None
    data: dict
    created_at: datetime


class KpiItem(BaseModel):
    value: float | None
    status: Literal["ok", "unknown", "stale"]
    source: str


class KpiOverview(BaseModel):
    generated_at: datetime
    hosts_total: KpiItem
    hosts_secured: KpiItem
    hosts_deploying: KpiItem
    active_deployments: KpiItem
    deployment_success_rate: KpiItem
    open_vulnerabilities: KpiItem
    compliance_score: KpiItem
    agent_coverage: KpiItem
    disconnected_agents: KpiItem
    open_critical_vulnerabilities: KpiItem
    open_high_vulnerabilities: KpiItem
    patch_coverage: KpiItem
    reboot_required: KpiItem
    kernel_exposure_days: KpiItem
    hardening_drift: KpiItem
    selinux_non_compliant: KpiItem
    alerts_by_severity: dict[str, int] | None = None


class KpiSnapshotOut(ORMModel):
    id: int
    metric: str
    scope_type: str
    scope_id: str | None = None
    value: float | None = None
    status: str
    source: str
    captured_at: datetime


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class ApiTokenOut(ORMModel):
    id: int
    name: str
    role: str
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime


class ApiTokenCreated(ApiTokenOut):
    token: str


class AgentOut(BaseModel):
    id: str
    name: str
    ip: str | None = None
    status: str
    os: str | None = None
    version: str | None = None
    last_keep_alive: datetime | None = None
    host_id: int | None = None


class AgentSummary(BaseModel):
    total: int
    active: int
    disconnected: int
    pending: int
    never_connected: int
    coverage: KpiItem


class AlertOut(ORMModel):
    id: int
    alert_id: str
    timestamp: datetime
    rule_id: str | None = None
    rule_level: int | None = None
    severity: str
    agent_id: str | None = None
    agent_name: str | None = None
    description: str | None = None
    location: str | None = None
    mitre: list = Field(default_factory=list)
    acknowledged: bool
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None


class ComplianceScanCreate(BaseModel):
    host_name: str = Field(min_length=1, max_length=64)
    profile: str | None = Field(default=None, max_length=255)
    content: str | None = None
    artifact_path: str | None = None


class ComplianceFindingOut(ORMModel):
    id: int
    rule_id: str
    title: str | None = None
    result: str
    severity: str | None = None
    description: str | None = None
    remediation: str | None = None


class ComplianceScanOut(ORMModel):
    id: str
    host_id: int | None = None
    host_name: str
    profile: str
    status: str
    score: float | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    artifact_path: str | None = None
    error_message: str | None = None
    created_at: datetime


class ComplianceScanDetail(ComplianceScanOut):
    findings: list[ComplianceFindingOut] = Field(default_factory=list)


class PatchFindingOut(ORMModel):
    id: int
    host_id: int | None = None
    host_name: str
    package: str
    current_version: str | None = None
    fixed_version: str | None = None
    cve: str
    errata: str
    severity: str
    source: str
    status: str
    reboot_required: bool
    detected_at: datetime
    updated_at: datetime


class LivepatchOut(ORMModel):
    id: int
    host_id: int | None = None
    host_name: str
    kernel: str
    livepatch_state: str
    patch_available: bool
    exposure_days: int | None = None
    last_checked: datetime


class LivepatchIn(BaseModel):
    host_name: str = Field(min_length=1, max_length=64)
    kernel: str = Field(min_length=1, max_length=128)
    livepatch_state: Literal["applied", "pending", "unavailable", "unknown"] = (
        "unknown"
    )
    patch_available: bool = False
    exposure_days: int | None = Field(default=None, ge=0)


class HardeningCheckIn(BaseModel):
    category: str = Field(min_length=1, max_length=64)
    control: str = Field(min_length=1, max_length=128)
    expected: str | None = None
    actual: str | None = None
    status: Literal["pass", "fail", "unknown", "not_applicable"] = "unknown"


class HardeningResultIn(BaseModel):
    host_name: str = Field(min_length=1, max_length=64)
    checks: list[HardeningCheckIn] = Field(min_length=1)


class HardeningCheckOut(ORMModel):
    id: int
    host_id: int | None = None
    host_name: str
    category: str
    control: str
    expected: str | None = None
    actual: str | None = None
    status: str
    checked_at: datetime


class OperationScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    operation: Literal["openscap", "patch", "uyuni_sync", "wazuh_sync"]
    environment: str = Field(min_length=1, max_length=64)
    playbook: str | None = Field(default=None, max_length=255)
    profile: str | None = Field(default=None, max_length=255)
    interval_minutes: int = Field(default=1440, ge=5, le=525600)
    enabled: bool = True
    hosts: list[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)


class OperationScheduleOut(ORMModel):
    id: int
    name: str
    operation: str
    environment_name: str
    playbook_name: str | None = None
    profile: str | None = None
    interval_minutes: int
    enabled: bool
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    last_status: str | None = None
    target_hosts: list = Field(default_factory=list)
    config: dict = Field(default_factory=dict)


class MaintenanceWindowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=64)
    starts_at: datetime
    ends_at: datetime
    enabled: bool = True
    config: dict = Field(default_factory=dict)

    @field_validator("ends_at")
    @classmethod
    def _end_after_start(cls, value: datetime) -> datetime:
        return value


class MaintenanceWindowOut(ORMModel):
    id: int
    name: str
    environment_name: str
    starts_at: datetime
    ends_at: datetime
    enabled: bool
    config: dict = Field(default_factory=dict)


class ActiveResponseRequest(BaseModel):
    action: Literal["firewall-drop", "disable-account"]
    confirm: Literal[True]


class HostPosture(BaseModel):
    host_id: int
    host_name: str
    compliance: ComplianceScanOut | None = None
    hardening: list[HardeningCheckOut] = Field(default_factory=list)
    patch_findings: list[PatchFindingOut] = Field(default_factory=list)
    livepatch: LivepatchOut | None = None
    agent: AgentOut | None = None


class IntegrationState(BaseModel):
    configured: bool
    reachable: bool | None = None
    detail: str | None = None


class IntegrationStatus(BaseModel):
    wazuh: IntegrationState
    uyuni: IntegrationState


class AuditOut(ORMModel):
    id: int
    actor_username: str | None = None
    action: str
    target_type: str
    target_id: str | None = None
    data: dict
    ip_address: str | None = None
    created_at: datetime


class SessionOut(BaseModel):
    authenticated: bool
    user: UserOut
    csrf_token: str | None = None


class Paginated(BaseModel):
    items: list
    total: int
    limit: int
    offset: int
