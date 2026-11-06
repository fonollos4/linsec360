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
