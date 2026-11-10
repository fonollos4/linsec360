"""SQLAlchemy models for the LinSec360 platform."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

JsonType = JSON().with_variant(JSONB, "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


host_group_members = Table(
    "host_group_members",
    Base.metadata,
    Column("host_id", ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "group_id",
        ForeignKey("host_groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    user: Mapped[User] = relationship(back_populates="sessions")


class Environment(TimestampMixin, Base):
    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))

    hosts: Mapped[list[Host]] = relationship(back_populates="environment")


class HostGroup(TimestampMixin, Base):
    __tablename__ = "host_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))

    hosts: Mapped[list[Host]] = relationship(
        secondary=host_group_members, back_populates="groups"
    )


class Host(TimestampMixin, Base):
    __tablename__ = "hosts"
    __table_args__ = (
        UniqueConstraint("name", "environment_id", name="uq_hosts_name_environment"),
        Index("ix_hosts_environment_status", "environment_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    environment_id: Mapped[int] = mapped_column(
        ForeignKey("environments.id", ondelete="RESTRICT"), nullable=False
    )
    security_level: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium"
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    agent_id: Mapped[str | None] = mapped_column(String(64))
    os: Mapped[str | None] = mapped_column(String(128))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ansible_user: Mapped[str] = mapped_column(
        String(64), nullable=False, default="linsec-ansible"
    )
    ansible_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    ansible_password_encrypted: Mapped[str | None] = mapped_column(Text)
    ssh_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    ssh_fingerprint: Mapped[str | None] = mapped_column(String(128))
    ssh_error: Mapped[str | None] = mapped_column(String(512))
    last_ssh_test_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    added_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    environment: Mapped[Environment] = relationship(back_populates="hosts")
    groups: Mapped[list[HostGroup]] = relationship(
        secondary=host_group_members, back_populates="hosts"
    )
    deployment_targets: Mapped[list[DeploymentTarget]] = relationship(
        back_populates="host"
    )


class Playbook(TimestampMixin, Base):
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    checksum: Mapped[str | None] = mapped_column(String(64))
    is_allowlisted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    deployments: Mapped[list[Deployment]] = relationship(back_populates="playbook")


class Deployment(Base):
    __tablename__ = "deployments"
    __table_args__ = (Index("ix_deployments_created_status", "created_at", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    playbook_id: Mapped[int | None] = mapped_column(
        ForeignKey("playbooks.id", ondelete="SET NULL")
    )
    playbook_name: Mapped[str] = mapped_column(String(255), nullable=False)
    environment_id: Mapped[int | None] = mapped_column(
        ForeignKey("environments.id", ondelete="SET NULL")
    )
    environment_name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    log_path: Mapped[str] = mapped_column(String(512), nullable=False)
    extra_vars: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    playbook: Mapped[Playbook | None] = relationship(back_populates="deployments")
    targets: Mapped[list[DeploymentTarget]] = relationship(
        back_populates="deployment", cascade="all, delete-orphan"
    )
    events: Mapped[list[DeploymentEvent]] = relationship(
        back_populates="deployment", cascade="all, delete-orphan"
    )


class DeploymentTarget(Base):
    __tablename__ = "deployment_targets"
    __table_args__ = (
        UniqueConstraint("deployment_id", "host_id", name="uq_deployment_target"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    deployment_id: Mapped[str] = mapped_column(
        ForeignKey("deployments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL")
    )
    host_name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")

    deployment: Mapped[Deployment] = relationship(back_populates="targets")
    host: Mapped[Host | None] = relationship(back_populates="deployment_targets")


class DeploymentEvent(Base):
    __tablename__ = "deployment_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    deployment_id: Mapped[str] = mapped_column(
        ForeignKey("deployments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    deployment: Mapped[Deployment] = relationship(back_populates="events")


class OperationSchedule(TimestampMixin, Base):
    __tablename__ = "operation_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    environment_name: Mapped[str] = mapped_column(String(64), nullable=False)
    playbook_name: Mapped[str | None] = mapped_column(String(255))
    profile: Mapped[str | None] = mapped_column(String(255))
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(32))
    target_hosts: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    config: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)


class MaintenanceWindow(TimestampMixin, Base):
    __tablename__ = "maintenance_windows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    environment_name: Mapped[str] = mapped_column(String(64), nullable=False)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)


class KpiSnapshot(Base):
    __tablename__ = "kpi_snapshots"
    __table_args__ = (Index("ix_kpi_metric_captured", "metric", "captured_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    metric: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="global"
    )
    scope_id: Mapped[str | None] = mapped_column(String(64))
    value: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_username: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class ApiToken(Base):
    """Hashed, revocable API token for automation clients."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class Alert(Base):
    """Normalized Wazuh alert retained for the platform UI and KPIs."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_timestamp_severity", "timestamp", "severity"),
        Index("ix_alerts_agent_time", "agent_name", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    rule_id: Mapped[str | None] = mapped_column(String(32))
    rule_level: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    agent_id: Mapped[str | None] = mapped_column(String(64))
    agent_name: Mapped[str | None] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(255))
    mitre: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    raw: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    acknowledged_by: Mapped[str | None] = mapped_column(String(64))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class ComplianceScan(Base):
    """One OpenSCAP XCCDF evaluation for a host."""

    __tablename__ = "compliance_scans"
    __table_args__ = (Index("ix_scans_host_finished", "host_id", "finished_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL")
    )
    host_name: Mapped[str] = mapped_column(String(64), nullable=False)
    profile: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    score: Mapped[float | None] = mapped_column(Float)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    artifact_path: Mapped[str | None] = mapped_column(String(512))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    findings: Mapped[list[ComplianceFinding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ComplianceFinding(Base):
    __tablename__ = "compliance_findings"
    __table_args__ = (Index("ix_findings_scan_result", "scan_id", "result"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("compliance_scans.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32))
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped[ComplianceScan] = relationship(back_populates="findings")


class PatchFinding(Base):
    """CVE/errata exposure from Wazuh vulnerabilities or Uyuni errata."""

    __tablename__ = "patch_findings"
    __table_args__ = (
        UniqueConstraint(
            "host_name",
            "package",
            "cve",
            "errata",
            "source",
            name="uq_patch_finding_identity",
        ),
        Index("ix_patch_host_status", "host_id", "status"),
        Index("ix_patch_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL")
    )
    host_name: Mapped[str] = mapped_column(String(64), nullable=False)
    package: Mapped[str] = mapped_column(String(255), nullable=False)
    current_version: Mapped[str | None] = mapped_column(String(128))
    fixed_version: Mapped[str | None] = mapped_column(String(128))
    cve: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    errata: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="wazuh")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    reboot_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class UyuniSystem(Base):
    __tablename__ = "uyuni_systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL")
    )
    host_name: Mapped[str] = mapped_column(String(64), nullable=False)
    uyuni_system_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    channels: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class LivepatchStatus(Base):
    __tablename__ = "livepatch_status"
    __table_args__ = (Index("ix_livepatch_host_checked", "host_id", "last_checked"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL")
    )
    host_name: Mapped[str] = mapped_column(String(64), nullable=False)
    kernel: Mapped[str] = mapped_column(String(128), nullable=False)
    livepatch_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    patch_available: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    exposure_days: Mapped[int | None] = mapped_column(Integer)
    last_checked: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class HardeningCheck(Base):
    __tablename__ = "hardening_checks"
    __table_args__ = (
        UniqueConstraint(
            "host_name",
            "control",
            "checked_at",
            name="uq_hardening_check_snapshot",
        ),
        Index("ix_hardening_host_checked", "host_id", "checked_at"),
        Index("ix_hardening_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL")
    )
    host_name: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    control: Mapped[str] = mapped_column(String(128), nullable=False)
    expected: Mapped[str | None] = mapped_column(Text)
    actual: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
