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
