"""integration layers: wazuh, compliance, patching, hardening, api tokens

Revision ID: 9f1c2d3e4a5b
Revises: 7e7c7e049d26
Create Date: 2026-11-06 12:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "9f1c2d3e4a5b"
down_revision: str | None = "7e7c7e049d26"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON_TYPE = sa.JSON().with_variant(
    postgresql.JSONB(astext_type=sa.Text()), "postgresql"
)


def upgrade() -> None:
    op.add_column(
        "deployments",
        sa.Column(
            "cancel_requested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "deployments",
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("alert_id", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=True),
        sa.Column("rule_level", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=True),
        sa.Column("agent_name", sa.String(length=128), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("location", sa.String(length=255), nullable=True),
        sa.Column("mitre", JSON_TYPE, nullable=False),
        sa.Column("raw", JSON_TYPE, nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("acknowledged_by", sa.String(length=64), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id"),
    )
    op.create_index(
        "ix_alerts_timestamp_severity", "alerts", ["timestamp", "severity"]
    )
    op.create_index("ix_alerts_agent_time", "alerts", ["agent_name", "timestamp"])

    op.create_table(
        "compliance_scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("host_name", sa.String(length=64), nullable=False),
        sa.Column("profile", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("artifact_path", sa.String(length=512), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_scans_host_finished", "compliance_scans", ["host_id", "finished_at"]
    )

    op.create_table(
        "compliance_findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["compliance_scans.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_findings_scan_result", "compliance_findings", ["scan_id", "result"]
    )

    op.create_table(
        "patch_findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("host_name", sa.String(length=64), nullable=False),
        sa.Column("package", sa.String(length=255), nullable=False),
        sa.Column("current_version", sa.String(length=128), nullable=True),
        sa.Column("fixed_version", sa.String(length=128), nullable=True),
        sa.Column("cve", sa.String(length=64), nullable=False),
        sa.Column("errata", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reboot_required", sa.Boolean(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "host_name",
            "package",
            "cve",
            "errata",
            "source",
            name="uq_patch_finding_identity",
        ),
    )
    op.create_index("ix_patch_host_status", "patch_findings", ["host_id", "status"])
    op.create_index("ix_patch_severity", "patch_findings", ["severity"])

    op.create_table(
        "uyuni_systems",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("host_name", sa.String(length=64), nullable=False),
        sa.Column("uyuni_system_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("channels", JSON_TYPE, nullable=False),
        sa.Column("last_sync", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uyuni_system_id"),
    )

    op.create_table(
        "livepatch_status",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("host_name", sa.String(length=64), nullable=False),
        sa.Column("kernel", sa.String(length=128), nullable=False),
        sa.Column("livepatch_state", sa.String(length=32), nullable=False),
        sa.Column("patch_available", sa.Boolean(), nullable=False),
        sa.Column("exposure_days", sa.Integer(), nullable=True),
        sa.Column("last_checked", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_livepatch_host_checked", "livepatch_status", ["host_id", "last_checked"]
    )

    op.create_table(
        "hardening_checks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("host_name", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("control", sa.String(length=128), nullable=False),
        sa.Column("expected", sa.Text(), nullable=True),
        sa.Column("actual", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "host_name", "control", "checked_at", name="uq_hardening_check_snapshot"
        ),
    )
    op.create_index(
        "ix_hardening_host_checked", "hardening_checks", ["host_id", "checked_at"]
    )
    op.create_index("ix_hardening_status", "hardening_checks", ["status"])


def downgrade() -> None:
    op.drop_index("ix_hardening_status", table_name="hardening_checks")
    op.drop_index("ix_hardening_host_checked", table_name="hardening_checks")
    op.drop_table("hardening_checks")
    op.drop_index("ix_livepatch_host_checked", table_name="livepatch_status")
    op.drop_table("livepatch_status")
    op.drop_table("uyuni_systems")
    op.drop_index("ix_patch_severity", table_name="patch_findings")
    op.drop_index("ix_patch_host_status", table_name="patch_findings")
    op.drop_table("patch_findings")
    op.drop_index("ix_findings_scan_result", table_name="compliance_findings")
    op.drop_table("compliance_findings")
    op.drop_index("ix_scans_host_finished", table_name="compliance_scans")
    op.drop_table("compliance_scans")
    op.drop_index("ix_alerts_agent_time", table_name="alerts")
    op.drop_index("ix_alerts_timestamp_severity", table_name="alerts")
    op.drop_table("alerts")
    op.drop_table("api_tokens")
    op.drop_column("deployments", "cancelled_at")
    op.drop_column("deployments", "cancel_requested")
