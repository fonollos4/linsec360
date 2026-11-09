"""Add SSH enrollment and trust fields to hosts.

Revision ID: c2d3e4f5a6b7
Revises: a1b2c3d4e5f6
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c2d3e4f5a6b7"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("ansible_user", sa.String(length=64), nullable=False, server_default="linsec-ansible"),
    )
    op.add_column(
        "hosts",
        sa.Column("ansible_port", sa.Integer(), nullable=False, server_default="22"),
    )
    op.add_column(
        "hosts",
        sa.Column("ssh_status", sa.String(length=32), nullable=False, server_default="pending"),
    )
    op.add_column("hosts", sa.Column("ssh_fingerprint", sa.String(length=128), nullable=True))
    op.add_column("hosts", sa.Column("ssh_error", sa.String(length=512), nullable=True))
    op.add_column("hosts", sa.Column("last_ssh_test_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("hosts", "last_ssh_test_at")
    op.drop_column("hosts", "ssh_error")
    op.drop_column("hosts", "ssh_fingerprint")
    op.drop_column("hosts", "ssh_status")
    op.drop_column("hosts", "ansible_port")
    op.drop_column("hosts", "ansible_user")
