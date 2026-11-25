"""Add a per-host SSH key reference for the service account.

Revision ID: b7c8d9e0f1a2
Revises: f6a7b8c9d0e1
Create Date: 2026-11-25
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "b7c8d9e0f1a2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column(
            "ssh_key_reference",
            sa.String(length=128),
            nullable=False,
            server_default="linsec-ansible",
        ),
    )


def downgrade() -> None:
    op.drop_column("hosts", "ssh_key_reference")
