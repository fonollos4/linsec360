"""Store an encrypted Ansible account password on each host.

Revision ID: d4e5f6a7b8c9
Revises: c2d3e4f5a6b7
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c2d3e4f5a6b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("ansible_password_encrypted", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("hosts", "ansible_password_encrypted")
