"""trap_catalog.clear_oid: VARCHAR(128) -> TEXT (comma-separated list of clearing OIDs)

Revision ID: 8d2f4a6c1b20
Revises: 7c1e2d9b3f10
Create Date: 2026-11-17 15:00:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "8d2f4a6c1b20"
down_revision: str | None = "7c1e2d9b3f10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("trap_catalog") as b:
        b.alter_column("clear_oid", existing_type=sa.String(length=128), type_=sa.Text(), existing_nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("trap_catalog") as b:
        b.alter_column("clear_oid", existing_type=sa.Text(), type_=sa.String(length=128), existing_nullable=True)
