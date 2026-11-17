"""nodes: OAuth grant type + password-grant creds; node_state: last Test Connection result

Revision ID: 7c1e2d9b3f10
Revises: 4a990e50a6ba
Create Date: 2026-11-17 13:30:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7c1e2d9b3f10"
down_revision: str | None = "4a990e50a6ba"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("nodes") as b:
        b.add_column(
            sa.Column(
                "api_grant_type",
                sa.Enum("client_credentials", "password", name="api_grant_type"),
                nullable=False,
                server_default="client_credentials",
            )
        )
        b.add_column(sa.Column("api_username", sa.String(length=128), nullable=True))
        b.add_column(sa.Column("api_password_enc", sa.Text(), nullable=True))
    with op.batch_alter_table("node_state") as b:
        b.add_column(sa.Column("last_test_at", sa.DateTime(), nullable=True))
        b.add_column(sa.Column("last_test", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("node_state") as b:
        b.drop_column("last_test")
        b.drop_column("last_test_at")
    with op.batch_alter_table("nodes") as b:
        b.drop_column("api_password_enc")
        b.drop_column("api_username")
        b.drop_column("api_grant_type")
