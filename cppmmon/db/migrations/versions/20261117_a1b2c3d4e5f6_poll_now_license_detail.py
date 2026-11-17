"""poll_requests table (Poll Now), license detail columns, trust-list cert rule disabled

Revision ID: a1b2c3d4e5f6
Revises: 9e3a5b7d2c30
Create Date: 2026-11-17 18:00:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "9e3a5b7d2c30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "poll_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("node_id", sa.Integer(), nullable=True),
        sa.Column("requested_by", sa.String(length=64), nullable=True),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("picked_at", sa.DateTime(), nullable=True),
        mysql_engine="InnoDB", mysql_charset="utf8mb4",
    )
    op.create_index("ix_poll_requests_picked", "poll_requests", ["picked_at"])
    with op.batch_alter_table("licenses") as b:
        b.add_column(sa.Column("license_type", sa.String(length=32), nullable=True))
        b.add_column(sa.Column("activated", sa.Boolean(), nullable=True))
        b.add_column(sa.Column("added_on", sa.DateTime(), nullable=True))
    # Scope change 2026-11-17: only RADIUS + HTTPS(RSA) server certs are polled; trust-list expiry
    # is covered by CPPM's own traps/syslog. Keep the rule row but disable it.
    op.execute("UPDATE thresholds SET enabled = 0 WHERE rule_id = 'trust_cert'")


def downgrade() -> None:
    op.execute("UPDATE thresholds SET enabled = 1 WHERE rule_id = 'trust_cert'")
    with op.batch_alter_table("licenses") as b:
        b.drop_column("added_on")
        b.drop_column("activated")
        b.drop_column("license_type")
    op.drop_index("ix_poll_requests_picked", table_name="poll_requests")
    op.drop_table("poll_requests")
