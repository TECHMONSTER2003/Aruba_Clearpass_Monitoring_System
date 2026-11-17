"""alerts: suppression reason, flap clear-pending, update-note rate limit, attributes

Revision ID: 9e3a5b7d2c30
Revises: 8d2f4a6c1b20
Create Date: 2026-11-17 16:30:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9e3a5b7d2c30"
down_revision: str | None = "8d2f4a6c1b20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("alerts") as b:
        b.add_column(sa.Column("suppress_reason", sa.String(length=32), nullable=True))
        b.add_column(sa.Column("clear_pending_at", sa.DateTime(), nullable=True))
        b.add_column(sa.Column("last_update_note_at", sa.DateTime(), nullable=True))
        b.add_column(sa.Column("attributes", sa.JSON(), nullable=True))
        b.create_index("ix_alerts_dedup_key", ["dedup_key"])
        b.create_index("ix_alerts_node_state", ["node_id", "state"])
    with op.batch_alter_table("tickets") as b:
        b.create_index("ix_tickets_alert", ["alert_id"])


def downgrade() -> None:
    with op.batch_alter_table("tickets") as b:
        b.drop_index("ix_tickets_alert")
    with op.batch_alter_table("alerts") as b:
        b.drop_index("ix_alerts_node_state")
        b.drop_index("ix_alerts_dedup_key")
        b.drop_column("attributes")
        b.drop_column("last_update_note_at")
        b.drop_column("clear_pending_at")
        b.drop_column("suppress_reason")
