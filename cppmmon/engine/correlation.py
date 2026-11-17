"""Correlation helpers (DESIGN §7.4–7.6): node-down suppression, maintenance, flap guard."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cppmmon.db.models import Alert, Node

FLAP_WINDOW = timedelta(minutes=30)
FLAP_CYCLES = 3  # more than 3 open/close cycles in 30 min → FLAPPING
NODE_DOWN = "node.down"


def open_alert(s: Session, key: str) -> Alert | None:
    """The single open-or-suppressed alert for a dedup key (open_marker=1)."""
    return s.scalar(select(Alert).where(Alert.dedup_key == key, Alert.open_marker == 1))


def node_down_parent(s: Session, node_id: int | None, event_type: str) -> Alert | None:
    """Open NODE DOWN alert that should suppress other alerts for this node."""
    if node_id is None or event_type == NODE_DOWN:
        return None
    return s.scalar(select(Alert).where(Alert.node_id == node_id, Alert.rule_id == NODE_DOWN, Alert.state == "open"))


def in_maintenance(node: Node | None, now: datetime) -> bool:
    """True while ``nodes.maintenance_until`` is in the future."""
    return bool(node is not None and node.maintenance_until and node.maintenance_until > now)


def recent_cycles(s: Session, key: str, now: datetime) -> int:
    """Open/close cycles for this key within the flap window."""
    return s.scalar(select(func.count()).select_from(Alert).where(
        Alert.dedup_key == key, Alert.state == "cleared", Alert.cleared_at >= now - FLAP_WINDOW)) or 0


def is_flapping(s: Session, key: str, now: datetime) -> bool:
    return recent_cycles(s, key, now) >= FLAP_CYCLES
