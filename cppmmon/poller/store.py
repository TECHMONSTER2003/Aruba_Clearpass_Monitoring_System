"""Poller DB writes: one transaction per job run (metrics, counters, state, events, inventory)."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from cppmmon.db.models import (
    Certificate,
    CounterState,
    Event,
    License,
    Metric,
    Node,
    NodeState,
    ServiceStatus,
)
from cppmmon.db.session import session_scope

log = logging.getLogger(__name__)


@dataclass
class JobResult:
    """Everything one job run wants persisted."""

    metrics: list[dict[str, Any]] = field(default_factory=list)
    counters: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)
    services: dict[str, dict[str, Any]] | None = None
    certs: list[dict[str, Any]] | None = None
    licenses: list[dict[str, Any]] | None = None
    role: str | None = None

    def metric(self, node_id: int, ts: datetime, name: str, value: float | None, instance: str = "") -> None:
        if value is not None:
            self.metrics.append({"node_id": node_id, "ts": ts, "metric": name, "value": float(value), "instance": instance[:128]})


def _upsert(s: Session, model: Any, rows: list[dict[str, Any]], keys: list[str], cols: list[str]) -> None:
    if not rows:
        return
    if s.get_bind().dialect.name == "mysql":
        stmt = mysql_insert(model).values(rows)
        s.execute(stmt.on_duplicate_key_update({c: stmt.inserted[c] for c in cols}))
    else:
        stmt = sqlite_insert(model).values(rows)
        s.execute(stmt.on_conflict_do_update(index_elements=keys, set_={c: stmt.excluded[c] for c in cols}))


def commit(node_id: int, r: JobResult, now: datetime) -> None:
    """Persist one job's results atomically."""
    with session_scope() as s:
        if r.metrics:
            s.execute(insert(Metric), r.metrics)
        _upsert(s, CounterState, r.counters, ["node_id", "metric", "instance"], ["last_value", "last_ts"])
        if r.events:
            s.execute(insert(Event), r.events)
        if r.state:
            if s.get(NodeState, node_id) is None:
                s.add(NodeState(node_id=node_id))
                s.flush()
            s.execute(update(NodeState).where(NodeState.node_id == node_id).values(**r.state))
        if r.role:
            s.execute(update(Node).where(Node.id == node_id).values(role=r.role))
        if r.services is not None:
            rows = [{"node_id": node_id, "service_name": v.get("display_name") or k, "status": v.get("state") or "?",
                     "raw": {"unit": k, "is_running": v.get("is_running"), "description": v.get("description")}, "ts": now}
                    for k, v in r.services.items()]
            _upsert(s, ServiceStatus, rows, ["node_id", "service_name"], ["status", "raw", "ts"])
        if r.certs is not None:
            s.execute(delete(Certificate).where(Certificate.node_id == node_id))
            s.add_all(Certificate(node_id=node_id, ts=now, **c) for c in r.certs)
        if r.licenses is not None:
            s.execute(delete(License).where(License.node_id == node_id))
            s.add_all(License(node_id=node_id, ts=now, **lic) for lic in r.licenses)


def load_counters() -> dict[tuple[int, str, str], tuple[float, datetime]]:
    """All persisted counter samples (restart-safe deltas)."""
    with session_scope() as s:
        return {(c.node_id, c.metric, c.instance): (float(c.last_value), c.last_ts) for c in s.scalars(select(CounterState))}


def load_node_context(node_id: int) -> dict[str, Any]:
    """Previous status/uptime/cluster size and service states for a node (restart-safe transitions)."""
    with session_scope() as s:
        st = s.get(NodeState, node_id)
        services = {x.service_name: (x.status or "").lower() == "running" for x in
                    s.scalars(select(ServiceStatus).where(ServiceStatus.node_id == node_id))}
        return {
            "status": st.status if st else "unknown",
            "uptime_s": st.uptime_s if st else None,
            "cluster_size": st.cluster_size if st else None,
            "sys_index": st.sys_index if st else None,
            "api_state": st.api_state if st else None,
            "services": services,
        }
