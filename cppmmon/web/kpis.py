"""Read-side KPI assembly for dashboard tiles and node overview (DESIGN §9)."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cppmmon.db.models import Alert, Certificate, License, Metric, Node, NodeState, ServiceStatus, Threshold
from cppmmon.db.session import utcnow

TILE_METRICS = ("cpu_pct", "mem_pct", "disk_pct", "auth_success_pct_today", "auth_per_min", "auth_fail_per_min",
                "endpoints_total", "icmp_rtt_ms", "license_pct", "load1")
KEY_SERVICES = (("RADIUS", "Radius server"), ("TACACS+", "TACACS+ server"), ("Policy", "Policy server"),
                ("DB repl", "DB replication service"), ("Async DB", "Async DB write service"))
STALE_AFTER = timedelta(minutes=5)


def _gauge_levels(s: Session) -> dict[str, tuple[float | None, float | None]]:
    """Gauge colour bands: DESIGN defaults, overridden by the (editable) threshold rules."""
    from cppmmon.poller.thresholds import DEFAULT_RULES

    gauges = ("cpu_pct", "mem_pct", "disk_pct")
    levels = {r["metric"]: (r["warn_value"], r["crit_value"]) for r in DEFAULT_RULES if r["metric"] in gauges}
    levels.update({t.metric: (t.warn_value, t.crit_value) for t in s.scalars(select(Threshold).where(
        Threshold.metric.in_(gauges), Threshold.enabled.is_(True)))})
    return levels


def level(value: float | None, warn: float | None, crit: float | None) -> str:
    """CSS level for a gauge value."""
    if value is None:
        return "muted"
    if crit is not None and value >= crit:
        return "crit"
    if warn is not None and value >= warn:
        return "warn"
    return "ok"


def latest_metrics(s: Session, node_ids: list[int], metrics: tuple[str, ...], since: datetime) -> dict[int, dict[str, Any]]:
    """{node_id: {metric or metric|instance: (value, ts)}} — newest sample per series."""
    out: dict[int, dict[str, Any]] = {n: {} for n in node_ids}
    if not node_ids:
        return out
    rows = s.execute(select(Metric.node_id, Metric.metric, Metric.instance, Metric.value, Metric.ts)
                     .where(Metric.node_id.in_(node_ids), Metric.metric.in_(metrics), Metric.ts >= since)
                     .order_by(Metric.ts.desc())).all()
    for nid, m, inst, val, ts in rows:
        key = f"{m}|{inst}" if inst else m
        out[nid].setdefault(key, (val, ts))
    return out


def node_summaries(s: Session, node_ids: list[int] | None = None) -> list[dict[str, Any]]:
    """Everything a dashboard tile shows, one dict per node."""
    q = select(Node, NodeState).outerjoin(NodeState, NodeState.node_id == Node.id).order_by(Node.enabled.desc(), Node.name)
    if node_ids:
        q = q.where(Node.id.in_(node_ids))
    rows = s.execute(q).all()
    ids = [n.id for n, _ in rows]
    now = utcnow()
    latest = latest_metrics(s, ids, TILE_METRICS, now - timedelta(hours=7))
    levels = _gauge_levels(s)
    services: dict[int, dict[str, ServiceStatus]] = {i: {} for i in ids}
    for sv in s.scalars(select(ServiceStatus).where(ServiceStatus.node_id.in_(ids))):
        services[sv.node_id][sv.service_name] = sv
    certs = dict(s.execute(select(Certificate.node_id, func.min(Certificate.days_left))
                           .where(Certificate.node_id.in_(ids), Certificate.cert_type == "server").group_by(Certificate.node_id)).all())
    lic: dict[int, list[License]] = {i: [] for i in ids}
    for x in s.scalars(select(License).where(License.node_id.in_(ids))):
        lic[x.node_id].append(x)
    alerts = dict(s.execute(select(Alert.node_id, func.count()).where(Alert.state == "open", Alert.node_id.in_(ids))
                            .group_by(Alert.node_id)).all())
    out = []
    for n, st in rows:
        m = latest[n.id]
        val = lambda k: m[k][0] if k in m else None  # noqa: E731
        last_ts = max((v[1] for v in m.values()), default=None)
        gauges = []
        for key, label in (("cpu_pct", "CPU"), ("mem_pct", "Memory"), ("disk_pct", "Disk")):
            w, c = levels.get(key, (None, None))
            v = val(key)
            gauges.append({"label": label, "value": v, "level": level(v, w, c)})
        svc = []
        for short, full in KEY_SERVICES:
            sv = services[n.id].get(full)
            svc.append({"label": short, "state": (sv.status if sv else None),
                        "level": "muted" if sv is None else ("ok" if (sv.status or "").lower() == "running" else "crit")})
        lic_pct = max((100.0 * (x.used or 0) / x.total for x in lic[n.id] if x.total), default=None)
        status = (st.status if st else "unknown") if n.enabled else "paused"
        out.append({
            "node": n, "state": st, "status": status, "gauges": gauges, "services": svc,
            "auth_success_pct": val("auth_success_pct_today"), "auth_per_min": val("auth_per_min"),
            "endpoints": val("endpoints_total"), "rtt": val("icmp_rtt_ms"), "load1": val("load1"),
            "cert_days": certs.get(n.id), "license_pct": lic_pct, "open_alerts": alerts.get(n.id, 0),
            "last_poll": last_ts, "stale": bool(n.enabled and (last_ts is None or now - last_ts > STALE_AFTER)),
        })
    return out


def unmonitored_clusters(s: Session) -> list[dict[str, Any]]:
    """Clusters whose CPPM-reported member count exceeds the nodes we monitor (auto-discovery hint)."""
    rows = s.execute(select(Node, NodeState).join(NodeState, NodeState.node_id == Node.id)
                     .where(NodeState.cluster_uuid.is_not(None))).all()
    if not rows:
        return []
    sizes = latest_metrics(s, [n.id for n, _ in rows], ("cluster_servers",), utcnow() - timedelta(hours=3))
    clusters: dict[str, dict[str, Any]] = {}
    for n, st in rows:
        c = clusters.setdefault(st.cluster_uuid, {"members": 0, "monitored": 0, "via": None})
        c["monitored"] += 1
        size = sizes[n.id].get("cluster_servers")
        if size:
            c["members"] = max(c["members"], int(size[0]))
        if n.api_enabled and (c["via"] is None or n.role == "publisher"):
            c["via"] = n
    return [c for c in clusters.values() if c["via"] is not None and c["members"] > c["monitored"]]


def series(s: Session, node_id: int, metrics: list[str], hours: float, max_points: int = 500) -> dict[str, list[list[float]]]:
    """{series_key: [[epoch_ms, value], ...]} bucket-averaged to at most ``max_points`` per series."""
    since = utcnow() - timedelta(hours=hours)
    rows = s.execute(select(Metric.metric, Metric.instance, Metric.ts, Metric.value)
                     .where(Metric.node_id == node_id, Metric.metric.in_(metrics), Metric.ts >= since)
                     .order_by(Metric.ts)).all()
    bucket_s = max(60.0, hours * 3600 / max_points)
    acc: dict[str, dict[int, list[float]]] = {}
    for m, inst, ts, v in rows:
        key = f"{m}|{inst}" if inst else m
        epoch_s = (ts - _EPOCH).total_seconds()  # stored timestamps are naive UTC
        acc.setdefault(key, {}).setdefault(int(epoch_s // bucket_s), []).append(v)
    return {key: [[round(b * bucket_s * 1000), round(sum(vals) / len(vals), 3)] for b, vals in sorted(buckets.items())]
            for key, buckets in acc.items()}


_EPOCH = datetime(1970, 1, 1)
