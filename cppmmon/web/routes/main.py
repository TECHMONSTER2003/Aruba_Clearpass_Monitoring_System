"""Dashboard shell, health page and an unauthenticated liveness probe."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from flask import Blueprint, abort, jsonify, render_template
from flask_login import current_user, login_required
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

from cppmmon.db.models import Alert, ServiceHeartbeat
from cppmmon.db.session import get_engine, session_scope, utcnow
from cppmmon.web.kpis import node_summaries, unmonitored_clusters

log = logging.getLogger("cppmmon.web.main")
bp = Blueprint("main", __name__)

SERVICES = ("receiver", "poller", "engine", "web", "maintenance")
STALE_AFTER = timedelta(seconds=60)


@bp.get("/")
@login_required
def dashboard() -> Any:
    """Node tiles (Phase 3). Phase 0: summary strip + empty state."""
    tiles, summary, db_ok = _dashboard_data()
    can_edit = getattr(current_user, "role", "viewer") in ("admin", "operator")
    return render_template("dashboard.html", summary=summary, tiles=tiles, db_ok=db_ok, can_edit=can_edit, active="dashboard")


def queue_poll(node_id: int | None, user: str) -> bool:
    """Insert a 'Poll now' request (skipped if an identical one is still pending). Returns True if queued."""
    from cppmmon.db.models import PollRequest

    with session_scope() as s:
        pending = s.scalar(select(func.count()).select_from(PollRequest).where(
            PollRequest.picked_at.is_(None),
            PollRequest.node_id.is_(None) if node_id is None else PollRequest.node_id == node_id))
        if pending:
            return False
        s.add(PollRequest(node_id=node_id, requested_by=user, requested_at=utcnow()))
    return True


@bp.post("/poll")
@login_required
def poll_all() -> Any:
    """Dashboard 'Poll now': every enabled node, every job, immediately."""
    from flask import flash, redirect, url_for

    if getattr(current_user, "role", "viewer") not in ("admin", "operator"):
        abort(403)
    queue_poll(None, current_user.username)
    flash("Poll requested for all nodes: fresh values appear within ~30 s (certificates and licenses included).", "info")
    return redirect(url_for("main.dashboard"))


@bp.get("/licenses")
@login_required
def licenses() -> Any:
    """Per-node license view."""
    from cppmmon.db.models import License, Node

    with session_scope() as s:
        out = []
        for n in s.scalars(select(Node).where(Node.api_enabled.is_(True)).order_by(Node.name)):
            rows = list(s.scalars(select(License).where(License.node_id == n.id).order_by(License.app_name)))
            out.append((n, rows, max((r.ts for r in rows), default=None)))
    can_edit = getattr(current_user, "role", "viewer") in ("admin", "operator")
    return render_template("licenses.html", nodes=out, can_edit=can_edit, active="licenses")


@bp.get("/dashboard/tiles")
@login_required
def dashboard_tiles() -> Any:
    """HTMX partial: summary strip + node tiles (auto-refresh every 30 s)."""
    tiles, summary, db_ok = _dashboard_data()
    return render_template("_dashboard_body.html", summary=summary, tiles=tiles, db_ok=db_ok)


def _dashboard_data() -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
    summary: dict[str, Any] = {"nodes": 0, "up": 0, "down": 0, "open_alerts": 0, "undiscovered": []}
    try:
        with session_scope() as s:
            tiles = node_summaries(s)
            summary["undiscovered"] = unmonitored_clusters(s)
            summary["open_alerts"] = s.scalar(select(func.count()).select_from(Alert).where(Alert.state == "open")) or 0
    except SQLAlchemyError as exc:
        log.error("dashboard query failed", extra={"error": exc.__class__.__name__})
        return [], summary, False
    monitored = [t for t in tiles if t["node"].enabled]
    summary["nodes"] = len(monitored)
    summary["up"] = sum(1 for t in monitored if t["status"] == "up")
    summary["down"] = sum(1 for t in monitored if t["status"] in ("down", "degraded"))
    return tiles, summary, True


def _service_rows() -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    now = utcnow()
    try:
        with session_scope() as s:
            beats = {b.service: b for b in s.scalars(select(ServiceHeartbeat))}
    except SQLAlchemyError as exc:
        log.error("heartbeat query failed", extra={"error": exc.__class__.__name__})
        return rows, False
    for name in SERVICES:
        b = beats.get(name)
        if name == "web":
            state = "ok"
        elif b is None:
            state = "unknown"
        elif name == "maintenance":
            state = "ok" if now - b.last_beat < timedelta(hours=2) else "stale"
        else:
            state = "ok" if now - b.last_beat < STALE_AFTER else "stale"
        rows.append({"name": name, "state": state, "beat": b})
    return rows, True


def _health_data() -> dict[str, Any]:
    import shutil

    from flask import current_app

    cfg = current_app.config["CPPMMON_SETTINGS"]
    rows, db_ok = _service_rows()
    beats = {r["name"]: (r["beat"].stats or {}) if r["beat"] else {} for r in rows}
    data: dict[str, Any] = {"rows": rows, "db_ok": db_ok, "rx": beats.get("receiver", {}), "eng": beats.get("engine", {}),
                            "pol": beats.get("poller", {}), "mnt": beats.get("maintenance", {})}
    try:
        du = shutil.disk_usage(str(cfg.data_dir))
        data["disk"] = {"used_pct": 100.0 * du.used / du.total, "free_gb": du.free / 2**30, "total_gb": du.total / 2**30}
    except OSError:
        data["disk"] = None
    data["tables"] = []
    if db_ok:
        try:
            with session_scope() as s:
                if s.get_bind().dialect.name == "mysql":
                    data["tables"] = [dict(r._mapping) for r in s.execute(text(
                        "SELECT table_name AS name, table_rows AS approx_rows, "
                        "ROUND((data_length + index_length) / 1048576, 1) AS mb FROM information_schema.tables "
                        "WHERE table_schema = DATABASE() ORDER BY (data_length + index_length) DESC LIMIT 8"))]
        except SQLAlchemyError as exc:
            log.warning("table size query failed", extra={"error": exc.__class__.__name__})
    try:
        bdir = cfg.data_dir.parent.parent / "backups" / "cppmmon"  # /var/backups/cppmmon
        backups = sorted(bdir.glob("cppmmon-*.tar.gz")) if bdir.exists() else []
    except OSError:
        backups = []
    data["backup"] = backups[-1].name if backups else None
    return data


@bp.get("/health")
@login_required
def health() -> Any:
    """Monitor health: services, receiver, engine, poller jobs, storage (CLAUDE.md §4.7)."""
    return render_template("health.html", active="health", **_health_data())


@bp.get("/health/body")
@login_required
def health_body() -> Any:
    """HTMX partial: the whole Health body, refreshed every 15 s."""
    return render_template("_health_body.html", **_health_data())


@bp.get("/healthz")
def healthz() -> Any:
    """Unauthenticated liveness probe for curl/monitoring. No sensitive data."""
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify(status="ok", db="ok")
    except SQLAlchemyError as exc:
        log.error("healthz db check failed", extra={"error": exc.__class__.__name__})
        return jsonify(status="degraded", db="error"), 503
