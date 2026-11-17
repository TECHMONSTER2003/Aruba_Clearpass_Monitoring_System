"""Alerts, Tickets and Thresholds pages (DESIGN §9).

The web never writes ``alerts``/``tickets`` (the engine is the single writer):
a manual resolve inserts an internal clear event that the engine processes.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from sqlalchemy import func, select

from cppmmon.db.models import Alert, AuditLog, Event, Node, Threshold, Ticket
from cppmmon.db.session import session_scope, utcnow

log = logging.getLogger("cppmmon.web.alerts")
bp = Blueprint("alerts", __name__)


def _can_edit() -> bool:
    return getattr(current_user, "role", "viewer") in ("admin", "operator")


# ----------------------------------------------------------------- alerts

@bp.get("/alerts")
@login_required
def alerts() -> Any:
    """Open / suppressed / cleared alerts with linked tickets."""
    state = request.args.get("state", "active")
    with session_scope() as s:
        q = select(Alert).order_by(Alert.last_seen.desc()).limit(500)
        if state == "active":
            q = q.where(Alert.state.in_(("open", "suppressed")))
        elif state in ("open", "suppressed", "cleared"):
            q = q.where(Alert.state == state)
        rows = list(s.scalars(q))
        nodes = {n.id: n.name for n in s.scalars(select(Node))}
        tickets = {t.id: t for t in s.scalars(select(Ticket).where(Ticket.id.in_([a.ticket_id for a in rows if a.ticket_id])))}
        counts = dict(s.execute(select(Alert.state, func.count()).group_by(Alert.state)).all())
    return render_template("alerts/index.html", rows=rows, nodes=nodes, tickets=tickets, state=state, counts=counts,
                           can_edit=_can_edit(), active="alerts")


def _queue_clear(s: Any, a: Alert, user: str) -> None:
    """Insert the internal clear event the engine turns into a resolve (web never writes alerts)."""
    _scope, etype, instance = (a.dedup_key.split("|", 2) + ["", ""])[:3]
    s.add(Event(ts=utcnow(), node_id=a.node_id, source="internal", event_type=etype, severity="info", is_clear=True,
                dedup_instance=instance, processed=0,
                attributes={"clears": etype, "manual_by": user, "title": f"manually resolved: {a.title}"}))


@bp.post("/alerts/<int:alert_id>/resolve")
@login_required
def resolve(alert_id: int) -> Any:
    """Queue a manual clear for one alert."""
    if not _can_edit():
        abort(403)
    with session_scope() as s:
        a = s.get(Alert, alert_id)
        if a is None or a.state == "cleared":
            abort(404)
        _queue_clear(s, a, current_user.username)
        s.add(AuditLog(user=current_user.username, action="alert.resolve", target=a.dedup_key, detail={"alert_id": a.id}))
    flash("Resolve queued: the engine applies it within a few seconds and resolves the ticket.", "info")
    return redirect(url_for("alerts.alerts"))


@bp.post("/alerts/resolve")
@login_required
def resolve_bulk() -> Any:
    """Resolve the ticked alerts (``ids``), or every active alert in the current view (``all=1``)."""
    if not _can_edit():
        abort(403)
    state = request.form.get("state", "active")
    with session_scope() as s:
        q = select(Alert).where(Alert.state.in_(("open", "suppressed")))
        if request.form.get("all") == "1":
            if state in ("open", "suppressed"):
                q = q.where(Alert.state == state)
        else:
            ids = [int(x) for x in request.form.getlist("ids") if x.isdigit()]
            if not ids:
                flash("Tick at least one alert first.", "error")
                return redirect(url_for("alerts.alerts", state=state))
            q = q.where(Alert.id.in_(ids))
        targets = list(s.scalars(q))
        # children before NODE DOWN parents, so clearing a parent never promotes them into new tickets
        targets.sort(key=lambda a: a.rule_id == "node.down")
        for a in targets:
            _queue_clear(s, a, current_user.username)
        s.add(AuditLog(user=current_user.username, action="alert.resolve.bulk", target=f"{len(targets)} alerts",
                       detail={"alert_ids": [a.id for a in targets]}))
    flash(f"Resolve queued for {len(targets)} alert(s); tickets are marked RESOLVED within a few seconds.", "info")
    return redirect(url_for("alerts.alerts", state=state))


# ----------------------------------------------------------------- tickets

@bp.get("/tickets")
@login_required
def tickets() -> Any:
    """Ticket list."""
    status = request.args.get("status", "")
    with session_scope() as s:
        q = select(Ticket).order_by(Ticket.id.desc()).limit(500)
        if status in ("new", "resolved"):
            q = q.where(Ticket.status == status)
        rows = list(s.scalars(q))
        alerts = {a.id: a for a in s.scalars(select(Alert).where(Alert.id.in_([t.alert_id for t in rows])))}
        nodes = {n.id: n.name for n in s.scalars(select(Node))}
    return render_template("alerts/tickets.html", rows=rows, alerts=alerts, nodes=nodes, status=status, active="tickets")


def _ticket_path(t: Ticket) -> Path:
    root = current_app.config["CPPMMON_SETTINGS"].tickets_dir.resolve()
    p = Path(t.file_path).resolve()
    if root not in p.parents:
        abort(404)
    return p


@bp.get("/tickets/<ticket_no>")
@login_required
def ticket(ticket_no: str) -> Any:
    """Ticket text view."""
    with session_scope() as s:
        t = s.scalar(select(Ticket).where(Ticket.ticket_no == ticket_no))
        if t is None:
            abort(404)
        a = s.get(Alert, t.alert_id)
    try:
        body = _ticket_path(t).read_text(encoding="utf-8")
    except OSError as exc:
        log.error("ticket file unreadable", extra={"ticket": ticket_no, "error": str(exc)})
        body = f"(ticket file not readable: {exc.strerror})"
    return render_template("alerts/ticket.html", t=t, a=a, body=body, active="tickets")


@bp.get("/tickets/<ticket_no>/download")
@login_required
def ticket_download(ticket_no: str) -> Any:
    """Download the .txt exactly as written."""
    with session_scope() as s:
        t = s.scalar(select(Ticket).where(Ticket.ticket_no == ticket_no))
        if t is None:
            abort(404)
    return send_file(_ticket_path(t), mimetype="text/plain", as_attachment=True, download_name=f"{ticket_no}.txt")


# -------------------------------------------------------------- thresholds

@bp.route("/thresholds", methods=["GET", "POST"])
@login_required
def thresholds() -> Any:
    """Edit threshold rules (poller reloads them within 60 s)."""
    errors: dict[str, str] = {}
    with session_scope() as s:
        rules = list(s.scalars(select(Threshold).order_by(Threshold.rule_id)))
        if request.method == "POST":
            if not _can_edit():
                abort(403)
            changed = []
            for r in rules:
                p = f"{r.rule_id}__"
                if f"{p}present" not in request.form:
                    continue
                try:
                    vals = {k: _num(request.form.get(p + k)) for k in ("warn_value", "crit_value", "clear_value")}
                    sustain = int(request.form.get(p + "sustain_s") or 0)
                    if sustain < 0 or sustain > 86400:
                        raise ValueError
                except ValueError:
                    errors[r.rule_id] = "Numbers only; sustain 0–86400 s."
                    continue
                if vals["warn_value"] is None and vals["crit_value"] is None:
                    errors[r.rule_id] = "Set a warning or critical value."
                    continue
                enabled = request.form.get(p + "enabled") == "on"
                new = (vals["warn_value"], vals["crit_value"], vals["clear_value"], sustain, enabled)
                old = (r.warn_value, r.crit_value, r.clear_value, r.sustain_s, r.enabled)
                if new != old:
                    r.warn_value, r.crit_value, r.clear_value, r.sustain_s, r.enabled = new
                    changed.append({"rule": r.rule_id, "old": old, "new": new})
            if errors:
                s.rollback()
            elif changed:
                s.add(AuditLog(user=current_user.username, action="thresholds.update", target=",".join(c["rule"] for c in changed),
                               detail={"changes": changed}))
                flash(f"{len(changed)} rule(s) saved. The poller applies them within 60 s.", "info")
                return redirect(url_for("alerts.thresholds"))
            else:
                flash("No changes.", "info")
                return redirect(url_for("alerts.thresholds"))
            rules = list(s.scalars(select(Threshold).order_by(Threshold.rule_id)))
        return render_template("alerts/thresholds.html", rules=rules, errors=errors, can_edit=_can_edit(), active="thresholds")


def _num(v: str | None) -> float | None:
    v = (v or "").strip()
    return None if v == "" else float(v)
