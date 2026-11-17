"""Live Traps and Live Syslog pages (DESIGN §9): filters + incremental tail via ``after_id``."""
from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, make_response, render_template, request
from flask_login import login_required
from sqlalchemy import Select, or_, select

from cppmmon.db.models import Node, RawSyslog, RawTrap
from cppmmon.db.session import session_scope

log = logging.getLogger("cppmmon.web.events")
bp = Blueprint("events", __name__)

PAGE = 200


def _filters() -> dict[str, Any]:
    a = request.args
    return {
        "node": a.get("node", type=int),
        "q": (a.get("q") or "").strip()[:128],
        "kind": a.get("kind") or "",  # traps: unknown|unregistered|badcomm ; syslog: fmt
    }


def _nodes(s: Any) -> dict[int, str]:
    return {n.id: n.name for n in s.scalars(select(Node).order_by(Node.name))}


def _trap_query(f: dict[str, Any], after_id: int | None) -> Select:
    stmt = select(RawTrap).order_by(RawTrap.id.desc()).limit(PAGE)
    if after_id:
        stmt = stmt.where(RawTrap.id > after_id)
    if f["node"]:
        stmt = stmt.where(RawTrap.node_id == f["node"])
    if f["q"]:
        like = f"%{f['q']}%"
        stmt = stmt.where(or_(RawTrap.trap_oid.like(like), RawTrap.trap_name.like(like), RawTrap.src_ip.like(like)))
    if f["kind"] == "unknown":
        stmt = stmt.where(RawTrap.trap_name.is_(None))
    elif f["kind"] == "unregistered":
        stmt = stmt.where(RawTrap.node_id.is_(None))
    elif f["kind"] == "badcomm":
        stmt = stmt.where(RawTrap.community_ok.is_(False))
    return stmt


def _syslog_query(f: dict[str, Any], after_id: int | None) -> Select:
    stmt = select(RawSyslog).order_by(RawSyslog.id.desc()).limit(PAGE)
    if after_id:
        stmt = stmt.where(RawSyslog.id > after_id)
    if f["node"]:
        stmt = stmt.where(RawSyslog.node_id == f["node"])
    if f["q"]:
        stmt = stmt.where(RawSyslog.msg.like(f"%{f['q']}%"))
    if f["kind"]:
        stmt = stmt.where(RawSyslog.fmt == f["kind"])
    return stmt


def _rows_response(template: str, rows: list[Any], nodes: dict[int, str], after_id: int) -> Any:
    max_id = max([r.id for r in rows], default=after_id)
    resp = make_response(render_template(template, rows=rows, nodes=nodes))
    resp.headers["X-Max-Id"] = str(max_id)
    return resp


@bp.get("/traps")
@login_required
def traps() -> Any:
    """Live Traps page."""
    f = _filters()
    with session_scope() as s:
        rows = list(s.scalars(_trap_query(f, None)))
        nodes = _nodes(s)
    return render_template("events/traps.html", rows=rows, nodes=nodes, f=f,
                           max_id=max([r.id for r in rows], default=0), active="traps")


@bp.get("/traps/rows")
@login_required
def trap_rows() -> Any:
    """Live-tail fragment: rows newer than ``after_id`` (newest first)."""
    f = _filters()
    after = request.args.get("after_id", default=0, type=int)
    with session_scope() as s:
        rows = list(s.scalars(_trap_query(f, after)))
        nodes = _nodes(s)
    return _rows_response("events/_trap_rows.html", rows, nodes, after)


@bp.get("/syslog")
@login_required
def syslog() -> Any:
    """Live Syslog page."""
    f = _filters()
    with session_scope() as s:
        rows = list(s.scalars(_syslog_query(f, None)))
        nodes = _nodes(s)
    return render_template("events/syslog.html", rows=rows, nodes=nodes, f=f,
                           max_id=max([r.id for r in rows], default=0), active="syslog")


@bp.get("/syslog/rows")
@login_required
def syslog_rows() -> Any:
    """Live-tail fragment for syslog (DESIGN: polling ``/api/syslog?after_id=``)."""
    f = _filters()
    after = request.args.get("after_id", default=0, type=int)
    with session_scope() as s:
        rows = list(s.scalars(_syslog_query(f, after)))
        nodes = _nodes(s)
    return _rows_response("events/_syslog_rows.html", rows, nodes, after)
