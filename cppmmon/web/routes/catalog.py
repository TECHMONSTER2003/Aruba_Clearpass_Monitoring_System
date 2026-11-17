"""Trap Catalog: view, upload (CSV/YAML), diff preview, apply (DESIGN §9, §6.4)."""
from __future__ import annotations

import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import select

from cppmmon.catalog import loader
from cppmmon.db.models import AuditLog, TrapCatalog, VarbindCatalog
from cppmmon.db.session import session_scope
from cppmmon.web.auth import admin_required

log = logging.getLogger("cppmmon.web.catalog")
bp = Blueprint("catalog", __name__, url_prefix="/catalog")

MAX_UPLOAD = 2 * 1024 * 1024
STAGE_TTL_S = 3600


def _stage_dir() -> Path:
    d = current_app.config["CPPMMON_SETTINGS"].data_dir / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


@bp.get("/")
@login_required
def index() -> Any:
    """Catalog listing."""
    with session_scope() as s:
        traps = list(s.scalars(select(TrapCatalog).order_by(TrapCatalog.oid)))
        vbs = list(s.scalars(select(VarbindCatalog).order_by(VarbindCatalog.oid_prefix)))
        names = {t.oid: t.name for t in traps}
    return render_template("catalog/index.html", traps=traps, vbs=vbs, names=names, active="catalog")


@bp.post("/preview")
@admin_required
def preview() -> Any:
    """Parse an upload and show added/changed/unchanged/untouched before anything is written."""
    f = request.files.get("file")
    if f is None or not f.filename:
        flash("Choose a CSV or YAML file to upload.", "error")
        return redirect(url_for("catalog.index"))
    content = f.stream.read(MAX_UPLOAD + 1)
    if len(content) > MAX_UPLOAD:
        flash("File is larger than 2 MB.", "error")
        return redirect(url_for("catalog.index"))
    try:
        pc = loader.parse(content, f.filename)
    except loader.CatalogError as exc:
        flash(f"Could not read {f.filename}: {exc}", "error")
        return redirect(url_for("catalog.index"))
    for old in _stage_dir().glob("*.json"):
        if time.time() - old.stat().st_mtime > STAGE_TTL_S:
            old.unlink(missing_ok=True)
    token = secrets.token_urlsafe(16)
    (_stage_dir() / f"{token}.json").write_text(json.dumps({"filename": f.filename, "traps": pc.traps,
                                                            "varbinds": pc.varbinds, "errors": pc.errors}))
    with session_scope() as s:
        d = loader.diff(s, pc)
    return render_template("catalog/preview.html", d=d, pc=pc, token=token, filename=f.filename, active="catalog")


@bp.post("/apply")
@admin_required
def apply() -> Any:
    """Commit a previewed upload (upsert by OID; nothing is deleted)."""
    token = request.form.get("token", "")
    path = _stage_dir() / f"{token}.json"
    if not token.replace("-", "").replace("_", "").isalnum() or not path.exists():
        abort(400)
    data = json.loads(path.read_text())
    pc = loader.ParsedCatalog(traps=data["traps"], varbinds=data["varbinds"], errors=data["errors"])
    with session_scope() as s:
        counts = loader.apply(s, pc)
        s.add(AuditLog(user=current_user.username, action="catalog.import", target=data["filename"], detail=counts))
    path.unlink(missing_ok=True)
    flash(f"Catalog updated from {data['filename']}: {counts['added']} added, {counts['updated']} updated, "
          f"{counts['vb_added'] + counts['vb_updated']} varbind names. The receiver picks this up within 30 s.", "info")
    return redirect(url_for("catalog.index"))
