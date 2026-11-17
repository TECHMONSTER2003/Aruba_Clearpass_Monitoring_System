"""Nodes: CRUD with write-only encrypted credentials, and Test Connection (DESIGN §9)."""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from cppmmon.collectors.probe import probe_sync
from cppmmon.collectors.snmp_client import AUTH_PROTOCOLS, PRIV_PROTOCOLS
from cppmmon.crypto import CryptoError, encrypt
from cppmmon.db.models import AuditLog, Node, NodeState
from cppmmon.db.session import session_scope, utcnow
from cppmmon.node_creds import api_params, snmp_params

log = logging.getLogger("cppmmon.web.nodes")
bp = Blueprint("nodes", __name__, url_prefix="/nodes")

# (form field, model column) for write-only secrets
SECRETS = (
    ("snmp_community", "snmp_community_enc"),
    ("snmp_v3_auth_key", "snmp_v3_auth_key_enc"),
    ("snmp_v3_priv_key", "snmp_v3_priv_key_enc"),
    ("trap_community", "trap_community_enc"),
    ("api_client_secret", "api_client_secret_enc"),
    ("api_password", "api_password_enc"),
)


def _can_edit() -> bool:
    return getattr(current_user, "role", "viewer") in ("admin", "operator")


def _require_edit() -> None:
    if not _can_edit():
        abort(403)


@dataclass
class FormResult:
    """Validated form values (plaintext secrets only in memory) plus field errors."""

    values: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)  # newly typed secrets
    clear: set[str] = field(default_factory=set)  # secrets the user chose to remove
    errors: dict[str, str] = field(default_factory=dict)


def _parse_form(existing: Node | None) -> FormResult:
    f = request.form
    r = FormResult()
    g = lambda k: (f.get(k) or "").strip()  # noqa: E731

    r.values["name"] = g("name")[:128]
    if not r.values["name"]:
        r.errors["name"] = "Name is required."
    ip = g("ip")
    try:
        r.values["ip"] = str(ipaddress.ip_address(ip))
    except ValueError:
        r.values["ip"] = ip
        r.errors["ip"] = "Enter a valid IPv4 or IPv6 address."
    r.values["site"] = g("site")[:128] or None
    if "maintenance_until" in f:
        mu = g("maintenance_until")
        if not mu:
            r.values["maintenance_until"] = None
        else:
            try:
                tz = ZoneInfo(current_app.config["CPPMMON_SETTINGS"].display_tz)
                local = datetime.fromisoformat(mu).replace(tzinfo=tz)
                r.values["maintenance_until"] = local.astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                r.errors["maintenance_until"] = "Use the date/time picker (YYYY-MM-DD HH:MM)."
    if f.get("enabled_present"):  # the checkbox only exists on the form; API/tests may omit it
        r.values["enabled"] = f.get("enabled") == "on"
    elif existing is None:
        r.values["enabled"] = True

    r.values["snmp_version"] = g("snmp_version") if g("snmp_version") in ("2c", "3") else "2c"
    try:
        port = int(g("snmp_port") or 161)
        if not 1 <= port <= 65535:
            raise ValueError
        r.values["snmp_port"] = port
    except ValueError:
        r.values["snmp_port"] = g("snmp_port")
        r.errors["snmp_port"] = "Port must be 1–65535."
    r.values["snmp_v3_user"] = g("snmp_v3_user")[:64] or None
    ap, pp = g("snmp_v3_auth_proto"), g("snmp_v3_priv_proto")
    r.values["snmp_v3_auth_proto"] = ap if ap in AUTH_PROTOCOLS else None
    r.values["snmp_v3_priv_proto"] = pp if pp in PRIV_PROTOCOLS else None

    r.values["api_enabled"] = f.get("api_enabled") == "on"
    r.values["api_grant_type"] = g("api_grant_type") if g("api_grant_type") in ("client_credentials", "password") else "client_credentials"
    r.values["api_client_id"] = g("api_client_id")[:128] or None
    r.values["api_username"] = g("api_username")[:128] or None
    r.values["api_verify_tls"] = f.get("api_verify_tls") == "on"

    for form_key, col in SECRETS:
        val = f.get(form_key) or ""
        if val:
            r.secrets[col] = val
        elif f.get(f"clear_{form_key}") == "on":
            r.clear.add(col)

    def has(col: str) -> bool:
        if col in r.clear:
            return False
        return col in r.secrets or bool(existing is not None and getattr(existing, col))

    if r.values["snmp_version"] == "2c" and not has("snmp_community_enc"):
        r.errors["snmp_community"] = "Community is required for SNMP v2c."
    if r.values["snmp_version"] == "3":
        if not r.values["snmp_v3_user"]:
            r.errors["snmp_v3_user"] = "User is required for SNMPv3."
        if r.values["snmp_v3_auth_proto"] and not has("snmp_v3_auth_key_enc"):
            r.errors["snmp_v3_auth_key"] = "Auth key is required when an auth protocol is selected."
        if r.values["snmp_v3_priv_proto"]:
            if not r.values["snmp_v3_auth_proto"]:
                r.errors["snmp_v3_priv_proto"] = "Privacy requires an auth protocol (authPriv)."
            elif not has("snmp_v3_priv_key_enc"):
                r.errors["snmp_v3_priv_key"] = "Priv key is required when a privacy protocol is selected."
    for col in ("snmp_v3_auth_key_enc", "snmp_v3_priv_key_enc"):
        if col in r.secrets and len(r.secrets[col]) < 8:
            r.errors[col.removesuffix("_enc")] = "SNMPv3 keys must be at least 8 characters."
    if r.values["api_enabled"]:
        if not r.values["api_client_id"]:
            r.errors["api_client_id"] = "Client ID is required when the API is enabled."
        if r.values["api_grant_type"] == "password":
            if not r.values["api_username"]:
                r.errors["api_username"] = "Username is required for the password grant."
            if not has("api_password_enc"):
                r.errors["api_password"] = "Password is required for the password grant."
        elif not has("api_client_secret_enc"):
            r.errors["api_client_secret"] = "Client secret is required for client_credentials."
    return r


def _apply(node: Node, r: FormResult) -> list[str]:
    """Copy validated values onto ``node``; returns names of changed secret fields (for audit)."""
    for k, v in r.values.items():
        setattr(node, k, v)
    changed: list[str] = []
    for col, plain in r.secrets.items():
        setattr(node, col, encrypt(plain))
        changed.append(col.removesuffix("_enc"))
    for col in r.clear:
        setattr(node, col, None)
        changed.append(col.removesuffix("_enc") + " (cleared)")
    return changed


def _draft_node(r: FormResult, existing: Node | None) -> Node:
    """Unsaved Node from form values; blank secrets fall back to the stored ones."""
    n = Node()
    if existing is not None:
        for col in [c.key for c in Node.__table__.columns]:
            setattr(n, col, getattr(existing, col))
    _apply(n, r)
    return n


def _summarise(results: list[Any]) -> dict[str, Any]:
    return {"at": utcnow().isoformat(timespec="seconds"), "by": current_user.username,
            "checks": [x.to_dict() for x in results]}


# ---------------------------------------------------------------- overview

CHARTS = {
    "res": (["cpu_pct", "mem_pct", "disk_pct"], "%"),
    "auth": (["auth_per_min", "auth_fail_per_min"], "/min"),
    "icmp": (["icmp_rtt_ms"], "ms"),
    "authsrc": (["auth_src_fail_per_min"], "/min"),
    "net": (["if_in_bps", "if_out_bps"], "bps"),
}


@bp.get("/<int:node_id>/overview")
@login_required
def overview(node_id: int) -> Any:
    """Node detail: charts, services, certificates, licenses, recent traps/syslog."""
    from cppmmon.db.models import Alert, Certificate, License, RawSyslog, RawTrap, ServiceStatus
    from cppmmon.web.kpis import latest_metrics, node_summaries

    with session_scope() as s:
        tiles = node_summaries(s, [node_id])
        if not tiles:
            abort(404)
        services = list(s.scalars(select(ServiceStatus).where(ServiceStatus.node_id == node_id).order_by(ServiceStatus.service_name)))
        certs = list(s.scalars(select(Certificate).where(Certificate.node_id == node_id)
                               .order_by(Certificate.cert_type.desc(), Certificate.days_left)))
        lic = list(s.scalars(select(License).where(License.node_id == node_id).order_by(License.app_name)))
        traps = list(s.scalars(select(RawTrap).where(RawTrap.node_id == node_id).order_by(RawTrap.id.desc()).limit(10)))
        logs = list(s.scalars(select(RawSyslog).where(RawSyslog.node_id == node_id).order_by(RawSyslog.id.desc()).limit(10)))
        alerts = list(s.scalars(select(Alert).where(Alert.node_id == node_id, Alert.state == "open").order_by(Alert.last_seen.desc())))
        lm = latest_metrics(s, [node_id], ("if_in_bps", "if_out_bps", "if_errors_per_min", "if_oper_up", "disk_mount_pct",
                                           "auth_src_fail_per_min", "auth_src_req_per_min"), utcnow() - timedelta(minutes=15))[node_id]
    ifaces: dict[str, dict[str, float]] = {}
    mounts: dict[str, float] = {}
    sources: dict[str, dict[str, float]] = {}
    for key, (val, _ts) in lm.items():
        metric, _, inst = key.partition("|")
        if metric.startswith("if_"):
            ifaces.setdefault(inst, {})[metric] = val
        elif metric == "disk_mount_pct":
            mounts[inst] = val
        elif metric.startswith("auth_src_"):
            sources.setdefault(inst, {})[metric] = val
    hours = request.args.get("hours", default=24, type=float)
    return render_template("nodes/overview.html", t=tiles[0], services=services, certs=certs, lic=lic, traps=traps, logs=logs,
                           alerts=alerts, ifaces=ifaces, mounts=mounts, sources=sources, charts=CHARTS,
                           hours=hours if hours in (1, 6, 24, 72, 168) else 24, now=utcnow(), active="nodes")


@bp.get("/<int:node_id>/series.json")
@login_required
def series_json(node_id: int) -> Any:
    """Chart data: ?chart=res|auth|icmp|authsrc|net&hours=N → {series: {key: [[ms, v], ...]}}."""
    from flask import jsonify

    from cppmmon.web.kpis import series

    chart = request.args.get("chart", "res")
    if chart not in CHARTS:
        abort(400)
    hours = min(max(request.args.get("hours", default=24, type=float), 0.25), 168)
    with session_scope() as s:
        data = series(s, node_id, CHARTS[chart][0], hours)
    if chart in ("authsrc", "net"):  # keep the busiest 6 series readable
        data = dict(sorted(data.items(), key=lambda kv: -max((p[1] for p in kv[1]), default=0))[:6])
    return jsonify(series=data, unit=CHARTS[chart][1])


# ---------------------------------------------------------------- poll now

@bp.post("/<int:node_id>/poll")
@login_required
def poll_node(node_id: int) -> Any:
    """'Poll now' for one node: all of its jobs run immediately (picked up by the poller within ~2 s)."""
    from cppmmon.web.auth import _safe_next
    from cppmmon.web.routes.main import queue_poll

    _require_edit()
    with session_scope() as s:
        n = s.get(Node, node_id)
        if n is None:
            abort(404)
        name, enabled = n.name, n.enabled
    if not enabled:
        flash(f"{name} has polling paused: enable it in Settings first.", "error")
    else:
        queue_poll(node_id, current_user.username)
        flash(f"Poll requested for {name}: fresh values appear within ~30 s.", "info")
    return redirect(_safe_next(request.form.get("next")))


# ------------------------------------------------------- cluster discovery

COPY_GROUPS = {
    "snmp": ("snmp_version", "snmp_port", "snmp_community_enc", "snmp_v3_user", "snmp_v3_auth_proto",
             "snmp_v3_auth_key_enc", "snmp_v3_priv_proto", "snmp_v3_priv_key_enc"),
    "api": ("api_enabled", "api_grant_type", "api_client_id", "api_client_secret_enc", "api_username",
            "api_password_enc", "api_verify_tls"),
    "trap": ("trap_community_enc",),
}


def _cluster_members(src: Node) -> list[dict[str, Any]]:
    """Live GET /api/cluster/server through ``src``'s API credentials."""
    import asyncio

    from cppmmon.collectors.cppm_api import CppmApi, fetch_cluster

    params = api_params(src)
    if params is None:
        raise ValueError("REST API is disabled on this node; enable it to discover the cluster.")

    async def go() -> list[dict[str, Any]]:
        async with CppmApi(params) as api:
            return await fetch_cluster(api)

    return asyncio.run(go())


@bp.route("/<int:node_id>/discover", methods=["GET", "POST"])
@login_required
def discover(node_id: int) -> Any:
    """List this node's cluster members (from the CPPM API) and add the unmonitored ones."""
    from cppmmon.collectors.cppm_api import ApiError

    _require_edit()
    with session_scope() as s:
        src = s.get(Node, node_id)
        if src is None:
            abort(404)
        try:
            members = _cluster_members(src)
        except (ApiError, ValueError, CryptoError) as exc:
            flash(f"Cluster discovery via {src.name} failed: {exc}", "error")
            return redirect(url_for("nodes.overview", node_id=node_id))
        known = {n.ip: n for n in s.scalars(select(Node))}
        rows = [{"name": m.get("name") or m.get("server_dns_name") or m.get("management_ip"),
                 "ip": m.get("management_ip"), "publisher": bool(m.get("is_publisher")),
                 "replication": m.get("replication_status"), "uuid": m.get("server_uuid"),
                 "node": known.get(m.get("management_ip"))} for m in members if m.get("management_ip")]

        if request.method == "GET":
            return render_template("nodes/discover.html", src=src, rows=rows, active="nodes")

        wanted = set(request.form.getlist("ip"))
        groups = [g for g in COPY_GROUPS if request.form.get(f"copy_{g}") == "on"]
        added = []
        for r in rows:
            if r["ip"] not in wanted or r["node"] is not None:
                continue
            n = Node(name=str(r["name"])[:128], ip=r["ip"], site=src.site,
                     role="publisher" if r["publisher"] else "subscriber", enabled=True)
            for g in groups:
                for col in COPY_GROUPS[g]:
                    setattr(n, col, getattr(src, col))  # encrypted values copied as-is (never decrypted)
            if "snmp" not in groups:
                n.snmp_version = src.snmp_version
            s.add(n)
            s.flush()
            s.add(NodeState(node_id=n.id, status="unknown"))
            added.append(f"{n.name} ({n.ip})")
        s.add(AuditLog(user=current_user.username, action="node.discover", target=f"{src.name} ({src.ip})",
                       detail={"added": added, "copied": groups}))
    if added:
        flash(f"Added {len(added)} node(s): {', '.join(added)}. Polling starts within 60 s; "
              "run Test Connection on each to confirm the copied credentials.", "info")
    else:
        flash("Nothing added (no unmonitored members were selected).", "info")
    return redirect(url_for("nodes.index"))


# ------------------------------------------------------------------- views


@bp.get("/")
@login_required
def index() -> Any:
    """Node list with the last Test Connection result."""
    with session_scope() as s:
        rows = s.execute(select(Node, NodeState).outerjoin(NodeState, NodeState.node_id == Node.id).order_by(Node.name)).all()
    return render_template("nodes/index.html", rows=rows, can_edit=_can_edit(), active="nodes")


@bp.route("/new", methods=["GET", "POST"])
@login_required
def create() -> Any:
    """Add a node."""
    _require_edit()
    if request.method == "GET":
        return render_template("nodes/form.html", node=None, v={"snmp_version": "2c", "snmp_port": 161, "api_grant_type": "client_credentials"},
                               errors={}, auth_protos=AUTH_PROTOCOLS, priv_protos=PRIV_PROTOCOLS, active="nodes")
    r = _parse_form(None)
    if not r.errors:
        try:
            with session_scope() as s:
                node = Node()
                changed = _apply(node, r)
                s.add(node)
                s.flush()
                s.add(NodeState(node_id=node.id, status="unknown"))
                s.add(AuditLog(user=current_user.username, action="node.create", target=f"{node.name} ({node.ip})",
                               detail={"secrets_set": changed}))
                node_id = node.id
            log.info("node created", extra={"node_id": node_id, "ip": r.values["ip"], "user": current_user.username})
            flash(f"Node “{r.values['name']}” added. Run Test Connection to verify ICMP, SNMP and API.", "info")
            return redirect(url_for("nodes.edit", node_id=node_id, test=1))
        except IntegrityError:
            r.errors["ip"] = "A node with this IP already exists."
        except (SQLAlchemyError, CryptoError) as exc:
            log.error("node create failed", extra={"error": exc.__class__.__name__})
            flash("Could not save the node (database or key error). See web.log.", "error")
    return render_template("nodes/form.html", node=None, v=r.values, errors=r.errors,
                           auth_protos=AUTH_PROTOCOLS, priv_protos=PRIV_PROTOCOLS, active="nodes"), 400


@bp.route("/<int:node_id>", methods=["GET", "POST"])
@login_required
def edit(node_id: int) -> Any:
    """View/edit a node. Secrets are never rendered back."""
    with session_scope() as s:
        node = s.get(Node, node_id)
        if node is None:
            abort(404)
        state = s.get(NodeState, node_id)
        if request.method == "GET":
            v = {c.key: getattr(node, c.key) for c in Node.__table__.columns}
            return render_template("nodes/form.html", node=node, state=state, v=v, errors={}, can_edit=_can_edit(),
                                   auth_protos=AUTH_PROTOCOLS, priv_protos=PRIV_PROTOCOLS,
                                   autotest=request.args.get("test") == "1", active="nodes")
        _require_edit()
        r = _parse_form(node)
        if not r.errors:
            try:
                changed = _apply(node, r)
                s.add(AuditLog(user=current_user.username, action="node.update", target=f"{node.name} ({node.ip})",
                               detail={"secrets_changed": changed}))
                s.flush()
            except IntegrityError:
                s.rollback()
                r.errors["ip"] = "A node with this IP already exists."
            except CryptoError:
                s.rollback()
                flash("Could not encrypt credentials (secret key problem). See web.log.", "error")
            else:
                log.info("node updated", extra={"node_id": node_id, "user": current_user.username})
                flash("Changes saved.", "info")
                return redirect(url_for("nodes.edit", node_id=node_id))
        return render_template("nodes/form.html", node=node, state=state, v=r.values, errors=r.errors, can_edit=True,
                               auth_protos=AUTH_PROTOCOLS, priv_protos=PRIV_PROTOCOLS, active="nodes"), 400


@bp.post("/<int:node_id>/delete")
@login_required
def delete(node_id: int) -> Any:
    """Delete a node (admin only). Historic raw/metric rows are kept."""
    if not getattr(current_user, "is_admin", False):
        abort(403)
    with session_scope() as s:
        node = s.get(Node, node_id)
        if node is None:
            abort(404)
        if (request.form.get("confirm") or "").strip() != node.name:
            flash("Type the node name exactly to confirm deletion.", "error")
            return redirect(url_for("nodes.edit", node_id=node_id))
        from cppmmon.db.models import Alert
        from cppmmon.web.routes.alerts import _queue_clear

        # Resolve the node's open alerts (children before NODE DOWN), so nothing stays open for a node that no longer exists.
        open_alerts = sorted(s.scalars(select(Alert).where(Alert.node_id == node_id, Alert.state.in_(("open", "suppressed")))),
                             key=lambda a: a.rule_id == "node.down")
        for a in open_alerts:
            _queue_clear(s, a, f"{current_user.username} (node deleted)")
        s.add(AuditLog(user=current_user.username, action="node.delete", target=f"{node.name} ({node.ip})",
                       detail={"alerts_resolved": [a.id for a in open_alerts]}))
        s.delete(node)
    flash(f"Node deleted{f'; {len(open_alerts)} open alert(s) are being resolved' if open_alerts else ''}.", "info")
    return redirect(url_for("nodes.index"))


@bp.post("/test")
@login_required
def test_draft() -> Any:
    """HTMX: Test Connection with the values currently in the form (saved or not).

    Blank secret fields fall back to the stored values of ``node_id``. For a saved
    node the result (no secrets) is recorded in ``node_state.last_test``.
    """
    _require_edit()
    node_id = request.form.get("node_id", type=int)
    with session_scope() as s:
        existing = s.get(Node, node_id) if node_id else None
        r = _parse_form(existing)
        blocking = {k: v for k, v in r.errors.items() if k in ("ip",)}
        if blocking:
            return render_template("nodes/_test_results.html", checks=[], error=blocking["ip"])
        try:
            draft = _draft_node(r, existing)
            sp = snmp_params(draft)
            ap = api_params(draft)
        except CryptoError:
            return render_template("nodes/_test_results.html", checks=[], error="Stored credentials could not be decrypted (secret key mismatch).")

    results = probe_sync(draft.ip, sp if not any(k.startswith("snmp") for k in r.errors) else None, ap)
    if any(k.startswith("snmp") for k in r.errors):
        results[1].skipped = True
        results[1].summary = "SNMP fields incomplete"
    summary = _summarise(results)

    if existing is not None:
        with session_scope() as s:
            st = s.get(NodeState, existing.id) or NodeState(node_id=existing.id)
            st.last_test_at = utcnow()
            st.last_test = summary
            snmp_r = results[1]
            if snmp_r.ok:
                d = snmp_r.details
                st.sys_index = d.get("sys_index")
                st.hostname = d.get("hostname") or d.get("sys_name")
                st.version = d.get("version") or st.version
                st.model = d.get("model") or st.model
                st.serial = d.get("serial") or st.serial
                st.node_type = d.get("node_type") or st.node_type
            api_r = results[2]
            if not api_r.skipped:
                st.api_state = "ok" if api_r.ok else ("auth_failed" if api_r.details.get("kind") in ("invalid_client", "invalid_grant", "grant_type", "auth") else "unreachable")
            s.merge(st)
            s.add(AuditLog(user=current_user.username, action="node.test", target=existing.ip,
                           detail={c["name"]: ("skip" if c["skipped"] else c["ok"]) for c in summary["checks"]}))
    return render_template("nodes/_test_results.html", checks=summary["checks"], error=None, at=summary["at"], fresh=True)
