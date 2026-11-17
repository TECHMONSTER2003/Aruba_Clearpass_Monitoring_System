"""Phase 4: alert state machine, correlation and ticket files (DESIGN §7, §8)."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from cppmmon.catalog import loader
from cppmmon.crypto import encrypt
from cppmmon.db.models import Alert, Event, Node, NodeState, Ticket
from cppmmon.db.session import session_scope, utcnow
from cppmmon.engine.main import Engine
from cppmmon.engine.tickets import FileTicketSink

SEED = Path(__file__).resolve().parents[1] / "catalog" / "cppm_traps.yaml"
B = "1.3.6.1.4.1.14823.1.6.1.1.200"


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, Any]:
    with session_scope() as s:
        loader.apply(s, loader.parse(SEED.read_bytes(), SEED.name), seed=True)
        n = Node(name="cppm-pub-01", ip="10.10.10.5", role="publisher", snmp_community_enc=encrypt("x"))
        s.add(n)
        s.flush()
        s.add(NodeState(node_id=n.id, status="up", version="6.14.1.372486"))
        nid = n.id
    from cppmmon.config import get_settings

    root = get_settings().tickets_dir  # same root the web app serves tickets from
    sink = FileTicketSink(root)
    return {"node_id": nid, "engine": Engine(sink), "root": root}


def trap(nid: int, name: str, oid_suffix: str, sev: str, vb: dict[str, Any], clears: str | None = None,
         instance: str = "") -> None:
    attrs: dict[str, Any] = {"trap_oid": f"{B}.{oid_suffix}", "vb": vb, "src_ip": "10.10.10.5"}
    if clears:
        attrs["clears"] = clears
    with session_scope() as s:
        s.add(Event(ts=utcnow(), node_id=nid, source="trap", event_type=name, severity=sev, is_clear=bool(clears),
                    dedup_instance=instance, attributes=attrs, raw_ref="trap:12345", processed=0))


def poll(nid: int, etype: str, sev: str, title: str, clear: bool = False, instance: str = "", **attrs: Any) -> None:
    with session_scope() as s:
        s.add(Event(ts=utcnow(), node_id=nid, source="poll", event_type=etype, severity=sev, is_clear=clear,
                    dedup_instance=instance, attributes={"title": title, **attrs}, processed=0))


def alerts() -> list[Alert]:
    with session_scope() as s:
        return list(s.scalars(select(Alert).order_by(Alert.id)))


def tickets() -> list[Ticket]:
    with session_scope() as s:
        return list(s.scalars(select(Ticket).order_by(Ticket.id)))


STOP = dict(name="cppmServiceStopNotification", oid_suffix="1017", sev="high",
            vb={"cppmServiceName": "Radius server", "cppmTrapMessage": "Radius server stopped"}, instance="Radius server")


def test_stop_reoccur_start_lifecycle(env: dict[str, Any]) -> None:
    nid, eng = env["node_id"], env["engine"]
    trap(nid, **STOP)
    eng.run_batch()
    [a], [t] = alerts(), tickets()
    assert a.state == "open" and a.severity == "high" and a.ticket_id == t.id
    assert a.rule_id == "service.down" and a.dedup_key.endswith("|service.down|radius server")
    assert a.title == "[CPPM][HIGH] Radius server stopped on cppm-pub-01"
    body = Path(t.file_path).read_text()
    for line in ("STATUS      : NEW", "Priority            : P2 - High", "Impact / Urgency    : 2 / 2",
                 "Configuration Item  : cppm-pub-01 (10.10.10.5) | Publisher | 6.14.1.372486 | SN: n/a",
                 "Service        : Radius server", "Trap Message   : Radius server stopped",
                 f"Source         : SNMP Trap (cppmServiceStopNotification, .{B}.1017)", "raw_trap_id=12345",
                 "Last poll: CPU n/a | Mem n/a | Disk n/a | Services:", "1. Administration > Server Manager"):
        assert line in body, line
    assert t.file_path.endswith(f"{t.ticket_no}.txt") and t.ticket_no.endswith("-0001")

    trap(nid, **STOP)  # repeat: same alert, no new ticket
    eng.run_batch()
    [a2] = alerts()
    assert a2.occurrences == 2 and len(tickets()) == 1
    assert "RE-OCCUR" in Path(t.file_path).read_text()

    trap(nid, "cppmServiceStartNotification", "1018", "info", {"cppmServiceName": "Radius server"},
         clears="cppmServiceStopNotification", instance="Radius server")
    eng.run_batch()
    [a3], [t3] = alerts(), tickets()
    assert a3.state == "cleared" and a3.open_marker is None and t3.status == "resolved"
    body = Path(t3.file_path).read_text()
    assert "STATUS      : RESOLVED" in body
    assert "RESOLVED  cppmServiceStartNotification received (Radius server)" in body
    assert body.rstrip().endswith("=" * 64)
    log_lines = [json.loads(x) for x in (env["root"] / "alerts.log").read_text().splitlines()]
    assert [x["action"] for x in log_lines] == ["opened", "reoccurred", "cleared"]

    trap(nid, **STOP)  # after clear: a new alert and a new ticket
    eng.run_batch()
    assert len(alerts()) == 2 and tickets()[-1].ticket_no.endswith("-0002")


def test_noncritical_service_is_medium_and_info_traps_are_log_only(env: dict[str, Any]) -> None:
    nid, eng = env["node_id"], env["engine"]
    trap(nid, "cppmServiceStopNotification", "1017", "high", {"cppmServiceName": "Ingress logger service"}, instance="Ingress logger service")
    trap(nid, "cppmClusterPwdChangeNotification", "1011", "info", {})
    trap(nid, "UNKNOWN_TRAP", "9999", "info", {})
    eng.run_batch()
    [a] = alerts()
    assert a.severity == "medium" and tickets()[0].priority.startswith("P3")


def test_node_down_suppresses_and_promotes(env: dict[str, Any]) -> None:
    nid, eng = env["node_id"], env["engine"]
    poll(nid, "threshold.cpu", "high", "[CPPM][HIGH] CPU 97% on cppm-pub-01", instance="", rule_id="cpu", metric="cpu_pct",
         value=97, op=">", threshold=95, unit="%", level="crit")
    eng.run_batch()
    poll(nid, "node.down", "critical", "[CPPM][CRITICAL] NODE DOWN: cppm-pub-01")
    eng.run_batch()
    trap(nid, **STOP)  # arrives while down → suppressed, no ticket
    eng.run_batch()
    by_rule = {a.rule_id: a for a in alerts()}
    down = by_rule["node.down"]
    assert down.state == "open" and down.severity == "critical"
    assert by_rule["threshold.cpu"].state == "suppressed" and by_rule["threshold.cpu"].parent_alert_id == down.id
    assert by_rule["service.down"].state == "suppressed"
    assert by_rule["service.down"].ticket_id is None
    down_ticket = next(t for t in tickets() if t.alert_id == down.id)
    assert down_ticket.priority.startswith("P1") and "SUPPRESS" in Path(down_ticket.file_path).read_text()

    poll(nid, "node.down", "info", "cppm-pub-01 reachable again", clear=True)
    eng.run_batch()
    by_rule = {a.rule_id: a for a in alerts()}
    assert by_rule["node.down"].state == "cleared"
    stop = by_rule["service.down"]
    assert stop.state == "open" and stop.ticket_id is not None  # promoted with its own ticket


def test_maintenance_window_records_without_ticket(env: dict[str, Any]) -> None:
    nid, eng = env["node_id"], env["engine"]
    with session_scope() as s:
        s.get(Node, nid).maintenance_until = utcnow() + timedelta(hours=1)
    trap(nid, **STOP)
    eng.run_batch()
    [a] = alerts()
    assert a.state == "suppressed" and a.suppress_reason == "maintenance" and not tickets()


def test_flap_guard(env: dict[str, Any]) -> None:
    nid, eng = env["node_id"], env["engine"]
    start = dict(name="cppmServiceStartNotification", oid_suffix="1018", sev="info", vb={"cppmServiceName": "Radius server"},
                 clears="cppmServiceStopNotification", instance="Radius server")
    for _ in range(3):
        trap(nid, **STOP)
        eng.run_batch()
        trap(nid, **start)
        eng.run_batch()
    trap(nid, **STOP)  # 4th opening within 30 min
    eng.run_batch()
    a = alerts()[-1]
    assert a.flapping and a.severity == "critical" and a.title.startswith("FLAPPING:")
    trap(nid, **start)  # clear while flapping: kept open, clear pending
    eng.run_batch()
    a = alerts()[-1]
    assert a.state == "open" and a.clear_pending_at is not None
    with session_scope() as s:  # 31 min of quiet → housekeeping clears it
        x = s.get(Alert, a.id)
        x.clear_pending_at = x.last_seen = utcnow() - timedelta(minutes=31)
    eng.housekeeping()
    assert alerts()[-1].state == "cleared"


def test_threshold_poll_events_open_and_clear(env: dict[str, Any]) -> None:
    nid, eng = env["node_id"], env["engine"]
    poll(nid, "threshold.cert", "critical", "[CPPM][CRITICAL] Certificate expiry server:HTTPS(ECC) EXPIRED on cppm-pub-01",
         instance="server:HTTPS(ECC)", rule_id="cert", metric="cert_days_left", value=-270, op="<=", threshold=None, unit=" days",
         level="expired")
    eng.run_batch()
    [a], [t] = alerts(), tickets()
    assert a.severity == "critical" and t.priority == "P1 - Critical"
    assert "Alarm Type     : Security Alert" in Path(t.file_path).read_text()
    poll(nid, "threshold.cert", "info", "renewed", clear=True, instance="server:HTTPS(ECC)")
    eng.run_batch()
    assert alerts()[0].state == "cleared" and tickets()[0].status == "resolved"


def test_manual_resolve_via_web_goes_through_engine(env: dict[str, Any]) -> None:
    from cppmmon.config import get_settings
    from cppmmon.db.models import User
    from cppmmon.web.app import create_app
    from cppmmon.web.auth import hash_password

    nid, eng = env["node_id"], env["engine"]
    poll(nid, "node.reboot", "high", "[CPPM][HIGH] Reboot detected on cppm-pub-01")
    eng.run_batch()
    with session_scope() as s:
        s.add(User(username="op", password_hash=hash_password("pw-1234567890"), role="operator"))
    c = create_app(get_settings(), testing=True).test_client()
    c.post("/login", data={"username": "op", "password": "pw-1234567890"})
    aid = alerts()[0].id
    assert c.post(f"/alerts/{aid}/resolve").status_code == 302
    assert alerts()[0].state == "open"  # the web never writes alerts
    eng.run_batch()
    assert alerts()[0].state == "cleared"
    assert "manually resolved by op" in Path(tickets()[0].file_path).read_text()
    for path in ("/alerts", "/alerts?state=cleared", "/tickets", f"/tickets/{tickets()[0].ticket_no}", "/thresholds"):
        assert c.get(path).status_code == 200, path
    dl = c.get(f"/tickets/{tickets()[0].ticket_no}/download")
    assert dl.status_code == 200 and b"TICKET      :" in dl.data


def test_bulk_resolve_selected_and_all(env: dict[str, Any]) -> None:
    from cppmmon.config import get_settings
    from cppmmon.db.models import User
    from cppmmon.web.app import create_app
    from cppmmon.web.auth import hash_password

    nid, eng = env["node_id"], env["engine"]
    poll(nid, "node.reboot", "high", "reboot")
    poll(nid, "threshold.disk", "medium", "disk", rule_id="disk", metric="disk_pct", value=85, op=">", threshold=80, unit="%", level="warn")
    poll(nid, "node.down", "critical", "down")
    eng.run_batch()
    with session_scope() as s:
        s.add(User(username="op2", password_hash=hash_password("pw-1234567890"), role="operator"))
    c = create_app(get_settings(), testing=True).test_client()
    c.post("/login", data={"username": "op2", "password": "pw-1234567890"})
    html = c.get("/alerts").get_data(as_text=True)
    assert "Resolve selected" in html and "Resolve all shown" in html
    first = next(a for a in alerts() if a.rule_id == "node.reboot")
    c.post("/alerts/resolve", data={"ids": [str(first.id)], "state": "active"})
    eng.run_batch()
    assert {a.rule_id: a.state for a in alerts()}["node.reboot"] == "cleared"
    c.post("/alerts/resolve", data={"all": "1", "state": "active"})
    eng.run_batch()
    eng.run_batch()
    assert all(a.state == "cleared" for a in alerts())
    # children are cleared before the NODE DOWN parent → no promotion, no extra tickets
    assert len(tickets()) == 3


def test_engine_failure_is_isolated(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    nid, eng = env["node_id"], env["engine"]
    trap(nid, **STOP)
    poll(nid, "node.reboot", "high", "reboot")
    calls = {"n": 0}
    real = eng.handle

    def flaky(s, ev, *a):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real(s, ev, *a)

    monkeypatch.setattr(eng, "handle", flaky)
    eng.run_batch()
    with session_scope() as s:
        assert sorted(s.scalars(select(Event.processed))) == [1, 2]
        assert s.scalar(select(func.count()).select_from(Alert)) == 1
