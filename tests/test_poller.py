"""Phase 3: delta/reset/wrap logic, CPU ticks, threshold state machine, node status, dashboard rendering."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from cppmmon.collectors.types import SnmpParams
from cppmmon.poller.deltas import WRAP32, counter_delta, cpu_percent
from cppmmon.poller.jobs import NodeRT, update_status
from cppmmon.poller.store import JobResult
from cppmmon.poller.thresholds import Evaluator, seed_rules

T0 = datetime(2026, 11, 17, 10, 0, 0)


# ------------------------------------------------------------------ deltas

def test_first_sample_has_no_delta() -> None:
    assert counter_delta(None, None, 100, T0).value is None


def test_daily_counter_midnight_reset_uses_new_value() -> None:
    d = counter_delta(5000, T0, 12, T0 + timedelta(minutes=1), "reset")
    assert d.reset and d.value == 12 and d.per_minute() == 12


def test_wrap32_and_reboot_is_not_a_wrap() -> None:
    d = counter_delta(WRAP32 - 100, T0, 50, T0 + timedelta(seconds=60), "wrap32")
    assert d.wrapped and d.value == 150
    r = counter_delta(WRAP32 - 100, T0, 50, T0 + timedelta(seconds=60), "wrap32", rebooted=True)
    assert r.reset and r.value == 50


def test_cpu_percent_from_ticks() -> None:
    prev = {"user": 1000, "nice": 0, "system": 500, "idle": 8500, "wait": None}
    cur = {"user": 1100, "nice": 0, "system": 550, "idle": 8850, "wait": None}
    assert cpu_percent(prev, cur) == pytest.approx(30.0)  # 150 busy of 500 ticks
    assert cpu_percent(prev, prev) is None


# -------------------------------------------------------------- thresholds

@pytest.fixture()
def ev() -> Evaluator:
    seed_rules()
    e = Evaluator()
    e.load()
    return e


def test_sustain_window_then_open(ev: Evaluator) -> None:
    assert ev.evaluate(1, "n1", "cpu_pct", "", 90, T0) == []  # breach starts, sustain 300 s
    assert ev.evaluate(1, "n1", "cpu_pct", "", 91, T0 + timedelta(seconds=240)) == []
    out = ev.evaluate(1, "n1", "cpu_pct", "", 92, T0 + timedelta(seconds=300))
    assert len(out) == 1 and out[0]["severity"] == "medium" and out[0]["event_type"] == "threshold.cpu"
    assert ev.evaluate(1, "n1", "cpu_pct", "", 92, T0 + timedelta(seconds=360)) == []  # no repeat while open


def test_escalation_and_hysteresis_clear(ev: Evaluator) -> None:
    ev.evaluate(1, "n1", "cpu_pct", "", 90, T0)
    ev.evaluate(1, "n1", "cpu_pct", "", 90, T0 + timedelta(seconds=300))
    up = ev.evaluate(1, "n1", "cpu_pct", "", 97, T0 + timedelta(seconds=360))
    assert up and up[0]["severity"] == "high"  # escalation warn → crit (sustain already met)
    assert ev.evaluate(1, "n1", "cpu_pct", "", 80, T0 + timedelta(seconds=420)) == []  # between clear (75) and warn: hold
    clr = ev.evaluate(1, "n1", "cpu_pct", "", 60, T0 + timedelta(seconds=480))
    assert len(clr) == 1 and clr[0]["is_clear"]


def test_breach_interrupted_resets_sustain(ev: Evaluator) -> None:
    ev.evaluate(1, "n1", "mem_pct", "", 90, T0)
    ev.evaluate(1, "n1", "mem_pct", "", 50, T0 + timedelta(seconds=200))
    assert ev.evaluate(1, "n1", "mem_pct", "", 90, T0 + timedelta(seconds=310)) == []


def test_cert_expired_is_critical_and_per_instance(ev: Evaluator) -> None:
    out = ev.evaluate(1, "n1", "cert_days_left", "server:HTTPS(ECC)", -270, T0)
    assert out[0]["severity"] == "critical" and "EXPIRED" in out[0]["attributes"]["title"]
    assert ev.evaluate(1, "n1", "cert_days_left", "server:RADIUS", 115, T0) == []
    soon = ev.evaluate(1, "n1", "cert_days_left", "server:RadSec", 5, T0)
    assert soon[0]["severity"] == "high"


# ------------------------------------------------------------------ status

def _rt() -> NodeRT:
    return NodeRT(1, "n1", "10.0.0.5", SnmpParams(host="10.0.0.5", community="x"), None, status="up")


def test_new_node_is_not_up_before_first_snmp_success() -> None:
    rt, res = _rt(), JobResult()
    rt.status = "unknown"
    rt.icmp_fail = 1  # ICMP job ran first and failed; SNMP has not run yet
    update_status(rt, res, T0)
    assert rt.status == "unknown"
    rt.snmp_ok = True
    update_status(rt, res, T0)
    assert rt.status == "up"


def test_node_down_needs_icmp_and_snmp_three_cycles() -> None:
    rt, res = _rt(), JobResult()
    rt.snmp_ok = False
    rt.icmp_fail, rt.snmp_fail = 3, 2
    update_status(rt, res, T0)
    assert rt.status == "up" and not res.events
    rt.snmp_fail = 3
    update_status(rt, res, T0)
    assert rt.status == "down" and res.events[-1]["event_type"] == "node.down" and res.events[-1]["severity"] == "critical"
    rt.icmp_fail = rt.snmp_fail = 0
    rt.snmp_ok = True
    update_status(rt, res, T0)
    assert rt.status == "up" and res.events[-1]["is_clear"]


def test_icmp_ok_snmp_and_api_failing_is_degraded() -> None:
    rt, res = _rt(), JobResult()
    rt.snmp_fail = 3  # api is None → counts as failing
    update_status(rt, res, T0)
    assert rt.status == "degraded" and res.events[-1]["event_type"] == "node.degraded"


# ---------------------------------------------------------- dashboard pages

def test_dashboard_and_overview_render(monkeypatch: pytest.MonkeyPatch) -> None:
    from cppmmon.config import get_settings
    from cppmmon.crypto import encrypt
    from cppmmon.db.models import Certificate, Metric, Node, NodeState, ServiceStatus, User
    from cppmmon.db.session import session_scope, utcnow
    from cppmmon.web.app import create_app
    from cppmmon.web.auth import hash_password

    now = utcnow()
    with session_scope() as s:
        s.add(User(username="v", password_hash=hash_password("pw-1234567890"), role="viewer"))
        n = Node(name="cppm-pub", ip="10.0.0.5", role="publisher", snmp_community_enc=encrypt("x"), api_enabled=True)
        s.add(n)
        s.flush()
        s.add(NodeState(node_id=n.id, status="up", version="6.14.1.372486", uptime_s=1191397))
        for i, (m, v) in enumerate([("cpu_pct", 12.6),("mem_pct", 91.0), ("disk_pct", 46.0), ("auth_success_pct_today", 100.0)]):
            s.add(Metric(node_id=n.id, ts=now - timedelta(seconds=30 + i), metric=m, value=v, instance=""))
        s.add(ServiceStatus(node_id=n.id, service_name="Radius server", status="Running", raw={}, ts=now))
        s.add(ServiceStatus(node_id=n.id, service_name="TACACS+ server", status="Stopped", raw={}, ts=now))
        s.add(Certificate(node_id=n.id, cert_type="server", service="HTTPS(ECC)", subject="CN=x", issuer="CN=y",
                          valid_to=now - timedelta(days=270), days_left=-270, ts=now))
        nid = n.id
    c = create_app(get_settings(), testing=True).test_client()
    c.post("/login", data={"username": "v", "password": "pw-1234567890"})
    html = c.get("/").get_data(as_text=True)
    assert "cppm-pub" in html and "13%" in html and "91%" in html and "lvl-warn" in html  # mem 91 ≥ warn 85
    assert "cert EXPIRED 270d" in html and "13d 18h" in html
    tiles = c.get("/dashboard/tiles").get_data(as_text=True)
    assert "cppm-pub" in tiles and "<html" not in tiles
    ov = c.get(f"/nodes/{nid}/overview").get_data(as_text=True)
    assert "HTTPS(ECC)" in ov and "Stopped" in ov and "data-chart" in ov
    js = c.get(f"/nodes/{nid}/series.json?chart=res&hours=1").get_json()
    assert set(js["series"]) == {"cpu_pct", "mem_pct", "disk_pct"} and js["unit"] == "%"
    assert c.get(f"/nodes/{nid}/series.json?chart=bogus").status_code == 400
