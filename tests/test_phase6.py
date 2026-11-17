"""Phase 6: rollups + metric retention, monitor disk self-check, Health page, adaptive service re-check."""
from __future__ import annotations

from collections import namedtuple
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from cppmmon.db.models import Alert, Event, Metric, Metric5m
from cppmmon.db.session import session_scope, utcnow
from cppmmon.jobs import maintenance as mt


def _metrics(start: datetime, minutes: int, value: float = 10.0) -> None:
    with session_scope() as s:
        for i in range(minutes):
            s.add(Metric(node_id=1, ts=start + timedelta(minutes=i), metric="cpu_pct", value=value + i % 5, instance=""))


def test_rollup_buckets_avg_min_max_and_watermark() -> None:
    start = datetime(2026, 11, 17, 8, 0)
    _metrics(start, 30)  # 08:00–08:29 → six 5-min buckets
    n = mt.rollup(now=datetime(2026, 11, 17, 9, 0))
    assert n == 6
    with session_scope() as s:
        b = s.get(Metric5m, (1, "cpu_pct", "", start))
        assert (b.min, b.max, b.avg) == (10.0, 14.0, 12.0)
    assert mt.rollup(now=datetime(2026, 11, 17, 9, 0)) == 0  # watermark: nothing re-rolled


def test_raw_metrics_purged_only_after_rollup(monkeypatch: pytest.MonkeyPatch) -> None:
    now = utcnow()
    old = mt._bucket(now - timedelta(days=9))  # aligned → 10 minutes = exactly 2 buckets
    _metrics(old, 10)
    assert mt.run_retention()["metrics"] == 0  # not rolled up yet → kept
    mt.rollup(now=old + timedelta(hours=1))
    assert mt.run_retention()["metrics"] == 10
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Metric5m)) == 2


def test_disk_check_opens_and_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    DU = namedtuple("DU", "total used free")
    monkeypatch.setattr(mt.shutil, "disk_usage", lambda p: DU(100, 90, 10))
    out = mt.disk_check("/x")
    assert out["disk_used_pct"] == 90.0
    with session_scope() as s:
        ev = s.scalar(select(Event).where(Event.event_type == "monitor.disk_low"))
        assert ev.severity == "medium" and not ev.is_clear and "90%" in ev.attributes["title"]
        s.add(Alert(dedup_key="None|monitor.disk_low|", open_marker=1, rule_id="monitor.disk_low", severity="medium",
                    state="open", title="disk", first_seen=utcnow(), last_seen=utcnow()))
    mt.disk_check("/x")  # still high, alert open → no duplicate event
    monkeypatch.setattr(mt.shutil, "disk_usage", lambda p: DU(100, 70, 30))
    mt.disk_check("/x")
    with session_scope() as s:
        evs = list(s.scalars(select(Event).where(Event.event_type == "monitor.disk_low").order_by(Event.id)))
        assert [e.is_clear for e in evs] == [False, True]


def test_health_page_renders_all_sections() -> None:
    from cppmmon.config import get_settings
    from cppmmon.db.models import ServiceHeartbeat, User
    from cppmmon.web.app import create_app
    from cppmmon.web.auth import hash_password

    with session_scope() as s:
        s.add(User(username="hv", password_hash=hash_password("pw-1234567890"), role="viewer"))
        s.add(ServiceHeartbeat(service="poller", pid=1, started_at=utcnow(), last_beat=utcnow(),
                               stats={"nodes": 3, "poll_now_served": 2, "jobs": {"icmp": {"runs": 5, "failures": 1, "last_ms": 3.2,
                                                                                         "max_ms": 9.9, "last_at": "2026-11-17T10:00:00", "last_error": "timeout"}}}))
        s.add(ServiceHeartbeat(service="receiver", pid=2, started_at=utcnow(), last_beat=utcnow(),
                               stats={"trap_pkts": 7, "syslog_redacted": 4, "spool_files": 0, "db_ok": True}))
    c = create_app(get_settings(), testing=True).test_client()
    c.post("/login", data={"username": "hv", "password": "pw-1234567890"})
    html = c.get("/health").get_data(as_text=True)
    for txt in ("Engine lag", "Spool backlog", "Monitor disk used", "Poller jobs", "Credentials masked", "Latest backup", "timeout"):
        assert txt in html, txt
    assert c.get("/health/body").status_code == 200


def test_fast_service_recheck_while_service_alert_open() -> None:
    from cppmmon.poller.main import _has_open_service_alert

    assert _has_open_service_alert(8) is False
    with session_scope() as s:
        s.add(Alert(dedup_key="8|service.down|cpass-tacacs-server", open_marker=1, node_id=8, rule_id="service.down",
                    severity="high", state="open", title="t", first_seen=utcnow(), last_seen=utcnow()))
    assert _has_open_service_alert(8) is True
