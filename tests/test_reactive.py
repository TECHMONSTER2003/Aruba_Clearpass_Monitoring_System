"""Reactive service health (watchdog + 1017 + REST → one alert), cert scope, Poll now, licenses page."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from cppmmon import services as svc
from cppmmon.catalog import loader
from cppmmon.crypto import encrypt
from cppmmon.db.models import Alert, Event, Node, NodeState, PollRequest, Ticket
from cppmmon.db.session import session_scope, utcnow
from cppmmon.engine.main import Engine
from cppmmon.engine.rules import watchdog_failing
from cppmmon.engine.tickets import FileTicketSink

SEED = Path(__file__).resolve().parents[1] / "catalog" / "cppm_traps.yaml"
B = "1.3.6.1.4.1.14823.1.6.1.1.200"
WD = "1.3.6.1.2.1.88.2.0"


@pytest.fixture()
def env() -> dict[str, Any]:
    from cppmmon.config import get_settings

    with session_scope() as s:
        loader.apply(s, loader.parse(SEED.read_bytes(), SEED.name), seed=True)
        n = Node(name="cppm-sub-02", ip="192.0.2.12", role="subscriber", snmp_community_enc=encrypt("x"))
        s.add(n)
        s.flush()
        s.add(NodeState(node_id=n.id, status="up"))
        nid = n.id
    return {"nid": nid, "eng": Engine(FileTicketSink(get_settings().tickets_dir))}


def _ev(nid: int, source: str, etype: str, sev: str, vb: dict[str, Any], oid: str = "", clear: bool = False,
        inst: str = "", **attrs: Any) -> None:
    a: dict[str, Any] = {"vb": vb, "trap_oid": oid, **attrs}
    with session_scope() as s:
        s.add(Event(ts=utcnow(), node_id=nid, source=source, event_type=etype, severity=sev, is_clear=clear,
                    dedup_instance=inst, attributes=a, processed=0))


def _alerts() -> list[Alert]:
    with session_scope() as s:
        return list(s.scalars(select(Alert).order_by(Alert.id)))


# --------------------------------------------------------- classification

@pytest.mark.parametrize(("vb", "failing"), [
    ({"extOutput": "TACACS+ Server [ cpass-tacacs-server ] is stopped", "mteHotValue": 3}, True),
    ({"extOutput": "Radius server [ cpass-radius-server ] is running", "mteHotValue": 0}, False),
    ({"extOutput": "httpd is inactive (dead)", "mteHotValue": 0}, True),  # arrived as a *Falling* trap in the lab
    ({"extOutput": "cpass-postgresql is active (running) since Tue", "mteHotValue": 0}, False),
    ({"memErrorName": "swap", "memSwapErrorMsg": "", "mteHotValue": 0}, False),
    ({"memErrorName": "swap", "memSwapErrorMsg": "Running out of swap space", "memSwapError": 1}, True),
])
def test_watchdog_classified_by_content(vb: dict[str, Any], failing: bool) -> None:
    assert watchdog_failing(vb) is failing


def test_service_names_canonical_across_signals() -> None:
    assert svc.from_watchdog("TACACS+ Server [ cpass-tacacs-server ] is stopped", "cpass-tacacs-server")[0] == "cpass-tacacs-server"
    assert svc.canonical("cpass-tacacs-server.service") == svc.canonical("cpass-tacacs-server") == "cpass-tacacs-server"
    assert svc.from_watchdog("Domain Server [  cpass-domain-server@EXAMPLE.service ] is running", None)[0] == "cpass-domain-server@example"
    assert svc.is_critical("cpass-policy-server") and svc.is_critical("cpass-dbcn-server") and svc.is_critical("Domain Server")
    assert not svc.is_critical("Micros Fidelio FIAS") and not svc.is_critical("cpass-statsd-server")


# --------------------------------------------- one alert from three signals

def test_trap_watchdog_and_rest_merge_into_one_alert(env: dict[str, Any]) -> None:
    nid, eng = env["nid"], env["eng"]
    # exactly the lab sequence for TACACS on .196 (2026-11-17)
    _ev(nid, "trap", "cppmServiceStopNotification", "high",
        {"cppmServiceName": "cpass-tacacs-server", "cppmTrapMessage": "cpass-tacacs-server service is stopped"}, f"{B}.1017",
        inst="cpass-tacacs-server")
    _ev(nid, "trap", "mteTriggerRising", "medium",
        {"mteHotTrigger": "extTable", "mteHotValue": 3, "extNames": "cpass-tacacs-server",
         "extOutput": "TACACS+ Server [ cpass-tacacs-server ] is stopped"}, f"{WD}.2", inst="cpass-tacacs-server")
    _ev(nid, "poll", "service.down", "high", {}, inst="cpass-tacacs-server", title="[CPPM][HIGH] Service 'TACACS+ server' Stopped")
    eng.run_batch()
    [a] = _alerts()
    assert a.dedup_key.endswith("|service.down|cpass-tacacs-server") and a.occurrences == 3 and a.severity == "high"
    with session_scope() as s:
        assert len(list(s.scalars(select(Ticket)))) == 1
    # watchdog "running" (even as a Rising trap) clears it
    _ev(nid, "trap", "mteTriggerRising", "medium",
        {"mteHotTrigger": "extTable", "mteHotValue": 0, "extNames": "cpass-tacacs-server",
         "extOutput": "TACACS+ Server [ cpass-tacacs-server ] is running"}, f"{WD}.2", inst="cpass-tacacs-server")
    eng.run_batch()
    assert _alerts()[0].state == "cleared"


def test_noncritical_watchdog_is_medium_and_linkdown_is_log_only(env: dict[str, Any]) -> None:
    nid, eng = env["nid"], env["eng"]
    _ev(nid, "trap", "mteTriggerRising", "medium",
        {"mteHotTrigger": "extTable", "mteHotValue": 3, "extNames": "fias-server",
         "extOutput": "Micros Fidelio FIAS [ fias-server ] is stopped"}, f"{WD}.2", inst="fias-server")
    _ev(nid, "trap", "linkDown", "low", {"ifIndex": 4, "ifOperStatus": 2}, "1.3.6.1.6.3.1.1.5.3", inst="4")
    eng.run_batch()
    [a] = _alerts()
    assert a.severity == "medium" and "fias-server" in a.dedup_key


def test_domain_server_watchdog_is_high(env: dict[str, Any]) -> None:
    nid, eng = env["nid"], env["eng"]
    _ev(nid, "trap", "mteTriggerRising", "medium",
        {"mteHotTrigger": "extTable", "mteHotValue": 1, "extNames": "cpass-domain-server@EXAMPLE.service",
         "extOutput": "Domain Server [  cpass-domain-server@EXAMPLE.service ] is stopped"}, f"{WD}.2")
    eng.run_batch()
    [a] = _alerts()
    assert a.severity == "high" and a.dedup_key.endswith("cpass-domain-server@example")


# ------------------------------------------------------------- cert scope

def test_only_radius_and_https_rsa_certs_are_polled(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import timedelta

    from cppmmon.collectors.types import SnmpParams
    from cppmmon.poller import jobs
    from cppmmon.poller.thresholds import Evaluator, seed_rules

    seed_rules()
    ev = Evaluator()
    ev.load()
    now = utcnow()

    async def fake_call(rt, ctx, res, now_, key, fn):  # type: ignore[no-untyped-def]
        if key == "server-cert":
            return [{"service": s, "cert_type": "server", "subject": "CN=x", "issuer": "CN=y",
                     "valid_to": now + timedelta(days=d)} for s, d in
                    (("RADIUS", 115), ("HTTPS(ECC)", -270), ("HTTPS(RSA)", 145), ("RadSec", 1660), ("Database", 206))]
        return None

    monkeypatch.setattr(jobs, "_api_call", fake_call)
    rt = jobs.NodeRT(1, "n1", "10.0.0.5", SnmpParams(host="10.0.0.5", community="x"), None)
    ctx = jobs.Ctx(counters={}, evaluator=ev, snmp_sem=asyncio.Semaphore(1), api_sem=asyncio.Semaphore(1))
    res = asyncio.run(jobs.job_rest_certs_licenses(rt, ctx))
    assert sorted(c["service"] for c in res.certs) == ["HTTPS(RSA)", "RADIUS"]
    assert not res.events  # the expired ECC cert is out of scope → no alert


# --------------------------------------------------------- poll now + UI

def test_poll_now_requests_and_pages() -> None:
    from cppmmon.config import get_settings
    from cppmmon.db.models import License, User
    from cppmmon.web.app import create_app
    from cppmmon.web.auth import hash_password

    with session_scope() as s:
        s.add(User(username="opx", password_hash=hash_password("pw-1234567890"), role="operator"))
        n = Node(name="pub", ip="10.0.0.9", snmp_community_enc=encrypt("x"), api_enabled=True, api_client_id="c")
        s.add(n)
        s.flush()
        s.add(NodeState(node_id=n.id, status="up"))
        s.add(License(node_id=n.id, app_name="Onboard", total=25, used=3, license_type="Permanent", activated=True, ts=utcnow()))
        nid = n.id
    c = create_app(get_settings(), testing=True).test_client()
    c.post("/login", data={"username": "opx", "password": "pw-1234567890"})
    assert "Poll all now" in c.get("/").get_data(as_text=True)
    assert "Poll now" in c.get("/nodes/").get_data(as_text=True)
    c.post("/poll")
    c.post("/poll")  # duplicate while pending → ignored
    c.post(f"/nodes/{nid}/poll", data={"next": "/nodes/"})
    with session_scope() as s:
        reqs = [r.node_id for r in s.scalars(select(PollRequest))]
    assert reqs == [None, nid]
    html = c.get("/licenses").get_data(as_text=True)
    assert "Onboard" in html and "Permanent" in html and "3 / 25" in html
    assert "Onboard" in c.get(f"/nodes/{nid}/overview").get_data(as_text=True)


def test_poller_wakes_jobs_on_request() -> None:
    from cppmmon.collectors.types import SnmpParams
    from cppmmon.poller.jobs import JOBS, Ctx, NodeRT
    from cppmmon.poller.main import Poller
    from cppmmon.poller.thresholds import Evaluator

    async def go() -> bool:
        p = Poller(Ctx(counters={}, evaluator=Evaluator(), snmp_sem=asyncio.Semaphore(1), api_sem=asyncio.Semaphore(1)))
        p.nodes[7] = NodeRT(7, "n", "10.0.0.7", SnmpParams(host="10.0.0.7", community="x"), None)
        sleeper = asyncio.create_task(p._sleep(7, JOBS[-1], 3600))  # a 6-hour job asleep
        await asyncio.sleep(0)
        assert p.poll_now(None) == 1
        await asyncio.wait_for(sleeper, 1)  # woke immediately
        return True

    assert asyncio.run(go())
