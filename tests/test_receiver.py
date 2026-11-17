"""Phase 2: trap decode, syslog framing/envelope, persistence + idempotent spool replay, catalog loader."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from pyasn1.codec.ber import encoder
from pysnmp.proto import api
from sqlalchemy import func, select

from cppmmon.catalog import loader
from cppmmon.db.models import Event, Node, NodeState, RawSyslog, RawTrap, TrapCatalog
from cppmmon.db.session import session_scope
from cppmmon.receiver.decode import decode_trap
from cppmmon.receiver.directory import load_snapshot
from cppmmon.receiver.framing import SyslogFramer
from cppmmon.receiver.persist import persist_batch, record_hash
from cppmmon.receiver.spool import Spool
from cppmmon.receiver.syslog_parsers import parse_envelope

SEED = Path(__file__).resolve().parents[1] / "catalog" / "cppm_traps.yaml"
B = "1.3.6.1.4.1.14823.1.6.1.1.200"


def _v2c_trap(community: str, trap_oid: str, vbs: list[tuple[str, object]]) -> bytes:
    p = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
    pdu = p.SNMPv2TrapPDU()
    p.apiTrapPDU.set_defaults(pdu)
    binds = [(p.ObjectIdentifier("1.3.6.1.2.1.1.3.0"), p.TimeTicks(12345)),
             (p.ObjectIdentifier("1.3.6.1.6.3.1.1.4.1.0"), p.ObjectIdentifier(trap_oid))]
    for oid, val in vbs:
        binds.append((p.ObjectIdentifier(oid), p.OctetString(val) if isinstance(val, str) else p.Integer(val)))
    p.apiTrapPDU.set_varbinds(pdu, binds)
    msg = p.Message()
    p.apiMessage.set_defaults(msg)
    p.apiMessage.set_community(msg, community)
    p.apiMessage.set_pdu(msg, pdu)
    return encoder.encode(msg)


def _v1_trap(generic: int, specific: int) -> bytes:
    p = api.PROTOCOL_MODULES[api.SNMP_VERSION_1]
    pdu = p.TrapPDU()
    p.apiTrapPDU.set_defaults(pdu)
    p.apiTrapPDU.set_enterprise(pdu, (1, 3, 6, 1, 4, 1, 14823, 1, 6, 1, 1, 200))
    p.apiTrapPDU.set_generic_trap(pdu, generic)
    p.apiTrapPDU.set_specific_trap(pdu, specific)
    msg = p.Message()
    p.apiMessage.set_defaults(msg)
    p.apiMessage.set_community(msg, "c1")
    p.apiMessage.set_pdu(msg, pdu)
    return encoder.encode(msg)


# ------------------------------------------------------------------ decode

def test_decode_v2c_trap() -> None:
    d = decode_trap(_v2c_trap("trapcomm", f"{B}.1017", [(f"{B}.100.17", "Radius server")]))
    assert d.version == "2c" and d.community == "trapcomm" and d.trap_oid == f"{B}.1017"
    assert d.uptime_ticks == 12345 and d.varbinds == [(f"{B}.100.17", "Radius server")]


def test_decode_v1_trap_rfc3584_mapping() -> None:
    assert decode_trap(_v1_trap(6, 1022)).trap_oid == f"{B}.0.1022"
    assert decode_trap(_v1_trap(0, 0)).trap_oid == "1.3.6.1.6.3.1.1.5.1"  # coldStart


def test_decode_garbage_raises() -> None:
    from cppmmon.receiver.decode import TrapDecodeError

    with pytest.raises(TrapDecodeError):
        decode_trap(b"\x30\x03not-snmp")


# ----------------------------------------------------------------- framing

def test_framing_lf_and_octet_count_across_feeds() -> None:
    f = SyslogFramer(1024)
    assert f.feed(b"<13>hello\n<13>wor") == [(b"<13>hello", False)]
    assert f.feed(b"ld\n11 <13>abcdef") == [(b"<13>world", False)]  # 10 of 11 bytes: wait
    assert f.feed(b"g") == [(b"<13>abcdefg", False)]


def test_framing_truncates_oversized() -> None:
    f = SyslogFramer(10)
    out = f.feed(b"0123456789ABCDEF\nnext\n")
    assert out[0] == (b"0123456789", True) and out[1] == (b"next", False)
    f2 = SyslogFramer(10)
    out2 = f2.feed(b"16 0123456789ABCDEF5 short")
    assert out2[0] == (b"0123456789", True) and out2[1] == (b"short", False)


# ---------------------------------------------------------------- envelope

def test_envelope_rfc5424_with_cef() -> None:
    e = parse_envelope("<134>1 2026-11-17T14:00:00+05:30 cppm1 CPPM_SIM - - - CEF:0|Aruba Networks|ClearPass|6.14|x|y|5|msg=a")
    assert (e.fmt, e.facility, e.severity, e.host, e.app) == ("cef", 16, 6, "cppm1", "CPPM_SIM")
    assert e.body.startswith("CEF:0|")


def test_envelope_cppm_iso_bsd_header() -> None:
    """Real shape from lab CPPM 6.14.1 (2026-11-17)."""
    e = parse_envelope("<142>2026-11-17T13:39:44+05:30 192.0.2.10 cppm.async-netd[3576615]: 2026/11/17 13:39:44 WARN Skipping Ingress Events")
    assert (e.fmt, e.facility, e.severity, e.host, e.app) == ("rfc3164", 17, 6, "192.0.2.10", "cppm.async-netd")
    assert e.body.endswith("WARN Skipping Ingress Events") and e.device_ts == "2026-11-17T13:39:44+05:30"


def test_redaction_of_leaked_credentials() -> None:
    from cppmmon.receiver.redact import redact

    shapes = [  # shapes seen from CPPM 6.14 async-netd DEBUG (values here are fake)
        ("<142>2026-11-17T15:07:15+05:30 10.0.0.5 cppm.async-netd[1]:  community=FAKEcomm123", "community=***"),
        ("... recovered community <OctetString value object, encoding iso-8859-1, payload [FAKEcomm123]>", "payload [***]"),
        ("securityName candidates for communityName 'FAKEcomm123' are", "communityName '***"),
        ("bind_password: hunter2 user=x", "bind_password: ***"),
    ]
    for raw, expect in shapes:
        out, masked = redact(raw)
        assert masked and "FAKEcomm123" not in out and "hunter2" not in out and expect in out, out
    assert redact("plain message without secrets") == ("plain message without secrets", False)


def test_repeat_suppression() -> None:
    from cppmmon.receiver.suppress import RepeatSuppressor

    sup = RepeatSuppressor(60)
    line = "<142>2026-11-17T13:39:{s:02d}+05:30 10.0.0.5 cppm.async-netd[3576615]: 2026/11/17 13:39:{s:02d} WARN Skipping Ingress Events"
    assert sup.admit("10.0.0.5", "udp", line.format(s=1), now=0) == (True, None)
    for i in range(2, 40):
        assert sup.admit("10.0.0.5", "udp", line.format(s=i), now=i)[0] is False
    assert sup.admit("10.0.0.5", "udp", "<142>2026-11-17T13:39:50+05:30 10.0.0.5 other: different", now=41)[0] is True
    assert sup.admit("10.0.0.6", "udp", line.format(s=3), now=42)[0] is True  # other source: not suppressed
    store, summary = sup.admit("10.0.0.5", "udp", line.format(s=5), now=61)  # window over
    assert store and summary["count"] == 38
    # a key that repeated zero times must never produce a "0 repeat(s)" summary row
    assert sup.admit("10.0.0.6", "udp", line.format(s=9), now=200) == (True, None)
    assert sup.expire(now=500) == []  # nothing else repeated


def test_envelope_rfc3164_and_raw() -> None:
    e = parse_envelope("<12>Nov 17 14:00:00 cppm1 CPPM_SIM: plain text")
    assert (e.fmt, e.host, e.app, e.body) == ("rfc3164", "cppm1", "CPPM_SIM", "plain text")
    assert parse_envelope("no header at all").fmt == "raw"


# ------------------------------------------------------------- persistence

@pytest.fixture()
def seeded() -> dict:
    from cppmmon.crypto import encrypt

    with session_scope() as s:
        loader.apply(s, loader.parse(SEED.read_bytes(), SEED.name), seed=True)
        n = Node(name="cppm-lab", ip="10.0.0.5", trap_community_enc=encrypt("trapcomm"), snmp_community_enc=encrypt("x"))
        s.add(n)
        s.flush()
        s.add(NodeState(node_id=n.id))
        nid = n.id
    return {"node_id": nid, "snap": load_snapshot()}


def _rec(src: str, oid: str, vbs: list, ok: bool = True, ts: str = "2026-11-17T08:00:00.000") -> dict:
    return {"kind": "trap", "received_at": datetime.fromisoformat(ts), "src_ip": src, "version": "2c", "community_ok": ok,
            "trap_oid": oid, "varbinds": vbs, "uptime_ticks": 1, "agent_addr": None,
            "dedup_hash": record_hash(src, ts, oid + repr(vbs))}


def test_persist_events_and_classification(seeded: dict) -> None:
    snap = seeded["snap"]
    assert "trapcomm" in snap.communities and f"{B}.1018" in snap.clears
    batch = [
        _rec("10.0.0.5", f"{B}.1017", [(f"{B}.100.17", "Radius server")]),                        # known → event
        _rec("10.0.0.5", f"{B}.9999", [], ts="2026-11-17T08:00:01.000"),                           # unknown → UNKNOWN_TRAP
        _rec("10.0.0.5", f"{B}.1017", [], ok=False, ts="2026-11-17T08:00:02.000"),                  # bad community → no event
        _rec("192.0.2.9", f"{B}.1017", [], ts="2026-11-17T08:00:03.000"),                          # unregistered → no event
        _rec("192.0.2.9", f"{B}.1018", [(f"{B}.100.2", "10.0.0.5"), (f"{B}.100.17", "Radius server")],
             ts="2026-11-17T08:00:04.000"),                                                         # cppmNodeIp fallback + clear
    ]
    res = persist_batch(batch, snap)
    assert res == {"traps": 5, "syslog": 0, "events": 3}
    with session_scope() as s:
        evs = list(s.scalars(select(Event).order_by(Event.id)))
        assert [e.event_type for e in evs] == ["cppmServiceStopNotification", "UNKNOWN_TRAP", "cppmServiceStartNotification"]
        stop, unknown, start = evs
        assert stop.severity == "high" and stop.dedup_instance == "Radius server" and not stop.is_clear
        assert unknown.severity == "info"
        assert start.is_clear and start.attributes["clears"] == "cppmServiceStopNotification"
        assert start.dedup_instance == "Radius server" and start.attributes["resolved_via"] == "cppmNodeIp"
        unreg = s.scalar(select(RawTrap).where(RawTrap.src_ip == "192.0.2.9", RawTrap.trap_oid == f"{B}.1017"))
        assert unreg.node_id is None and unreg.trap_name == "cppmServiceStopNotification"
        assert s.get(NodeState, seeded["node_id"]).last_trap_at is not None


def test_persist_is_idempotent(seeded: dict) -> None:
    batch = [_rec("10.0.0.5", f"{B}.1017", [(f"{B}.100.17", "Radius server")])]
    persist_batch(batch, seeded["snap"])
    again = persist_batch(batch, seeded["snap"])
    assert again["events"] == 0
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(RawTrap)) == 1
        assert s.scalar(select(func.count()).select_from(Event)) == 1


def test_spool_roundtrip(seeded: dict, tmp_path: Path) -> None:
    sp = Spool(tmp_path / "spool")
    batch = [_rec("10.0.0.5", f"{B}.1022", []),
             {"kind": "syslog", "received_at": datetime(2026, 11, 17, 8, 0, 5), "src_ip": "10.0.0.5", "transport": "udp",
              "msg": "<13>1 - h a - - - CEF:0|x", "truncated": False, "dedup_hash": "abc"}]
    sp.append(batch)
    assert sp.backlog()[0] == 1
    assert "trapcomm" not in (tmp_path / "spool").joinpath(sp.files()[0].name).read_text()
    assert sp.replay(lambda recs: persist_batch(recs, seeded["snap"])) == 2
    assert sp.files() == []
    with session_scope() as s:
        assert s.scalar(select(RawSyslog.fmt)) == "cef"
        assert s.scalar(select(func.count()).select_from(Event)) == 1


def test_retention_batches(seeded: dict) -> None:
    from cppmmon.jobs.maintenance import purge

    old = [{**_rec("10.0.0.5", f"{B}.1022", [], ts=f"2026-01-01T00:00:{i:02d}.000")} for i in range(30)]
    persist_batch(old + [_rec("10.0.0.5", f"{B}.1022", [], ts="2026-11-17T09:00:00.000")], seeded["snap"])
    assert purge(RawTrap, RawTrap.received_at, datetime(2026, 6, 1)) == 30
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(RawTrap)) == 1
        # unprocessed events are never purged
        assert purge(Event, Event.ts, datetime(2026, 6, 1), Event.processed == 1) == 0


# ------------------------------------------------------------------ loader

def test_loader_seed_and_csv() -> None:
    pc = loader.parse(SEED.read_bytes(), SEED.name)
    assert len(pc.traps) >= 22 and not pc.errors
    assert pc.traps[f"{B}.1017"]["clear_oid"] == f"{B}.1018,{B}.1019"
    with session_scope() as s:
        loader.apply(s, pc, seed=True)
    csv = (f"oid,name,severity,create_ticket\n{B}.1017,cppmServiceStopNotification,critical,yes\n"
           f"{B}.2000,customTrap,low,no\nbad-oid,x,info,no\n").encode()
    up = loader.parse(csv, "db.csv")
    assert len(up.errors) == 1
    with session_scope() as s:
        d = loader.diff(s, up)
        assert [a["oid"] for a in d.added] == [f"{B}.2000"]
        assert d.changed[0]["fields"]["severity"] == ("high", "critical")
        assert len(d.untouched) >= 21  # seed entries not in the CSV are kept, never deleted
        loader.apply(s, up, seed=True)  # seed mode must not overwrite
    with session_scope() as s:
        assert s.get(TrapCatalog, f"{B}.1017").severity == "high"
        loader.apply(s, up)
    with session_scope() as s:
        t = s.get(TrapCatalog, f"{B}.1017")
        assert t.severity == "critical"
        assert t.clear_oid == f"{B}.1018,{B}.1019" and t.title_tpl  # columns absent from the CSV are preserved
