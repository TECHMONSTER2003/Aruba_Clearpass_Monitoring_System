"""Batch persistence for received traps/syslog: raw rows + outbox events in one transaction.

Idempotent by ``dedup_hash`` (sha1 of src|ts|payload) so spool replays can be
repeated safely: rows that already exist are skipped and get no second event.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import insert, select, update

from cppmmon.db.models import Event, NodeState, RawSyslog, RawTrap
from cppmmon.db.session import session_scope
from cppmmon.receiver.directory import Snapshot
from cppmmon.receiver.syslog_parsers import parse_envelope

log = logging.getLogger(__name__)

CPPM_NODE_IP_VB = "cppmNodeIp"
UNKNOWN_TRAP = "UNKNOWN_TRAP"


def record_hash(src: str, ts: str, payload: str) -> str:
    """Idempotency key for one received packet/message."""
    return hashlib.sha1(f"{src}|{ts}|{payload}".encode("utf-8", errors="replace")).hexdigest()


def _ts(value: Any) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def _insert_ignore(model: Any) -> Any:
    return insert(model).prefix_with("IGNORE", dialect="mysql").prefix_with("OR IGNORE", dialect="sqlite")


def enrich_trap(r: dict[str, Any], snap: Snapshot) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Turn a received trap record into (raw_traps row, event row or None)."""
    vb_list = [{"oid": o, "name": snap.varbind_name(o), "value": v} for o, v in r["varbinds"]]
    vb = {x["name"]: x["value"] for x in vb_list}
    node_id = snap.by_ip.get(r["src_ip"])
    via = "src_ip"
    if node_id is None and isinstance(vb.get(CPPM_NODE_IP_VB), str):
        node_id = snap.by_ip.get(vb[CPPM_NODE_IP_VB].strip())
        via = CPPM_NODE_IP_VB if node_id else "unregistered"
    elif node_id is None:
        via = "unregistered"
    community_ok = bool(r["community_ok"])  # evaluated at receive time; the community itself is never stored
    oid = r.get("trap_oid") or ""
    tdef = snap.traps.get(oid)
    raw = {
        "received_at": _ts(r["received_at"]),
        "src_ip": r["src_ip"],
        "node_id": node_id,
        "snmp_version": r["version"],
        "community_ok": community_ok,
        "trap_oid": oid or None,
        "trap_name": tdef.name if tdef else None,
        "varbinds": {"list": vb_list, "uptime_ticks": r.get("uptime_ticks"), "agent_addr": r.get("agent_addr"), "resolved_via": via},
        "dedup_hash": r["dedup_hash"],
    }
    # No events for bad community or unregistered senders (stored for troubleshooting only).
    if not community_ok or node_id is None:
        return raw, None
    attrs: dict[str, Any] = {"trap_oid": oid, "vb": vb, "src_ip": r["src_ip"], "resolved_via": via}
    is_clear = False
    if oid in snap.clears:
        parent = snap.clears[oid]
        is_clear = True
        attrs["clears"] = parent.name
        instance = str(vb.get(parent.clear_match_field or "", "") or "")
    else:
        instance = str(vb.get(tdef.dedup_field, "") or "") if tdef and tdef.dedup_field else ""
    event = {
        "ts": raw["received_at"],
        "node_id": node_id,
        "source": "trap",
        "event_type": tdef.name if tdef else UNKNOWN_TRAP,
        "severity": tdef.severity if tdef else "info",
        "is_clear": is_clear,
        "dedup_instance": instance[:128],
        "attributes": attrs,
        "processed": 0,
    }
    return raw, event


def enrich_syslog(r: dict[str, Any], snap: Snapshot) -> dict[str, Any]:
    """Turn a received syslog record into a raw_syslog row (header parse only in Phase 2)."""
    msg = r["msg"]
    # Repeat-summary rows embed the original line; take host/app/format from that sample.
    sample = msg.split(": ", 1)[1] if msg.startswith("[cppmmon]") and ": " in msg else msg
    env = parse_envelope(sample)
    parsed = env.parsed() or {}
    if r.get("suppressed_repeats"):
        parsed["suppressed_repeats"] = r["suppressed_repeats"]
    return {
        "received_at": _ts(r["received_at"]),
        "src_ip": r["src_ip"],
        "node_id": snap.by_ip.get(r["src_ip"]),
        "transport": r["transport"],
        "facility": env.facility,
        "severity": env.severity,
        "host": (env.host or "")[:255] or None,
        "app": (env.app or "")[:128] or None,
        "msg": r["msg"],
        "truncated": bool(r.get("truncated")),
        "fmt": env.fmt,
        "parsed": parsed or None,
        "dedup_hash": r["dedup_hash"],
    }


def persist_batch(records: list[dict[str, Any]], snap: Snapshot) -> dict[str, int]:
    """Write one batch in a single transaction. Raises SQLAlchemyError on DB failure (caller spools)."""
    traps = [enrich_trap(r, snap) for r in records if r["kind"] == "trap"]
    logs = [enrich_syslog(r, snap) for r in records if r["kind"] == "syslog"]
    n_events = 0
    with session_scope() as s:
        last_trap: dict[int, datetime] = {}
        last_log: dict[int, datetime] = {}
        if traps:
            s.execute(_insert_ignore(RawTrap), [raw for raw, _ev in traps])
            hashes = [raw["dedup_hash"] for raw, _ev in traps]
            ids = dict(s.execute(select(RawTrap.dedup_hash, RawTrap.id).where(RawTrap.dedup_hash.in_(hashes))).all())
            refs = [f"trap:{ids[h]}" for h in hashes if h in ids]
            already = set(s.scalars(select(Event.raw_ref).where(Event.raw_ref.in_(refs)))) if refs else set()
            events = []
            for raw, ev in traps:
                if raw["node_id"] is not None:
                    last_trap[raw["node_id"]] = max(raw["received_at"], last_trap.get(raw["node_id"], raw["received_at"]))
                rid = ids.get(raw["dedup_hash"])
                if ev is not None and rid is not None and f"trap:{rid}" not in already:
                    events.append({**ev, "raw_ref": f"trap:{rid}"})
            if events:
                s.execute(insert(Event), events)
                n_events = len(events)
        if logs:
            s.execute(_insert_ignore(RawSyslog), logs)
            for row in logs:
                if row["node_id"] is not None:
                    last_log[row["node_id"]] = max(row["received_at"], last_log.get(row["node_id"], row["received_at"]))
        for nid, ts in last_trap.items():
            s.execute(update(NodeState).where(NodeState.node_id == nid).values(last_trap_at=ts))
        for nid, ts in last_log.items():
            s.execute(update(NodeState).where(NodeState.node_id == nid).values(last_syslog_at=ts))
    return {"traps": len(traps), "syslog": len(logs), "events": n_events}


def to_json_line(record: dict[str, Any]) -> str:
    """Spool serialisation (datetimes → ISO strings)."""
    return json.dumps({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in record.items()}, default=str)
