"""In-memory caches the receiver needs per packet: node lookup, trap communities, catalog.

Refreshed periodically from the DB in a worker thread; on DB failure the last
good snapshot is kept so ingest never stops.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from cppmmon.crypto import CryptoError, decrypt
from cppmmon.db.models import Node, TrapCatalog, VarbindCatalog
from cppmmon.db.session import session_scope

log = logging.getLogger(__name__)

# Standard varbind names always known, regardless of the imported catalog.
BUILTIN_VARBINDS = {
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.6.3.1.1.4.1": "snmpTrapOID",
    "1.3.6.1.6.3.18.1.3": "snmpTrapAddress",
    "1.3.6.1.6.3.18.1.4": "snmpTrapCommunity",
    "1.3.6.1.6.3.1.1.4.3": "snmpTrapEnterprise",
}


@dataclass
class TrapDef:
    oid: str
    name: str
    severity: str
    create_ticket: bool
    dedup_field: str | None
    clear_match_field: str | None


@dataclass
class Snapshot:
    """Immutable-by-convention view used by the writer thread."""

    by_ip: dict[str, int] = field(default_factory=dict)
    names: dict[int, str] = field(default_factory=dict)
    communities: frozenset[str] = frozenset()
    traps: dict[str, TrapDef] = field(default_factory=dict)
    clears: dict[str, TrapDef] = field(default_factory=dict)  # clearing OID → the trap it clears
    varbinds: list[tuple[str, str]] = field(default_factory=list)  # (prefix, name), longest prefix first

    def varbind_name(self, oid: str) -> str:
        """Longest catalog prefix match → base object name (instance index dropped; the full OID
        stays in the varbind list). Table columns such as extNames.14 become ``extNames`` so rules
        can use them as dedup fields. Unknown OIDs keep their numeric form."""
        for prefix, name in self.varbinds:
            if oid == prefix or oid.startswith(prefix + "."):
                return name
        return oid


def load_snapshot() -> Snapshot:
    """Read nodes + catalog from the DB (blocking; call via ``asyncio.to_thread``)."""
    snap = Snapshot()
    comms: set[str] = set()
    with session_scope() as s:
        # All nodes, including polling-paused ones: their traps/syslog are still matched.
        for n in s.scalars(select(Node)):
            snap.by_ip[n.ip] = n.id
            snap.names[n.id] = n.name
            try:
                c = decrypt(n.trap_community_enc)
            except CryptoError:
                log.error("trap community decrypt failed", extra={"node_id": n.id})
                c = None
            if c:
                comms.add(c)
        for t in s.scalars(select(TrapCatalog)):
            d = TrapDef(t.oid, t.name, t.severity, bool(t.create_ticket), t.dedup_field, t.clear_match_field)
            snap.traps[t.oid] = d
        for t in s.scalars(select(TrapCatalog).where(TrapCatalog.clear_oid.is_not(None))):
            for c_oid in (t.clear_oid or "").split(","):
                if c_oid:
                    snap.clears[c_oid] = snap.traps[t.oid]
        vbs: dict[str, str] = dict(BUILTIN_VARBINDS)
        vbs.update({v.oid_prefix: v.name for v in s.scalars(select(VarbindCatalog))})
    snap.communities = frozenset(comms)
    snap.varbinds = sorted(vbs.items(), key=lambda kv: len(kv[0]), reverse=True)
    return snap


def summary(s: Snapshot) -> dict[str, Any]:
    """Counts only (never the communities themselves) for logs/health."""
    return {"nodes": len(s.by_ip), "trap_communities": len(s.communities), "catalog_traps": len(s.traps)}
