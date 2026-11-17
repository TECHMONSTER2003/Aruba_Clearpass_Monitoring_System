"""One canonical key per CPPM service, so every signal about it lands on ONE alert.

A stopped service is reported three ways (all observed on the lab CPPM 6.14.1, 2026-11-17):
  * trap 1017/1018/1019 ``cppmServiceName``      "cpass-tacacs-server"            (unit name)
  * watchdog trap ``extOutput`` / ``extNames``    "TACACS+ Server [ cpass-tacacs-server ] is stopped"
  * REST /api/server/service                      key "cpass-tacacs-server.service", display_name "TACACS+ server"
All map to dedup instance ``cpass-tacacs-server`` under event type ``service.down``.
When only a display name is known (e.g. simulated traps) the lower-cased display name is used.
"""
from __future__ import annotations

import re

SERVICE_DOWN = "service.down"
# High severity: services whose loss stops authentication, the database or replication (DESIGN §2.2)
CRITICAL_RE = re.compile(
    r"radius|tacacs|policy[ -]?server|\bdb|dbcn|dbwrite|database|replication|postgres|domain[ -]?server", re.I)
_BRACKET = re.compile(r"^\s*(?P<display>.+?)\s*\[\s*(?P<unit>[^\]]+?)\s*\]")


def canonical(name: str | None) -> str:
    """Unit names lose '.service' and case; display names are lower-cased with spaces collapsed."""
    n = re.sub(r"\s+", " ", (name or "").strip()).lower()
    return n.removesuffix(".service")[:128]


def from_watchdog(ext_output: str | None, ext_name: str | None) -> tuple[str, str]:
    """(canonical key, display label) from a watchdog trap's extOutput / extNames."""
    m = _BRACKET.match(ext_output or "")
    if m:
        return canonical(m.group("unit")), m.group("display").strip()
    unit = (ext_name or (ext_output or "").split(" is ")[0] or "unknown").strip()
    return canonical(unit), unit


def is_critical(*names: str | None) -> bool:
    """True if any given name is a RADIUS/TACACS/Policy/DB/replication/domain service."""
    return any(CRITICAL_RE.search(n or "") for n in names)
