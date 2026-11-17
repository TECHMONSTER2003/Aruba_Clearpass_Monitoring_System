"""Mask credentials that devices leak into syslog before anything is stored (CLAUDE.md §0.4).

Found 2026-11-17: CPPM 6.14 ``cppm.async-netd`` at DEBUG level logs every SNMP
request, including ``community=<value>`` and pysnmp's ``payload [<value>]`` repr
of the community OctetString. Masked generically, not just for known values,
because other SNMP managers' communities appear there too.
"""
from __future__ import annotations

import re

_KEYED = re.compile(
    r"(?i)\b(community(?:name)?|password|passwd|secret|client_secret|bind_?password|auth_?key|priv_?key|"
    r"shared_?secret|radius_?secret)(\s*[=:]\s*|\s+)(['\"]?)[^\s'\",>\]]+"
)
_PAYLOAD = re.compile(r"payload \[[^\]]*\]")


def redact(msg: str) -> tuple[str, bool]:
    """Return (masked message, whether anything was masked)."""
    out = _KEYED.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***", msg)
    out = _PAYLOAD.sub("payload [***]", out)
    return out, out != msg
