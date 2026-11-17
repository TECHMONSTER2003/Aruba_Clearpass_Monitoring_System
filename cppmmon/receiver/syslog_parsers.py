"""Syslog envelope parsing (RFC 5424 / RFC 3164) and payload format detection.

Phase 2 scope: header fields + format tag only. Field-level CEF/LEEF/CPPM-standard
parsers are Phase 5, built against real captured lab samples.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$",
    re.S,
)
# BSD header. CPPM 6.14 sends an ISO-8601 timestamp in place of "Mmm dd hh:mm:ss"
# (observed on the lab node: "<142>2026-11-17T13:39:44+05:30 192.0.2.10 cppm.async-netd[...]:").
_RFC3164 = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) (?P<rest>.*)$", re.S
)
_TAG = re.compile(r"^(?P<app>[^:\[\s]{1,64})(?:\[(?P<pid>[^\]]*)\])?: ?(?P<msg>.*)$", re.S)


@dataclass
class Envelope:
    fmt: str  # cef | leef | cppm_std | rfc5424 | rfc3164 | raw
    facility: int | None
    severity: int | None
    host: str | None
    app: str | None
    device_ts: str | None
    body: str

    def parsed(self) -> dict[str, Any]:
        """Header details kept in ``raw_syslog.parsed`` (device timestamp per DESIGN §10)."""
        return {"device_ts": self.device_ts, "envelope": self.envelope} if self.device_ts or self.envelope else {}

    envelope: str | None = None


def detect_payload(body: str) -> str | None:
    """Payload format inside the envelope, if recognisable."""
    if "CEF:" in body[:200]:
        return "cef"
    if "LEEF:" in body[:200]:
        return "leef"
    return None


def parse_envelope(msg: str) -> Envelope:
    """Split PRI/header/body. Never raises: unparseable input is ``raw``."""
    facility = severity = None
    rest = msg
    m = _PRI.match(msg)
    if m and int(m.group(1)) <= 191:
        pri = int(m.group(1))
        facility, severity = pri >> 3, pri & 7
        rest = msg[m.end():]

    m5 = _RFC5424.match(rest)
    if m5:
        body = m5.group("msg") or ""
        app = None if m5.group("app") == "-" else m5.group("app")
        host = None if m5.group("host") == "-" else m5.group("host")
        return Envelope(detect_payload(body) or "rfc5424", facility, severity, host, app, m5.group("ts"), body, "rfc5424")

    m3 = _RFC3164.match(rest)
    if m3:
        app = None
        body = m3.group("rest")
        t = _TAG.match(body)
        if t:
            app, body = t.group("app"), t.group("msg")
        return Envelope(detect_payload(body) or "rfc3164", facility, severity, m3.group("host"), app, m3.group("ts"), body, "rfc3164")

    return Envelope(detect_payload(rest) or "raw", facility, severity, None, None, None, rest, None)
