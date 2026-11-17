"""Syslog repeat suppression: store a repeating message once per window, then a count.

Added 2026-11-17 after the lab CPPM sent ~44 msg/s of one repeating async-netd
WARN line (≈2.6 GB/day of raw rows on a VM with 1.9 GB free). Messages are keyed
by (source IP, body with digits/hex normalised), so timestamps, PIDs and counters
inside otherwise identical lines do not defeat it. Distinct messages are never
suppressed.
"""
from __future__ import annotations

import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

_HEADER = re.compile(r"^<\d{1,3}>(?:1 )?\S+ \S+ ")  # PRI + timestamp + host
_VOLATILE = re.compile(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{8,}|\d+")


def template(msg: str) -> str:
    """Normalised body used as the repeat key."""
    body = _HEADER.sub("", msg, count=1)
    return _VOLATILE.sub("#", body)[:400]


@dataclass
class _Entry:
    first: float
    suppressed: int
    sample: str
    src: str
    transport: str


class RepeatSuppressor:
    """Not thread-safe: used only from the event-loop thread."""

    def __init__(self, window_s: float = 60.0, max_keys: int = 20000) -> None:
        self.window = window_s
        self.max_keys = max_keys
        self._seen: OrderedDict[tuple[str, str], _Entry] = OrderedDict()

    @property
    def enabled(self) -> bool:
        return self.window > 0

    def admit(self, src: str, transport: str, msg: str, now: float | None = None) -> tuple[bool, dict[str, Any] | None]:
        """Return (store_this_message, summary_record_to_store_first_or_None)."""
        if not self.enabled:
            return True, None
        now = time.monotonic() if now is None else now
        key = (src, template(msg))
        e = self._seen.get(key)
        if e is not None and now - e.first < self.window:
            e.suppressed += 1
            return False, None
        summary = self._summary(e) if e is not None and e.suppressed else None  # nothing suppressed → no summary row
        self._seen[key] = _Entry(now, 0, msg, src, transport)
        self._seen.move_to_end(key)
        while len(self._seen) > self.max_keys:
            _k, old = self._seen.popitem(last=False)
            if old.suppressed and summary is None:
                summary = self._summary(old)
        return True, summary

    def expire(self, now: float | None = None) -> list[dict[str, Any]]:
        """Close windows that have ended; returns summary records for those with repeats."""
        now = time.monotonic() if now is None else now
        out = []
        for key in [k for k, e in self._seen.items() if now - e.first >= self.window]:
            e = self._seen.pop(key)
            if e.suppressed:
                out.append(self._summary(e))
        return out

    def _summary(self, e: _Entry) -> dict[str, Any]:
        return {"src": e.src, "transport": e.transport, "count": e.suppressed, "window_s": int(self.window),
                "msg": f"[cppmmon] {e.suppressed} repeat(s) of this message suppressed within {int(self.window)}s: {e.sample}"}
