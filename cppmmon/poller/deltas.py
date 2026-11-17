"""Counter delta logic (CLAUDE.md §4.1, DESIGN §10): resets, 32-bit wraps, first sample.

A negative delta means either a reset (daily auth counters at 00:00, service or
node restart: the new value *is* the delta) or a 32-bit wrap (interface octets,
CPU ticks): ``cur + 2^32 - prev``. Callers that know the node rebooted pass
``rebooted=True`` so a wrap is never assumed across a reboot.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

WRAP32 = 2 ** 32
Kind = Literal["reset", "wrap32"]


@dataclass(frozen=True)
class Delta:
    value: float | None  # None on the first sample (no previous value)
    seconds: float
    reset: bool = False
    wrapped: bool = False

    def per_minute(self) -> float | None:
        """Rate per minute, or None when undefined."""
        if self.value is None or self.seconds <= 0:
            return None
        return self.value * 60.0 / self.seconds


def counter_delta(prev: float | None, prev_ts: datetime | None, cur: float, cur_ts: datetime,
                  kind: Kind = "reset", rebooted: bool = False) -> Delta:
    """Delta between two counter samples."""
    if prev is None or prev_ts is None:
        return Delta(None, 0.0)
    secs = (cur_ts - prev_ts).total_seconds()
    d = cur - prev
    if d >= 0:
        return Delta(d, secs)
    if kind == "wrap32" and not rebooted and prev > WRAP32 * 0.5 and cur < WRAP32 * 0.5:
        return Delta(cur + WRAP32 - prev, secs, wrapped=True)
    return Delta(cur, secs, reset=True)


CPU_FIELDS = ("user", "nice", "system", "idle", "wait", "kernel", "interrupt")


def cpu_percent(prev: dict[str, float | None], cur: dict[str, float | None]) -> float | None:
    """Busy % from UCD raw tick deltas (fields missing on either side are ignored)."""
    total = idle = 0.0
    for f in CPU_FIELDS:
        a, b = prev.get(f), cur.get(f)
        if a is None or b is None:
            continue
        d = b - a
        if d < 0:
            d = b + WRAP32 - a if a > WRAP32 * 0.5 else 0.0
        total += d
        if f in ("idle", "wait"):
            idle += d
    if total <= 0:
        return None
    return max(0.0, min(100.0, 100.0 * (1.0 - idle / total)))
