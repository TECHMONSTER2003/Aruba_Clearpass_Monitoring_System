"""ICMP reachability: icmplib unprivileged sockets, falling back to fping."""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
import time

from icmplib import async_ping
from icmplib.exceptions import ICMPLibError, SocketPermissionError

from cppmmon.collectors.types import CheckResult

log = logging.getLogger(__name__)

HINT = (
    "No echo reply. Check routing from this monitor to the CPPM management IP and any ACL/firewall "
    "dropping ICMP. CPPM answers ping by default."
)


async def _fping(host: str, count: int, timeout_s: float) -> tuple[bool, float | None, float]:
    exe = shutil.which("fping")
    if exe is None:
        raise RuntimeError("icmplib not permitted and fping is not installed")
    proc = await asyncio.create_subprocess_exec(
        exe, "-q", "-C", str(count), "-t", str(int(timeout_s * 1000)), host,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    # "host : 0.71 0.65 -"
    samples = [float(x) for x in re.findall(r"\d+\.\d+", err.decode(errors="replace").split(":", 1)[-1])]
    loss = 1 - len(samples) / count
    return bool(samples), (sum(samples) / len(samples) if samples else None), loss


async def ping(host: str, count: int = 3, timeout_s: float = 2.0) -> CheckResult:
    """Send ``count`` echo requests; ok if at least one reply arrives."""
    t0 = time.perf_counter()
    method = "icmplib"
    try:
        h = await async_ping(host, count=count, interval=0.2, timeout=timeout_s, privileged=False)
        alive, rtt, loss = h.is_alive, (h.avg_rtt if h.is_alive else None), h.packet_loss
    except SocketPermissionError:
        log.warning("unprivileged ICMP not permitted, using fping", extra={"host": host})
        method = "fping"
        try:
            alive, rtt, loss = await _fping(host, count, timeout_s)
        except (OSError, RuntimeError) as exc:
            return CheckResult("icmp", ok=False, error=str(exc), hint="Enable unprivileged ping (sysctl net.ipv4.ping_group_range) or install fping.")
    except (ICMPLibError, OSError) as exc:
        return CheckResult("icmp", ok=False, error=f"{exc.__class__.__name__}: {exc}", hint=HINT)

    elapsed = (time.perf_counter() - t0) * 1000
    details = {"method": method, "sent": count, "loss_pct": round(loss * 100, 1)}
    if not alive:
        return CheckResult("icmp", ok=False, latency_ms=round(elapsed, 1), summary="100% packet loss",
                           error=f"no reply to {count} echo requests", hint=HINT, details=details)
    return CheckResult("icmp", ok=True, latency_ms=round(rtt or 0.0, 2),
                       summary=f"{rtt:.2f} ms avg, {details['loss_pct']}% loss", details=details)
