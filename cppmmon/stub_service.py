"""Shared idle loop for services that are stubs in Phase 0 (poller, engine)."""
from __future__ import annotations

import asyncio
import logging
import signal

from cppmmon.config import get_settings
from cppmmon.db.session import utcnow
from cppmmon.heartbeat import heartbeat_loop
from cppmmon.logging_setup import setup_logging


async def _idle(service: str) -> None:
    log = logging.getLogger(f"cppmmon.{service}")
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    log.info("started", extra={"phase": 0, "stub": True})
    hb = asyncio.create_task(heartbeat_loop(service, utcnow(), lambda: {"stub": True}))
    await stop.wait()
    hb.cancel()
    log.info("stopped")


def run_stub(service: str) -> None:
    """Set up logging and idle (with heartbeats) until SIGTERM."""
    cfg = get_settings()
    setup_logging(service, cfg.log_dir, cfg.log_level)
    asyncio.run(_idle(service))
