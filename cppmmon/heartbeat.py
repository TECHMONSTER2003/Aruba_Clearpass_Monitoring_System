"""Service heartbeat: each long-running service upserts its liveness + counters."""
from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError

from cppmmon.db.models import ServiceHeartbeat
from cppmmon.db.session import session_scope, utcnow

log = logging.getLogger(__name__)


def beat(service: str, started_at: datetime, stats: dict | None = None) -> bool:
    """Upsert one heartbeat row. Returns False (and logs) if the DB is unavailable."""
    try:
        with session_scope() as s:
            row = s.get(ServiceHeartbeat, service)
            if row is None:
                row = ServiceHeartbeat(service=service, started_at=started_at, last_beat=utcnow())
                s.add(row)
            row.pid = os.getpid()
            row.started_at = started_at
            row.last_beat = utcnow()
            row.stats = stats or {}
        return True
    except SQLAlchemyError as exc:
        log.warning("heartbeat write failed", extra={"service": service, "error": str(exc.__class__.__name__)})
        return False


async def heartbeat_loop(
    service: str, started_at: datetime, stats_fn: Callable[[], dict] | None = None, interval_s: float = 15.0
) -> None:
    """Run :func:`beat` forever in a worker thread so the event loop never blocks on DB I/O."""
    while True:
        stats = stats_fn() if stats_fn else {}
        await asyncio.to_thread(beat, service, started_at, stats)
        await asyncio.sleep(interval_s)
