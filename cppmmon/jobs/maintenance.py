"""Maintenance one-shot (systemd timer, hourly): 5-min rollups, retention, monitor self-checks.

* Rollups: raw ``metrics`` → ``metrics_5m`` (avg/min/max per node/metric/instance/5-min bucket).
  Watermark = newest rolled bucket; at most ``MAX_ROLLUP_HOURS`` of backlog per run.
* Retention (DESIGN §6): raw_syslog 30 d, raw_traps 90 d, processed events 30 d,
  raw metrics 7 d (only rows already rolled up), metrics_5m 90 d. Deletes in 10k batches.
* Self-check: monitor disk usage → internal ``monitor.disk_low`` event (Medium) / clear.
"""
from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from cppmmon.config import get_settings
from cppmmon.db.models import Alert, Event, Metric, Metric5m, RawSyslog, RawTrap
from cppmmon.db.session import session_scope, utcnow
from cppmmon.heartbeat import beat
from cppmmon.logging_setup import setup_logging

log = logging.getLogger("cppmmon.maintenance")
BATCH = 10_000
BUCKET_S = 300
MAX_ROLLUP_HOURS = 48
DISK_WARN_PCT = 85.0
DISK_CLEAR_PCT = 80.0


def purge(model: Any, ts_col: Any, cutoff: Any, extra: Any = None, max_batches: int = 500) -> int:
    """Delete rows older than ``cutoff`` in id batches; returns rows deleted."""
    total = 0
    for _ in range(max_batches):
        with session_scope() as s:
            q = select(model.id).where(ts_col < cutoff).order_by(model.id).limit(BATCH)
            if extra is not None:
                q = q.where(extra)
            ids = list(s.scalars(q))
            if not ids:
                break
            s.execute(delete(model).where(model.id.in_(ids)))
            total += len(ids)
        if len(ids) < BATCH:
            break
    return total


def _bucket(ts: datetime) -> datetime:
    epoch = datetime(1970, 1, 1)
    return epoch + timedelta(seconds=int((ts - epoch).total_seconds() // BUCKET_S * BUCKET_S))


def rollup(now: datetime | None = None) -> int:
    """Roll complete 5-min buckets into metrics_5m. Returns buckets written."""
    now = now or utcnow()
    end = _bucket(now - timedelta(minutes=10))  # only buckets that can no longer receive samples
    with session_scope() as s:
        mark = s.scalar(select(func.max(Metric5m.bucket)))
        start = mark + timedelta(seconds=BUCKET_S) if mark else _bucket(s.scalar(select(func.min(Metric.ts))) or end)
    end = min(end, start + timedelta(hours=MAX_ROLLUP_HOURS))  # bounded work per run; later runs catch up
    written = 0
    cur = start
    while cur < end:
        chunk_end = min(cur + timedelta(hours=1), end)
        with session_scope() as s:
            acc: dict[tuple[int, str, str, datetime], list[float]] = {}
            for nid, m, inst, ts, v in s.execute(select(Metric.node_id, Metric.metric, Metric.instance, Metric.ts, Metric.value)
                                                 .where(Metric.ts >= cur, Metric.ts < chunk_end)):
                acc.setdefault((nid, m, inst or "", _bucket(ts)), []).append(v)
            rows = [{"node_id": k[0], "metric": k[1], "instance": k[2], "bucket": k[3],
                     "avg": sum(v) / len(v), "min": min(v), "max": max(v)} for k, v in acc.items()]
            if rows:
                if s.get_bind().dialect.name == "mysql":
                    st = mysql_insert(Metric5m).values(rows)
                    s.execute(st.on_duplicate_key_update(avg=st.inserted.avg, min=st.inserted.min, max=st.inserted.max))
                else:
                    st = sqlite_insert(Metric5m).values(rows)
                    s.execute(st.on_conflict_do_update(index_elements=["node_id", "metric", "instance", "bucket"],
                                                       set_={"avg": st.excluded.avg, "min": st.excluded.min, "max": st.excluded.max}))
            written += len(rows)
        cur = chunk_end
    return written


def run_retention() -> dict[str, int]:
    """Apply the configured retention windows (raw metrics only once rolled up)."""
    cfg = get_settings()
    now = utcnow()
    with session_scope() as s:
        mark = s.scalar(select(func.max(Metric5m.bucket)))
    metrics_cutoff = now - timedelta(days=cfg.retain_metrics_days)
    if mark is not None:
        metrics_cutoff = min(metrics_cutoff, mark + timedelta(seconds=BUCKET_S))  # never purge raw rows not yet rolled up
    return {
        "raw_syslog": purge(RawSyslog, RawSyslog.received_at, now - timedelta(days=cfg.retain_raw_syslog_days)),
        "raw_traps": purge(RawTrap, RawTrap.received_at, now - timedelta(days=cfg.retain_raw_traps_days)),
        "events": purge(Event, Event.ts, now - timedelta(days=cfg.retain_events_days), Event.processed == 1),
        "metrics": purge(Metric, Metric.ts, metrics_cutoff) if mark is not None else 0,
        "metrics_5m": _purge_5m(now - timedelta(days=cfg.retain_metrics_5m_days)),
    }


def _purge_5m(cutoff: datetime) -> int:
    with session_scope() as s:
        return s.execute(delete(Metric5m).where(Metric5m.bucket < cutoff)).rowcount or 0


def disk_check(path: str | None = None) -> dict[str, Any]:
    """Monitor's own disk: emit monitor.disk_low (Medium) above 85 %, clear below 80 %."""
    cfg = get_settings()
    du = shutil.disk_usage(path or str(cfg.data_dir))
    pct = 100.0 * du.used / du.total
    with session_scope() as s:
        is_open = s.scalar(select(Alert.id).where(Alert.dedup_key == "None|monitor.disk_low|", Alert.open_marker == 1)) is not None
        title = f"[CPPM][MEDIUM] Monitor VM disk {pct:.0f}% used ({du.free / 2**30:.1f} GB free) on {cfg.data_dir}"
        if pct >= DISK_WARN_PCT and not is_open:
            s.add(Event(ts=utcnow(), node_id=None, source="internal", event_type="monitor.disk_low", severity="medium",
                        is_clear=False, dedup_instance="", processed=0,
                        attributes={"title": title, "used_pct": round(pct, 1), "free_gb": round(du.free / 2**30, 2)}))
        elif pct < DISK_CLEAR_PCT and is_open:
            s.add(Event(ts=utcnow(), node_id=None, source="internal", event_type="monitor.disk_low", severity="info",
                        is_clear=True, dedup_instance="", processed=0,
                        attributes={"title": f"Monitor VM disk back to {pct:.0f}% used"}))
    return {"disk_used_pct": round(pct, 1), "disk_free_gb": round(du.free / 2**30, 2)}


def main() -> None:
    """One-shot run (Type=oneshot unit)."""
    cfg = get_settings()
    setup_logging("maintenance", cfg.log_dir, cfg.log_level)
    started = utcnow()
    t0 = time.perf_counter()
    try:
        buckets = rollup()
        deleted = run_retention()
        disk = disk_check()
    except SQLAlchemyError as exc:
        log.error("maintenance failed", extra={"error": exc.__class__.__name__})
        raise SystemExit(1) from exc
    stats = {"rollup_rows": buckets, "deleted": deleted, **disk, "duration_s": round(time.perf_counter() - t0, 2)}
    log.info("maintenance done", extra=stats)
    beat("maintenance", started, stats)


if __name__ == "__main__":
    main()
