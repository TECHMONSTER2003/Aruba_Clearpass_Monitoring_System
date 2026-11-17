"""Receiver: SNMP traps (UDP) + syslog (UDP/TCP) in one asyncio loop (CLAUDE.md §4.3/§4.4).

Socket callbacks only decode and enqueue (no I/O). A writer task drains the queue
every 200 ms or 500 records into the DB; on DB failure the batch goes to the
JSONL spool, and a replay task re-inserts it (idempotently) once the DB is back.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from cppmmon.config import get_settings
from cppmmon.db.session import utcnow
from cppmmon.heartbeat import heartbeat_loop
from cppmmon.logging_setup import setup_logging
from cppmmon.receiver.decode import TrapDecodeError, decode_trap
from cppmmon.receiver.directory import Snapshot, load_snapshot, summary
from cppmmon.receiver.framing import SyslogFramer
from cppmmon.receiver.persist import persist_batch, record_hash
from cppmmon.receiver.redact import redact
from cppmmon.receiver.spool import Spool
from cppmmon.receiver.suppress import RepeatSuppressor

SERVICE = "receiver"
log = logging.getLogger(f"cppmmon.{SERVICE}")

QUEUE_MAX = 100_000
BATCH_MAX = 500
BATCH_WAIT_S = 0.2


@dataclass
class Stats:
    trap_pkts: int = 0
    trap_decode_errors: int = 0
    trap_bad_community: int = 0
    syslog_udp_msgs: int = 0
    syslog_tcp_msgs: int = 0
    syslog_tcp_conns: int = 0
    syslog_truncated: int = 0
    syslog_suppressed: int = 0
    syslog_redacted: int = 0
    queue_drops: int = 0
    written_traps: int = 0
    written_syslog: int = 0
    events_emitted: int = 0
    db_errors: int = 0
    spooled: int = 0
    replayed: int = 0
    spool_failures: int = 0
    last_batch_ms: float = 0.0


@dataclass
class State:
    snap: Snapshot = field(default_factory=Snapshot)
    db_ok: bool = True


class TrapProtocol(asyncio.DatagramProtocol):
    def __init__(self, q: asyncio.Queue, state: State, stats: Stats) -> None:
        self.q, self.state, self.stats = q, state, stats
        self._inform_warned = False

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.stats.trap_pkts += 1
        try:
            d = decode_trap(data)
        except TrapDecodeError as exc:
            self.stats.trap_decode_errors += 1
            log.debug("trap decode failed", extra={"src": addr[0], "error": str(exc)})
            return
        if d.is_inform and not self._inform_warned:
            log.warning("InformRequest received; informs are stored but not acknowledged", extra={"src": addr[0]})
            self._inform_warned = True
        ok = d.community in self.state.snap.communities
        if not ok:
            self.stats.trap_bad_community += 1
        now = utcnow()
        rec = {
            "kind": "trap", "received_at": now, "src_ip": addr[0], "version": d.version, "community_ok": ok,
            "trap_oid": d.trap_oid, "varbinds": d.varbinds, "uptime_ticks": d.uptime_ticks, "agent_addr": d.agent_addr,
            "dedup_hash": record_hash(addr[0], now.isoformat(), data.hex()),
        }
        _enqueue(self.q, rec, self.stats)


class SyslogUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, q: asyncio.Queue, stats: Stats, max_bytes: int, sup: RepeatSuppressor) -> None:
        self.q, self.stats, self.max, self.sup = q, stats, max_bytes, sup

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.stats.syslog_udp_msgs += 1
        _enqueue_syslog(self.q, self.stats, self.sup, addr[0], "udp", data, self.max)


def _enqueue(q: asyncio.Queue, rec: dict[str, Any], stats: Stats) -> None:
    try:
        q.put_nowait(rec)
    except asyncio.QueueFull:
        stats.queue_drops += 1


def _syslog_record(src: str, transport: str, msg: str, truncated: bool = False, repeats: int | None = None) -> dict[str, Any]:
    now = utcnow()
    rec = {"kind": "syslog", "received_at": now, "src_ip": src, "transport": transport, "msg": msg,
           "truncated": truncated, "dedup_hash": record_hash(src, now.isoformat(), msg)}
    if repeats is not None:
        rec["suppressed_repeats"] = repeats
    return rec


def _enqueue_summary(q: asyncio.Queue, stats: Stats, s: dict[str, Any]) -> None:
    _enqueue(q, _syslog_record(s["src"], s["transport"], s["msg"], repeats=s["count"]), stats)


def _enqueue_syslog(q: asyncio.Queue, stats: Stats, sup: RepeatSuppressor, src: str, transport: str, data: bytes,
                    max_bytes: int, truncated: bool = False) -> None:
    if len(data) > max_bytes:
        data, truncated = data[:max_bytes], True
    if truncated:
        stats.syslog_truncated += 1
    msg = data.decode("utf-8", errors="replace").rstrip("\r\n\x00")
    if not msg:
        return
    msg, masked = redact(msg)  # never store credentials devices leak into their logs
    if masked:
        stats.syslog_redacted += 1
    store, summary = sup.admit(src, transport, msg)
    if summary is not None:
        _enqueue_summary(q, stats, summary)
    if not store:
        stats.syslog_suppressed += 1
        return
    _enqueue(q, _syslog_record(src, transport, msg, truncated), stats)


async def _suppress_expirer(q: asyncio.Queue, stats: Stats, sup: RepeatSuppressor) -> None:
    while True:
        await asyncio.sleep(10)
        for s in sup.expire():
            _enqueue_summary(q, stats, s)


async def _writer(q: asyncio.Queue, state: State, spool: Spool, stats: Stats) -> None:
    loop = asyncio.get_running_loop()
    while True:
        batch = [await q.get()]
        deadline = loop.time() + BATCH_WAIT_S
        while len(batch) < BATCH_MAX:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(q.get(), remaining))
            except TimeoutError:
                break
        await _flush(batch, state, spool, stats)


async def _flush(batch: list[dict[str, Any]], state: State, spool: Spool, stats: Stats) -> None:
    t0 = time.perf_counter()
    try:
        res = await asyncio.to_thread(persist_batch, batch, state.snap)
        stats.written_traps += res["traps"]
        stats.written_syslog += res["syslog"]
        stats.events_emitted += res["events"]
        if not state.db_ok:
            log.info("database writes recovered")
        state.db_ok = True
    except Exception as exc:  # noqa: BLE001 - any failure must spool, never drop
        stats.db_errors += 1
        if state.db_ok:
            log.error("database write failed, spooling", extra={"error": exc.__class__.__name__, "detail": str(exc)[:200]},
                      exc_info=not isinstance(exc, SQLAlchemyError))
        state.db_ok = False
        try:
            await asyncio.to_thread(spool.append, batch)
            stats.spooled += len(batch)
        except OSError as sexc:
            stats.spool_failures += len(batch)
            log.critical("spool write failed, records lost", extra={"records": len(batch), "error": str(sexc)})
    stats.last_batch_ms = round((time.perf_counter() - t0) * 1000, 1)


async def _replayer(state: State, spool: Spool, stats: Stats) -> None:
    while True:
        await asyncio.sleep(10)
        if not spool.files():
            continue
        try:
            n = await asyncio.to_thread(spool.replay, lambda recs: persist_batch(recs, state.snap))
            stats.replayed += n
            if n:
                log.info("spool replay complete", extra={"records": n})
        except SQLAlchemyError as exc:
            log.warning("spool replay deferred, DB still failing", extra={"error": exc.__class__.__name__})
        except OSError as exc:
            log.error("spool replay I/O error", extra={"error": str(exc)})


async def _refresher(state: State) -> None:
    first = True
    while True:
        try:
            state.snap = await asyncio.to_thread(load_snapshot)
            if first:
                log.info("directory loaded", extra=summary(state.snap))
                first = False
        except SQLAlchemyError as exc:
            log.warning("directory refresh failed, keeping last snapshot", extra={"error": exc.__class__.__name__})
        await asyncio.sleep(30)


async def run() -> None:
    """Bind all listeners and run until SIGTERM; drains the queue on shutdown."""
    cfg = get_settings()
    stats, state = Stats(), State()
    spool = Spool(cfg.spool_dir)
    q: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
    loop = asyncio.get_running_loop()
    started = utcnow()

    try:
        state.snap = await asyncio.to_thread(load_snapshot)
    except SQLAlchemyError as exc:
        log.error("initial directory load failed; traps will be stored without events until the DB is back",
                  extra={"error": exc.__class__.__name__})

    trap_tr, _ = await loop.create_datagram_endpoint(lambda: TrapProtocol(q, state, stats),
                                                     local_addr=(cfg.receiver_bind, cfg.receiver_trap_port))
    sup = RepeatSuppressor(cfg.syslog_repeat_window_s)
    sys_tr, _ = await loop.create_datagram_endpoint(lambda: SyslogUdpProtocol(q, stats, cfg.syslog_max_bytes, sup),
                                                    local_addr=(cfg.receiver_bind, cfg.receiver_syslog_port))

    async def _tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        stats.syslog_tcp_conns += 1
        peer = writer.get_extra_info("peername")[0]
        framer = SyslogFramer(cfg.syslog_max_bytes)
        try:
            while data := await reader.read(65536):
                for msg, trunc in framer.feed(data):
                    stats.syslog_tcp_msgs += 1
                    _enqueue_syslog(q, stats, sup, peer, "tcp", msg, cfg.syslog_max_bytes, trunc)
            for msg, trunc in framer.flush():
                stats.syslog_tcp_msgs += 1
                _enqueue_syslog(q, stats, sup, peer, "tcp", msg, cfg.syslog_max_bytes, trunc)
        except ConnectionError as exc:
            log.debug("tcp syslog peer reset", extra={"src": peer, "error": str(exc)})
        finally:
            writer.close()

    tcp_srv = await asyncio.start_server(_tcp, cfg.receiver_bind, cfg.receiver_syslog_port, limit=cfg.syslog_max_bytes * 2)
    log.info("started", extra={"trap_udp": cfg.receiver_trap_port, "syslog_udp": cfg.receiver_syslog_port,
                               "syslog_tcp": cfg.receiver_syslog_port, **summary(state.snap)})

    prev = {"t": time.monotonic(), "traps": 0, "syslog": 0}

    def _beat_stats() -> dict[str, Any]:
        now = time.monotonic()
        dt = max(now - prev["t"], 1e-6)
        sys_total = stats.syslog_udp_msgs + stats.syslog_tcp_msgs
        rates = {"traps_per_s": round((stats.trap_pkts - prev["traps"]) / dt, 2),
                 "syslog_per_s": round((sys_total - prev["syslog"]) / dt, 2)}
        prev.update(t=now, traps=stats.trap_pkts, syslog=sys_total)
        files, size = spool.backlog()
        return {**vars(stats), **rates, "queue_depth": q.qsize(), "db_ok": state.db_ok,
                "spool_files": files, "spool_bytes": size, **summary(state.snap)}

    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    tasks = [
        asyncio.create_task(_writer(q, state, spool, stats), name="writer"),
        asyncio.create_task(_replayer(state, spool, stats), name="replayer"),
        asyncio.create_task(_refresher(state), name="refresher"),
        asyncio.create_task(_suppress_expirer(q, stats, sup), name="suppress-expirer"),
        asyncio.create_task(heartbeat_loop(SERVICE, started, _beat_stats), name="heartbeat"),
    ]
    await stop.wait()
    trap_tr.close()
    sys_tr.close()
    tcp_srv.close()
    for t in tasks:
        t.cancel()
    pending: list[dict[str, Any]] = []
    while not q.empty():
        pending.append(q.get_nowait())
    if pending:
        await _flush(pending, state, spool, stats)
    log.info("stopped", extra={k: v for k, v in vars(stats).items() if isinstance(v, int)})


def main() -> None:
    """Console entrypoint (systemd ExecStart)."""
    cfg = get_settings()
    setup_logging(SERVICE, cfg.log_dir, cfg.log_level)
    asyncio.run(run())


if __name__ == "__main__":
    main()
