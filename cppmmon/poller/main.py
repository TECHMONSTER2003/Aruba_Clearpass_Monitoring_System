"""Poller scheduler: per-node, per-job asyncio tasks with jitter and concurrency caps (DESIGN §11).

* Node list is reloaded every 60 s: new/enabled nodes start, removed/paused nodes
  stop, credential edits are picked up without losing counter/status state.
* SNMP sessions are capped at 50, REST at 20. Every interval is jittered ±10 %.
* Job outcomes (runs, failures, duration) are published via the heartbeat for
  the Health page.
"""
from __future__ import annotations

import asyncio
import logging
import random
import signal
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from cppmmon.config import get_settings
from cppmmon.crypto import CryptoError
from cppmmon.db.models import Node, PollRequest
from cppmmon.db.session import session_scope, utcnow
from cppmmon.heartbeat import heartbeat_loop
from cppmmon.logging_setup import setup_logging
from cppmmon.node_creds import api_params, snmp_params
from cppmmon.poller import store
from cppmmon.poller.jobs import JOBS, Ctx, Job, NodeRT
from cppmmon.poller.thresholds import Evaluator, seed_rules

SERVICE = "poller"
log = logging.getLogger(f"cppmmon.{SERVICE}")
FAST_SERVICE_RECHECK_S = 120


def _has_open_service_alert(node_id: int) -> bool:
    """True while the node has an open/suppressed service.down alert (drives the fast service re-check)."""
    from cppmmon.db.models import Alert

    try:
        with session_scope() as s:
            return s.scalar(select(Alert.id).where(Alert.node_id == node_id, Alert.rule_id == "service.down",
                                                   Alert.open_marker == 1).limit(1)) is not None
    except SQLAlchemyError:
        return False


@dataclass
class JobStat:
    runs: int = 0
    failures: int = 0
    last_ms: float = 0.0
    max_ms: float = 0.0
    last_at: str | None = None
    last_error: str | None = None


@dataclass
class Poller:
    ctx: Ctx
    nodes: dict[int, NodeRT] = field(default_factory=dict)
    fingerprints: dict[int, tuple] = field(default_factory=dict)
    tasks: dict[tuple[int, str], asyncio.Task] = field(default_factory=dict)
    stats: dict[str, JobStat] = field(default_factory=lambda: {j.name: JobStat() for j in JOBS})
    db_errors: int = 0
    wake: dict[tuple[int, str], asyncio.Event] = field(default_factory=dict)
    poll_now_served: int = 0

    async def _sleep(self, node_id: int, job: Job, seconds: float) -> None:
        """Sleep until the next interval, or until 'Poll now' wakes this node's jobs."""
        ev = self.wake.setdefault((node_id, job.name), asyncio.Event())
        try:
            await asyncio.wait_for(ev.wait(), seconds)
        except TimeoutError:
            pass
        ev.clear()

    def poll_now(self, node_ids: list[int] | None) -> int:
        """Wake every job of the given nodes (None = all). Returns the number of nodes woken."""
        targets = list(self.nodes) if node_ids is None else [n for n in node_ids if n in self.nodes]
        for nid in targets:
            for job in JOBS:
                self.wake.setdefault((nid, job.name), asyncio.Event()).set()
        return len(targets)

    async def watch_poll_requests(self) -> None:
        """Pick up 'Poll now' requests written by the web UI (poll_requests table)."""
        def take() -> list[int | None]:
            with session_scope() as s:
                rows = list(s.scalars(select(PollRequest).where(PollRequest.picked_at.is_(None)).order_by(PollRequest.id).limit(50)))
                for r in rows:
                    r.picked_at = utcnow()
                return [r.node_id for r in rows]

        while True:
            try:
                reqs = await asyncio.to_thread(take)
                if reqs:
                    ids = None if any(r is None for r in reqs) else sorted({r for r in reqs if r is not None})
                    n = self.poll_now(ids)
                    self.poll_now_served += len(reqs)
                    log.info("poll now", extra={"requests": len(reqs), "nodes_woken": n, "scope": "all" if ids is None else ids})
            except SQLAlchemyError as exc:
                log.warning("poll-request check failed", extra={"error": exc.__class__.__name__})
            await asyncio.sleep(2)

    async def run_job(self, node_id: int, job: Job) -> None:
        await self._sleep(node_id, job, random.uniform(1, min(job.interval_s, 30)))  # initial stagger
        while True:
            rt = self.nodes.get(node_id)
            if rt is None:
                return
            st = self.stats[job.name]
            t0 = time.perf_counter()
            try:
                res = await asyncio.wait_for(job.fn(rt, self.ctx), job.timeout_s)
                await asyncio.to_thread(store.commit, rt.id, res, utcnow())
                st.last_error = None
            except TimeoutError:
                st.failures += 1
                st.last_error = f"timeout after {job.timeout_s}s"
                log.warning("job timed out", extra={"job": job.name, "node_id": node_id})
            except SQLAlchemyError as exc:
                st.failures += 1
                self.db_errors += 1
                st.last_error = f"db: {exc.__class__.__name__}"
                log.error("job results not saved (DB)", extra={"job": job.name, "node_id": node_id, "error": exc.__class__.__name__})
            except Exception as exc:  # noqa: BLE001 - one bad job must never stop the scheduler
                st.failures += 1
                st.last_error = f"{exc.__class__.__name__}: {str(exc)[:120]}"
                log.exception("job crashed", extra={"job": job.name, "node_id": node_id})
            ms = (time.perf_counter() - t0) * 1000
            st.runs += 1
            st.last_ms = round(ms, 1)
            st.max_ms = max(st.max_ms, st.last_ms)
            st.last_at = utcnow().isoformat(timespec="seconds")
            interval = job.interval_s
            if job.name == "rest_services" and await asyncio.to_thread(_has_open_service_alert, node_id):
                # Adaptive: CPPM does not always send a "started" trap (lab, 2026-11-17), so while a
                # service.down alert is open, re-check this node's services every 2 min instead of 15.
                interval = FAST_SERVICE_RECHECK_S
            await self._sleep(node_id, job, interval * random.uniform(0.9, 1.1))

    def _start(self, rt: NodeRT) -> None:
        for job in JOBS:
            if job.needs_api and rt.api is None:
                continue
            key = (rt.id, job.name)
            if key not in self.tasks or self.tasks[key].done():
                self.tasks[key] = asyncio.create_task(self.run_job(rt.id, job), name=f"{job.name}:{rt.id}")

    def _stop(self, node_id: int) -> None:
        for key in [k for k in self.tasks if k[0] == node_id]:
            self.tasks.pop(key).cancel()
        self.nodes.pop(node_id, None)
        self.fingerprints.pop(node_id, None)

    async def refresh_nodes(self) -> None:
        """Sync runtime node set with the DB (enabled nodes only)."""
        def load() -> list[tuple[Node, Any, Any, dict[str, Any]]]:
            out = []
            with session_scope() as s:
                for n in s.scalars(select(Node).where(Node.enabled.is_(True))):
                    try:
                        sp, ap = snmp_params(n), api_params(n)
                    except CryptoError:
                        log.error("cannot decrypt node credentials; skipping", extra={"node_id": n.id})
                        continue
                    out.append((n, sp, ap, store.load_node_context(n.id) if n.id not in self.nodes else {}))
            return out

        rows = await asyncio.to_thread(load)
        seen = set()
        for n, sp, ap, nctx in rows:
            seen.add(n.id)
            fp = (n.name, n.ip, sp, ap)
            rt = self.nodes.get(n.id)
            if rt is None:
                rt = NodeRT(n.id, n.name, n.ip, sp, ap, status=nctx.get("status") or "unknown",
                            sys_index=nctx.get("sys_index"), uptime_s=nctx.get("uptime_s"),
                            cluster_size=nctx.get("cluster_size"), api_state=nctx.get("api_state"),
                            services_prev=nctx.get("services") or {})
                self.nodes[n.id] = rt
                log.info("polling node", extra={"node_id": n.id, "node": n.name, "ip": n.ip, "api": ap is not None})
            elif self.fingerprints.get(n.id) != fp:
                if rt.ip != n.ip:
                    rt.sys_index, rt.server_uuid, rt.cpu_prev = None, None, None
                rt.name, rt.ip, rt.snmp, rt.api = n.name, n.ip, sp, ap
                rt.unsupported.clear()
                log.info("node settings changed; applied", extra={"node_id": n.id})
            self.fingerprints[n.id] = fp
            self._start(rt)
        for nid in [i for i in self.nodes if i not in seen]:
            log.info("node removed or paused; stopping its jobs", extra={"node_id": nid})
            self._stop(nid)

    def beat_stats(self) -> dict[str, Any]:
        return {"nodes": len(self.nodes), "tasks": len(self.tasks), "db_errors": self.db_errors, "poll_now_served": self.poll_now_served,
                "jobs": {k: vars(v) for k, v in self.stats.items()},
                "status": {rt.name: rt.status for rt in self.nodes.values()}}


async def run() -> None:
    """Start the scheduler and run until SIGTERM."""
    started = utcnow()
    added = await asyncio.to_thread(seed_rules)
    if added:
        log.info("default threshold rules seeded", extra={"added": added})
    evaluator = Evaluator()
    await asyncio.to_thread(evaluator.load)
    counters = await asyncio.to_thread(store.load_counters)
    p = Poller(Ctx(counters=counters, evaluator=evaluator, snmp_sem=asyncio.Semaphore(50), api_sem=asyncio.Semaphore(20)))
    log.info("started", extra={"rules": len(evaluator.rules), "counters": len(counters)})

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def refresher() -> None:
        while True:
            try:
                await p.refresh_nodes()
                await asyncio.to_thread(evaluator.load)  # picks up threshold edits
            except SQLAlchemyError as exc:
                log.warning("node/rule refresh failed; keeping current set", extra={"error": exc.__class__.__name__})
            await asyncio.sleep(60)

    bg = [asyncio.create_task(refresher()), asyncio.create_task(heartbeat_loop(SERVICE, started, p.beat_stats)),
          asyncio.create_task(p.watch_poll_requests())]
    await stop.wait()
    for t in [*bg, *p.tasks.values()]:
        t.cancel()
    log.info("stopped")


def main() -> None:
    """Console entrypoint (systemd ExecStart)."""
    cfg = get_settings()
    setup_logging(SERVICE, cfg.log_dir, cfg.log_level)
    asyncio.run(run())


if __name__ == "__main__":
    main()
