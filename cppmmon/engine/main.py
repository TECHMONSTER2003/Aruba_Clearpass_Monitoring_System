"""Engine: events outbox → alerts → tickets. The only writer of ``alerts`` and ``tickets`` (CLAUDE.md §4.5).

Loop every 2 s: take up to 500 unprocessed events (``FOR UPDATE SKIP LOCKED`` on
MySQL; plain SELECT with a single consumer on SQLite), apply the rules in
DESIGN §7, mark them processed. Each event runs in its own savepoint so one bad
event is marked failed (processed=2) instead of blocking the queue.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from cppmmon.config import get_settings
from cppmmon.db.models import Alert, Event, Node, NodeState, Ticket, TrapCatalog
from cppmmon.db.session import session_scope, utcnow
from cppmmon.engine import correlation as corr
from cppmmon.engine.rules import SEV_ORDER, TICKET_SEVERITIES, Decision, bump, decide, ticket_context
from cppmmon.engine.tickets import FileTicketSink, TicketSink
from cppmmon.heartbeat import heartbeat_loop
from cppmmon.logging_setup import setup_logging

SERVICE = "engine"
log = logging.getLogger(f"cppmmon.{SERVICE}")
BATCH = 500
REOCCUR_NOTE_EVERY = timedelta(minutes=30)


@dataclass
class EngineStats:
    processed: int = 0
    failed: int = 0
    opened: int = 0
    reoccurred: int = 0
    cleared: int = 0
    suppressed: int = 0
    tickets: int = 0
    ticket_failures: int = 0
    lag_s: float = 0.0
    last_batch_ms: float = 0.0


class Engine:
    def __init__(self, sink: TicketSink, stats: EngineStats | None = None) -> None:
        self.sink = sink
        self.stats = stats or EngineStats()

    # ----------------------------------------------------------- batch
    def run_batch(self) -> int:
        """Process one batch; returns events handled. Raises SQLAlchemyError if the DB is down."""
        t0 = time.perf_counter()
        with session_scope() as s:
            q = select(Event).where(Event.processed == 0).order_by(Event.id).limit(BATCH)
            if s.get_bind().dialect.name == "mysql":
                q = q.with_for_update(skip_locked=True)
            events = list(s.scalars(q))
            if not events:
                oldest = None
            else:
                catalog = {c.oid: c for c in s.scalars(select(TrapCatalog))}
                nodes: dict[int, tuple[Node | None, NodeState | None]] = {}
                for ev in events:
                    if ev.node_id is not None and ev.node_id not in nodes:
                        nodes[ev.node_id] = (s.get(Node, ev.node_id), s.get(NodeState, ev.node_id))
                    node, state = nodes.get(ev.node_id, (None, None)) if ev.node_id is not None else (None, None)
                    sp = s.begin_nested()
                    try:
                        self.handle(s, ev, node, state, catalog)
                        ev.processed = 1
                        sp.commit()
                        self.stats.processed += 1
                    except Exception:  # noqa: BLE001 - poison event: record and move on
                        sp.rollback()
                        ev.processed = 2
                        self.stats.failed += 1
                        log.exception("event processing failed; marked processed=2", extra={"event_id": ev.id})
            oldest = s.scalar(select(func.min(Event.ts)).where(Event.processed == 0))
        self.stats.lag_s = round((utcnow() - oldest).total_seconds(), 1) if oldest else 0.0
        self.stats.last_batch_ms = round((time.perf_counter() - t0) * 1000, 1)
        return len(events)

    # ----------------------------------------------------------- one event
    def handle(self, s: Session, ev: Event, node: Node | None, state: NodeState | None, catalog: dict[str, TrapCatalog]) -> None:
        d = decide(s, ev, node, state, catalog)
        if d is None:
            return
        now = utcnow()
        existing = corr.open_alert(s, d.key)
        if d.is_clear:
            if existing is None:
                return
            forced = bool((ev.attributes or {}).get("manual_by"))
            if existing.flapping and not forced and now - existing.last_seen < corr.FLAP_WINDOW:
                existing.clear_pending_at = now  # stop toggling; housekeeping clears after 30 min quiet
                return
            self.clear(s, existing, self._clear_note(ev, d), now)
            return
        if existing is not None:
            self.reoccur(s, existing, ev, d, node, state, catalog, now)
            return
        self.open(s, ev, d, node, state, catalog, now)

    def _clear_note(self, ev: Event, d: Decision) -> str:
        attrs = ev.attributes or {}
        if attrs.get("manual_by"):
            return f"manually resolved by {attrs['manual_by']}"
        if ev.source == "trap":
            vb = attrs.get("vb") or {}
            what = vb.get("extOutput") or vb.get("cppmServiceName") or d.instance  # as CPPM reported it
            return f"{ev.event_type} received{' (' + str(what) + ')' if what else ''}"
        return attrs.get("title") or f"{d.event_type} cleared"

    def open(self, s: Session, ev: Event, d: Decision, node: Node | None, state: NodeState | None,
             catalog: dict[str, TrapCatalog], now: datetime) -> Alert:
        flapping = corr.is_flapping(s, d.key, now)
        sev = bump(d.severity) if flapping else d.severity
        attrs = dict(ev.attributes or {})
        attrs.update(_source=ev.source, _event_type=ev.event_type, _instance=d.instance, _wants_ticket=d.ticket, _event_id=ev.id)
        a = Alert(dedup_key=d.key, open_marker=1, node_id=ev.node_id, rule_id=d.event_type, severity=sev, state="open",
                  flapping=flapping, title=(f"FLAPPING: {d.title}" if flapping else d.title)[:512], first_seen=ev.ts,
                  last_seen=ev.ts, occurrences=1, attributes=attrs)
        s.add(a)
        s.flush()
        parent = corr.node_down_parent(s, ev.node_id, d.event_type)
        if corr.in_maintenance(node, now):
            a.state, a.suppress_reason = "suppressed", "maintenance"
            self.stats.suppressed += 1
            self.sink.alerts_log("suppressed", a, None, now, reason="maintenance")  # type: ignore[attr-defined]
        elif parent is not None:
            self.suppress(s, a, parent, now)
        elif d.ticket:
            self.create_ticket(s, a, ev, node, state, catalog, now)
        else:
            self.sink.alerts_log("opened", a, None, now)  # type: ignore[attr-defined]
        if d.event_type == corr.NODE_DOWN:
            for child in s.scalars(select(Alert).where(Alert.node_id == ev.node_id, Alert.state == "open",
                                                       Alert.rule_id != corr.NODE_DOWN, Alert.id != a.id)):
                self.suppress(s, child, a, now)
        self.stats.opened += 1
        log.info("alert opened", extra={"alert_id": a.id, "key": d.key, "severity": a.severity, "state": a.state})
        return a

    def create_ticket(self, s: Session, a: Alert, ev: Event, node: Node | None, state: NodeState | None,
                      catalog: dict[str, TrapCatalog], now: datetime) -> None:
        try:
            ctx = ticket_context(s, ev, node, state, catalog, now)
            self.sink.create(s, a, ctx, now)
            self.stats.tickets += 1
            if a.flapping and a.ticket_id:
                t = s.get(Ticket, a.ticket_id)
                self.sink.update(s, t, "FLAPPING: more than 3 open/close cycles in 30 min; severity raised, toggling stopped", now, "FLAPPING")
        except OSError as exc:
            self.stats.ticket_failures += 1
            log.critical("ticket file write failed; alert kept, will retry", extra={"alert_id": a.id, "error": str(exc)})

    def suppress(self, s: Session, a: Alert, parent: Alert, now: datetime) -> None:
        a.state, a.suppress_reason, a.parent_alert_id = "suppressed", "node_down", parent.id
        self.stats.suppressed += 1
        ptk = s.get(Ticket, parent.ticket_id) if parent.ticket_id else None
        if ptk is not None:
            self._safe_update(s, ptk, f"related alert suppressed (node down): {a.title}", now, "SUPPRESS")
        if a.ticket_id:
            ctk = s.get(Ticket, a.ticket_id)
            if ctk is not None:
                self._safe_update(s, ctk, f"suppressed under NODE DOWN ticket {ptk.ticket_no if ptk else parent.id}", now, "SUPPRESS")
        self.sink.alerts_log("suppressed", a, ptk.ticket_no if ptk else None, now, reason="node_down")  # type: ignore[attr-defined]

    def reoccur(self, s: Session, a: Alert, ev: Event, d: Decision, node: Node | None, state: NodeState | None,
                catalog: dict[str, TrapCatalog], now: datetime) -> None:
        a.occurrences += 1
        a.last_seen = max(a.last_seen, ev.ts)
        a.clear_pending_at = None
        t = s.get(Ticket, a.ticket_id) if a.ticket_id else None
        if SEV_ORDER.index(d.severity) > SEV_ORDER.index(a.severity):
            old = a.severity
            a.severity = bump(d.severity) if a.flapping else d.severity
            a.title = (f"FLAPPING: {d.title}" if a.flapping else d.title)[:512]
            if t is not None:
                self._safe_update(s, t, f"severity {old} → {a.severity}: {d.title}", now, "ESCALATE")
            elif a.state == "open" and d.ticket:
                self.create_ticket(s, a, ev, node, state, catalog, now)
            self.sink.alerts_log("escalated", a, t.ticket_no if t else None, now, previous=old)  # type: ignore[attr-defined]
        elif t is not None and (a.last_update_note_at is None or now - a.last_update_note_at >= REOCCUR_NOTE_EVERY):
            self._safe_update(s, t, f"re-occurred (occurrence #{a.occurrences})", now, "RE-OCCUR")
            a.last_update_note_at = now
            self.sink.alerts_log("reoccurred", a, t.ticket_no, now)  # type: ignore[attr-defined]
        self.stats.reoccurred += 1

    def clear(self, s: Session, a: Alert, note: str, now: datetime) -> None:
        a.state, a.cleared_at, a.open_marker, a.clear_pending_at = "cleared", now, None, None
        t = s.get(Ticket, a.ticket_id) if a.ticket_id else None
        if t is not None and t.status != "resolved":
            try:
                self.sink.resolve(s, t, note, now)
            except OSError as exc:
                log.error("ticket resolve write failed", extra={"ticket": t.ticket_no, "error": str(exc)})
        self.sink.alerts_log("cleared", a, t.ticket_no if t else None, now, note=note)  # type: ignore[attr-defined]
        self.stats.cleared += 1
        if a.rule_id == corr.NODE_DOWN:  # node back: still-active children become normal alerts
            for c in s.scalars(select(Alert).where(Alert.parent_alert_id == a.id, Alert.state == "suppressed")):
                c.state, c.suppress_reason, c.parent_alert_id = "open", None, None
                if c.ticket_id is None and c.severity in TICKET_SEVERITIES and (c.attributes or {}).get("_wants_ticket"):
                    self._ticket_from_alert(s, c, now)
        log.info("alert cleared", extra={"alert_id": a.id, "key": a.dedup_key})

    def _ticket_from_alert(self, s: Session, a: Alert, now: datetime) -> None:
        attrs = a.attributes or {}
        ev = Event(id=attrs.get("_event_id"), ts=a.first_seen, node_id=a.node_id, source=attrs.get("_source", "poll"),
                   event_type=attrs.get("_event_type", a.rule_id), severity=a.severity, is_clear=False,
                   dedup_instance=attrs.get("_instance", ""), attributes=attrs, raw_ref=None)
        catalog = {c.oid: c for c in s.scalars(select(TrapCatalog))}
        node = s.get(Node, a.node_id) if a.node_id else None
        state = s.get(NodeState, a.node_id) if a.node_id else None
        self.create_ticket(s, a, ev, node, state, catalog, now)
        s.expunge(ev) if ev in s else None

    def _safe_update(self, s: Session, t: Ticket, note: str, now: datetime, action: str) -> None:
        try:
            self.sink.update(s, t, note, now, action)
        except OSError as exc:
            log.error("ticket update write failed", extra={"ticket": t.ticket_no, "error": str(exc)})

    # ----------------------------------------------------------- housekeeping
    def housekeeping(self) -> None:
        """Clear quiet flapping alerts; retry tickets whose file write failed."""
        now = utcnow()
        with session_scope() as s:
            for a in s.scalars(select(Alert).where(Alert.flapping.is_(True), Alert.open_marker == 1,
                                                   Alert.clear_pending_at.is_not(None))):
                if now - a.clear_pending_at >= corr.FLAP_WINDOW and a.last_seen <= a.clear_pending_at:
                    self.clear(s, a, "flapping stopped: no re-occurrence for 30 min after the last clear", now)
            for a in s.scalars(select(Alert).where(Alert.state == "open", Alert.ticket_id.is_(None),
                                                   Alert.severity.in_(TICKET_SEVERITIES))):
                if (a.attributes or {}).get("_wants_ticket"):
                    self._ticket_from_alert(s, a, now)


async def run() -> None:
    """Main loop until SIGTERM."""
    cfg = get_settings()
    sink = FileTicketSink(cfg.tickets_dir, cfg.display_tz, cfg.ticket_assignment_group, cfg.ticket_caller)
    eng = Engine(sink)
    started = utcnow()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    hb = asyncio.create_task(heartbeat_loop(SERVICE, started, lambda: dict(vars(eng.stats))))
    log.info("started", extra={"tickets_dir": str(cfg.tickets_dir)})
    db_ok, last_hk = True, 0.0
    while not stop.is_set():
        try:
            n = await asyncio.to_thread(eng.run_batch)
            if time.monotonic() - last_hk > 60:
                await asyncio.to_thread(eng.housekeeping)
                last_hk = time.monotonic()
            if not db_ok:
                log.info("database recovered")
            db_ok = True
        except SQLAlchemyError as exc:
            if db_ok:
                log.error("database unavailable; retrying", extra={"error": exc.__class__.__name__})
            db_ok, n = False, 0
        if n < BATCH:
            try:
                await asyncio.wait_for(stop.wait(), timeout=2.0)
            except TimeoutError:
                pass
    hb.cancel()
    log.info("stopped", extra=dict(vars(eng.stats)))


def main() -> None:
    """Console entrypoint (systemd ExecStart)."""
    cfg = get_settings()
    setup_logging(SERVICE, cfg.log_dir, cfg.log_level)
    asyncio.run(run())


if __name__ == "__main__":
    main()
