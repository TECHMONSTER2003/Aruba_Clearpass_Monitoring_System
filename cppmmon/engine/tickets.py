"""Ticket sinks (ADR-005, DESIGN §8). ``FileTicketSink`` writes ServiceNow-ready .txt tickets.

* Path: tickets/YYYY/MM/DD/CPPM-YYYYMMDD-NNNN.txt; NNNN is a daily sequence held in
  the DB (``ticket_seq``), never a filesystem count.
* Updates/resolutions are appended to the UPDATES block of the same file.
* Every write is atomic (``*.tmp`` → fsync → rename); every lifecycle change also
  appends one JSON line to tickets/alerts.log.
"""
from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from cppmmon.db.models import Alert, Node, NodeState, Ticket, TicketSequence

log = logging.getLogger(__name__)

RULE = "=" * 64
SUB = "-" * 64
PRIORITY = {
    "critical": ("P1 - Critical", "1 / 1"),
    "high": ("P2 - High", "2 / 2"),
    "medium": ("P3 - Moderate", "3 / 3"),
}


@dataclass
class TicketContext:
    """Everything the ticket body needs beyond the alert row."""

    node: Node | None
    state: NodeState | None
    alarm_type: str
    source: str
    service: str | None = None
    trap_message: str | None = None
    impact: str | None = None
    evidence: list[str] = field(default_factory=list)
    recommended: list[str] = field(default_factory=list)


class TicketSink(ABC):
    """Destination for incident tickets. FileTicketSink now, ServiceNowSink later (same calls)."""

    @abstractmethod
    def create(self, s: Session, alert: Alert, ctx: TicketContext, now: datetime) -> Ticket: ...

    @abstractmethod
    def update(self, s: Session, ticket: Ticket, note: str, now: datetime, action: str = "UPDATE") -> None: ...

    @abstractmethod
    def resolve(self, s: Session, ticket: Ticket, note: str, now: datetime) -> None: ...


def atomic_write(path: Path, text: str) -> None:
    """Write via tmp + fsync + rename so readers never see a partial ticket."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class FileTicketSink(TicketSink):
    def __init__(self, root: Path, tz: str = "Asia/Kolkata", assignment_group: str = "Network Operations",
                 caller: str = "CPPM-Monitor (automation)") -> None:
        self.root = root
        self.tz = ZoneInfo(tz)
        self.tz_label = "IST" if tz == "Asia/Kolkata" else tz
        self.group = assignment_group
        self.caller = caller

    # ------------------------------------------------------------ helpers
    def _local(self, dt: datetime) -> str:
        return dt.replace(tzinfo=timezone.utc).astimezone(self.tz).strftime(f"%Y-%m-%d %H:%M:%S {self.tz_label}")

    def _next_number(self, s: Session, now: datetime) -> str:
        day = now.replace(tzinfo=timezone.utc).astimezone(self.tz).strftime("%Y%m%d")
        seq = s.execute(select(TicketSequence).where(TicketSequence.day == day).with_for_update()).scalar_one_or_none()
        if seq is None:
            seq = TicketSequence(day=day, last_seq=0)
            s.add(seq)
        seq.last_seq += 1
        s.flush()
        return f"CPPM-{day}-{seq.last_seq:04d}"

    def alerts_log(self, action: str, alert: Alert, ticket_no: str | None, now: datetime, **extra: Any) -> None:
        """Append one JSON line per lifecycle change (grep-friendly audit trail)."""
        self.root.mkdir(parents=True, exist_ok=True)
        rec = {"ts": now.replace(tzinfo=timezone.utc).isoformat(timespec="seconds"), "action": action, "alert_id": alert.id,
               "ticket": ticket_no, "dedup_key": alert.dedup_key, "node_id": alert.node_id, "severity": alert.severity,
               "state": alert.state, "occurrences": alert.occurrences, "title": alert.title, **extra}
        with (self.root / "alerts.log").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")

    def render(self, ticket_no: str, alert: Alert, ctx: TicketContext, now: datetime) -> str:
        """Ticket body exactly in the DESIGN §8 layout."""
        prio, impact_urgency = PRIORITY.get(alert.severity, ("P4 - Low", "4 / 4"))
        n, st = ctx.node, ctx.state
        ci = "unknown node"
        if n is not None:
            role = (n.role or "unknown").capitalize()
            ci = f"{n.name} ({n.ip}) | {role} | {(st.version if st and st.version else 'version ?')} | SN: {(st.serial if st and st.serial else 'n/a')}"
        lines = [
            RULE,
            f"TICKET      : {ticket_no}",
            f"CREATED     : {self._local(now)}",
            "STATUS      : NEW",
            SUB,
            f"Caller              : {self.caller}",
            "Category            : Network",
            "Subcategory         : AAA/NAC",
            f"Configuration Item  : {ci}",
            f"Assignment Group    : {self.group}",
            f"Impact / Urgency    : {impact_urgency}",
            f"Priority            : {prio}",
            f"Short Description   : {alert.title}",
            SUB,
            "Description:",
            f"  Alarm Type     : {ctx.alarm_type}",
            f"  Source         : {ctx.source}",
            f"  First Seen     : {self._local(alert.first_seen)}",
            f"  Node           : {(n.name + ' / ' + n.ip) if n else 'unregistered'}",
        ]
        if ctx.service:
            lines.append(f"  Service        : {ctx.service}")
        if ctx.trap_message:
            lines.append(f"  Trap Message   : {ctx.trap_message}")
        if ctx.impact:
            first, *rest = _wrap(ctx.impact, 62)
            lines.append(f"  Impact         : {first}")
            lines.extend(f"                   {r}" for r in rest)
        lines.append("Evidence:")
        lines.extend(f"  {e}" for e in (ctx.evidence or ["(none)"]))
        lines.append("Recommended Action:")
        lines.extend(f"  {i}. {a}" for i, a in enumerate(ctx.recommended or ["Investigate on the CPPM and escalate per matrix."], 1))
        lines += [SUB, "UPDATES:", RULE]
        return "\n".join(lines) + "\n"

    def _append(self, path: Path, line: str, status: str | None = None) -> None:
        text = path.read_text(encoding="utf-8")
        body, sep, _tail = text.rstrip("\n").rpartition("\n" + RULE)
        if not sep:  # unexpected layout: append at the end, never lose the update
            body = text.rstrip("\n")
        if status:
            body = body.replace("STATUS      : NEW", f"STATUS      : {status}", 1)
        atomic_write(path, f"{body}\n  {line}\n{RULE}\n")

    # ------------------------------------------------------------ TicketSink
    def create(self, s: Session, alert: Alert, ctx: TicketContext, now: datetime) -> Ticket:
        no = self._next_number(s, now)
        day = no.split("-")[1]
        path = self.root / day[:4] / day[4:6] / day[6:8] / f"{no}.txt"
        atomic_write(path, self.render(no, alert, ctx, now))
        t = Ticket(ticket_no=no, alert_id=alert.id, created_at=now, priority=PRIORITY.get(alert.severity, ("P4",))[0][:16],
                   short_description=alert.title[:512], file_path=str(path), status="new")
        s.add(t)
        s.flush()
        alert.ticket_id = t.id
        self.alerts_log("opened", alert, no, now)
        log.info("ticket created", extra={"ticket": no, "alert_id": alert.id, "severity": alert.severity})
        return t

    def update(self, s: Session, ticket: Ticket, note: str, now: datetime, action: str = "UPDATE") -> None:
        self._append(Path(ticket.file_path), f"{self._local(now)[:19]}  {action:<9} {note}")

    def resolve(self, s: Session, ticket: Ticket, note: str, now: datetime) -> None:
        self._append(Path(ticket.file_path), f"{self._local(now)[:19]}  RESOLVED  {note}", status="RESOLVED")
        ticket.status = "resolved"
        ticket.resolved_at = now
        log.info("ticket resolved", extra={"ticket": ticket.ticket_no})


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    return lines + ([cur] if cur else []) or [""]
