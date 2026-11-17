"""Event → alert decision (DESIGN §2.2, §7): severity overrides, clear pairing, titles, ticket context."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from jinja2 import Environment, StrictUndefined, TemplateError
from sqlalchemy import select
from sqlalchemy.orm import Session

from cppmmon import services as svc
from cppmmon.db.models import Event, Metric, Node, NodeState, ServiceStatus, TrapCatalog
from cppmmon.engine.tickets import TicketContext

log = logging.getLogger(__name__)

SEV_ORDER = ("info", "low", "medium", "high", "critical")
TICKET_SEVERITIES = {"medium", "high", "critical"}  # Low/Info → log only (DESIGN §7.7)
CRITICAL_SERVICE_RE = re.compile(r"radius|tacacs|policy server|db|database|replication", re.I)

# Cluster-wide event types share one alert/ticket per cluster (DESIGN §7.5).
CLUSTER_SCOPED = {"cppmClusterNodeNSyncNotification", "cppmClusterNodeDelNotification", "cppmClusterLicenseOverrun",
                  "cppmClusterLicenseUsage", "cluster.size_drop", "cppmClusterNodePromNotification"}

_jinja = Environment(undefined=StrictUndefined, autoescape=False)
_TAG = re.compile(r"^(\[[^\]]+\])+\s*")

POLL_INFO: dict[str, tuple[str, str, list[str]]] = {
    # event_type: (alarm type, impact, recommended actions)
    "node.down": ("Node Down", "The node is not answering ICMP or SNMP. RADIUS/TACACS requests sent to it will time out; "
                  "NADs fail over to the secondary server if one is configured.",
                  ["Check VM/appliance power and console", "Check the management network path from the monitor",
                   "If the node is up but unreachable, check ACLs/firewall for ICMP and UDP/161"]),
    "node.degraded": ("Management Unreachable", "ICMP answers but SNMP and the REST API do not: monitoring is blind to this node.",
                      ["Check SNMP service (Server Configuration > System Monitor)", "Check the API client and HTTPS reachability"]),
    "node.reboot": ("System Event", "The node restarted; services were unavailable during the reboot.",
                    ["Confirm planned vs unplanned reboot", "Verify all services are running (Services Control)",
                     "Collect logs if unplanned"]),
    "service.down": ("Application Failure", "The service is not running on this node.",
                     ["Administration > Server Manager > Server Configuration > Services Control: start the service",
                      "Check Event Viewer for the reason it stopped", "Escalate per matrix if it fails to start"]),
    "cluster.replication": ("Replication Failure", "This subscriber is not replicating from the publisher; configuration changes "
                            "will not reach it.", ["Check publisher<->subscriber reachability (TCP 443/5432) and time sync",
                                                   "Check replication status in Server Manager"]),
    "cluster.size_drop": ("Cluster Event", "A node has left the cluster.", ["Confirm whether the change was planned",
                                                                            "Check the missing node's health"]),
    "cluster.role_change": ("Cluster Event", "Publisher role moved; configuration changes now go to a different node.",
                            ["Verify the publisher failover cause", "Check the original publisher's health"]),
    "monitor.disk_low": ("Monitoring Platform", "The monitor VM's disk is filling; if it fills, MySQL stops and "
                         "traps/syslog are only spooled.", ["Check table sizes and syslog volume (Runbook § Troubleshooting)",
                                                            "Extend the VM disk or shorten retention (CPPMMON_RETAIN_*_DAYS)"]),
    "api.auth_failed": ("Monitoring Credentials", "REST-based KPIs (services, certificates, licenses) are not being collected.",
                        ["Check the API client in Guest > Administration > API Services", "Update the node credentials in the monitor"]),
}
THRESHOLD_INFO: dict[str, tuple[str, str, list[str]]] = {
    "cpu": ("Resource Threshold", "Sustained high CPU slows authentications and can cause RADIUS timeouts.",
            ["Check auth rate spike, Insight/report jobs, and per-service CPU in System Monitor"]),
    "mem": ("Resource Threshold", "Memory pressure can make services restart or slow down.",
            ["Check System Monitor for the consuming service", "Plan a restart in a maintenance window if it persists"]),
    "disk": ("Storage Threshold", "A full disk stops logging and database writes.",
             ["Run log cleanup (Cleanup Intervals)", "Review Insight DB size and Access Tracker retention"]),
    "disk_mount": ("Storage Threshold", "A full filesystem stops logging and database writes.", ["Free space on the mount"]),
    "auth_fail": ("Authentication Failure Rate", "A high share of authentications is failing.",
                  ["Check Access Tracker for the dominant failure reason", "Check AD/LDAP and certificate health"]),
    "auth_src_fail": ("Auth Source Failure", "An authentication source (AD/LDAP/SQL) is failing requests.",
                      ["Check reachability and credentials of the auth source", "Check the source's service account"]),
    "license": ("License Alert", "License usage is near or at the limit; new authentications may be blocked.",
                ["Add licenses or reduce consumption"]),
    "cert": ("Security Alert", "An expired or expiring server certificate breaks HTTPS, EAP or RadSec.",
             ["Renew the certificate (Certificates > Server Certificate)", "Update trust on NADs/supplicants if the CA changes"]),
    "trust_cert": ("Security Alert", "A trusted CA in the trust list is expired or expiring.",
                   ["Replace or disable the expired CA entry (Certificates > Trust List)"]),
    "if_errors": ("Interface Errors", "Interface errors/discards indicate a link or duplex problem.",
                  ["Check the switch port, cabling and duplex settings"]),
}


@dataclass
class Decision:
    key: str
    event_type: str  # alert rule_id (for clears: the event type being cleared)
    severity: str
    title: str
    is_clear: bool
    ticket: bool
    instance: str
    cluster_scoped: bool


def bump(sev: str) -> str:
    """Severity + 1 (flap guard)."""
    i = SEV_ORDER.index(sev) if sev in SEV_ORDER else 2
    return SEV_ORDER[min(i + 1, len(SEV_ORDER) - 1)]


def _render(tpl: str | None, node: Node | None, vb: dict[str, Any], fallback: str) -> str:
    if not tpl:
        return fallback
    try:
        return _jinja.from_string(tpl).render(node={"name": node.name if node else "unregistered", "ip": node.ip if node else "",
                                                    "role": node.role if node else ""}, vb=_VB(vb))
    except TemplateError as exc:
        log.warning("title template failed; using fallback", extra={"error": str(exc)[:120]})
        return fallback


class _VB(dict):
    """vb.<name> lookups that render missing varbinds as '?' instead of failing the whole title."""

    def __getattr__(self, name: str) -> Any:
        return self.get(name, "?")


def tag(sev: str, text: str) -> str:
    """Normalise the [CPPM][SEV] prefix to the effective severity."""
    return f"[CPPM][{sev.upper()}] {_TAG.sub('', text).strip()}"


def decide(s: Session, ev: Event, node: Node | None, state: NodeState | None,
           catalog: dict[str, TrapCatalog]) -> Decision | None:
    """Map one event to an alert decision, or None for log-only events."""
    attrs = ev.attributes or {}
    vb: dict[str, Any] = attrs.get("vb") or {}
    sev = ev.severity
    etype = attrs.get("clears") if ev.is_clear and attrs.get("clears") else ev.event_type
    instance = ev.dedup_instance or ""
    ticket = sev in TICKET_SEVERITIES

    if ev.source == "trap":
        entry = catalog.get(attrs.get("trap_oid", ""))
        if ev.event_type == "UNKNOWN_TRAP":
            return None  # stored + visible in Live Traps; info, no alert (DESIGN §2.2)
        if ev.event_type in WATCHDOG_TRAPS:
            return _watchdog(ev, node, state, vb)
        if ev.event_type in SERVICE_TRAPS:  # 1017 stop / 1018 start / 1019 restart → shared service.down key
            inst = svc.canonical(str(vb.get("cppmServiceName", "")))
            if ev.is_clear:
                title = f"Service '{vb.get('cppmServiceName', '?')}' {'restarted' if '1019' in attrs.get('trap_oid', '') else 'started'}"
                return Decision(_key(ev, svc.SERVICE_DOWN, inst, state), svc.SERVICE_DOWN, "info", title, True, False, inst, False)
            sev = "high" if svc.is_critical(str(vb.get("cppmServiceName", ""))) else "medium"
            title = tag(sev, str(vb.get("cppmTrapMessage") or "") + (f" on {node.name}" if node and vb.get("cppmTrapMessage") else "")
                        or _render(entry.title_tpl if entry else None, node, vb, ev.event_type))
            return Decision(_key(ev, svc.SERVICE_DOWN, inst, state), svc.SERVICE_DOWN, sev, title, False, True, inst, False)
        if ev.is_clear:
            parent = next((c for c in catalog.values() if c.name == etype), None)
            title = _render(parent.title_tpl if parent else None, node, vb, etype)
            return Decision(_key(ev, etype, instance, state), etype, "info", title, True, False, instance, etype in CLUSTER_SCOPED)
        if entry is None:
            return None
        ticket = bool(entry.create_ticket)
        # Severity overrides (DESIGN §2.2)
        if ev.event_type == "cppmNodeCertExpiry":
            try:
                if int(vb.get("cppmCertDaysRemaining", 999)) <= 7:
                    sev = "high"
            except (TypeError, ValueError):
                pass
        elif ev.event_type in ("cppmUpdateNotification", "cppmUpgradeNotification"):
            status = str(vb.get("cppmImageInstallStatus", "")).lower()
            if status and "success" not in status:
                sev, ticket = "medium", True
        elif ev.event_type == "cppmClusterLicenseUsage":
            try:
                ratio = float(vb.get("cppmClusterLicenseUsageCount", 0)) / float(vb.get("cppmClusterLicenseTotalCount", 0))
            except (TypeError, ValueError, ZeroDivisionError):
                ratio = 0.0
            if ratio >= 0.90:
                sev, ticket = "medium", True
            elif ratio < 0.85:
                title = f"License usage {ratio:.0%} for {vb.get('cppmNodeApplicationName', '?')}"
                return Decision(_key(ev, etype, instance, state), etype, "info", title, True, False, instance, True)
            else:
                return None
        if sev not in TICKET_SEVERITIES:
            return None  # info/low traps: log only
        title = tag(sev, _render(entry.title_tpl, node, vb, entry.name))
        return Decision(_key(ev, etype, instance, state), etype, sev, title, False, ticket and sev in TICKET_SEVERITIES,
                        instance, etype in CLUSTER_SCOPED)

    # poll / internal
    title = attrs.get("title") or f"{etype} {instance}".strip()
    if ev.is_clear:
        return Decision(_key(ev, etype, instance, state), etype, "info", title, True, False, instance, etype in CLUSTER_SCOPED)
    if sev not in TICKET_SEVERITIES:
        return None
    return Decision(_key(ev, etype, instance, state), etype, sev, tag(sev, title), False, True, instance, etype in CLUSTER_SCOPED)


WATCHDOG_TRAPS = {"mteTriggerFired", "mteTriggerRising", "mteTriggerFalling"}
SERVICE_TRAPS = {"cppmServiceStopNotification", "cppmServiceStartNotification", "cppmServiceRestartNotification"}
_WD_FAIL = re.compile(r"\b(is stopped|stopped|inactive|dead|failed|not running|error)\b", re.I)
_WD_OK = re.compile(r"\b(is running|active \(running\))\b", re.I)


def watchdog_failing(vb: dict[str, Any]) -> bool:
    """Classify a CPPM watchdog trap by its content, not its Rising/Falling direction."""
    text = " ".join(str(vb.get(k) or "") for k in ("extOutput", "memSwapErrorMsg", "dskErrorMsg", "laErrMessage", "prErrMessage"))
    if _WD_FAIL.search(text):
        return True
    if _WD_OK.search(text):
        return False
    for flag in ("extResult", "memSwapError", "dskErrorFlag", "laErrorFlag", "prErrorFlag", "mteHotValue"):
        v = vb.get(flag)
        if v not in (None, ""):
            try:
                return int(v) != 0
            except (TypeError, ValueError):
                continue
    return False


def _watchdog(ev: Event, node: Node | None, state: NodeState | None, vb: dict[str, Any]) -> Decision:
    """CPPM watchdog trap → service.down open/clear (extTable) or watchdog.<trigger> for memory/disk/load."""
    failing = watchdog_failing(vb)
    trigger = str(vb.get("mteHotTrigger") or "check")
    where = f" on {node.name}" if node else ""
    if vb.get("extNames") or vb.get("extOutput"):
        inst, label = svc.from_watchdog(str(vb.get("extOutput") or ""), str(vb.get("extNames") or ""))
        etype = svc.SERVICE_DOWN
        sev = "high" if svc.is_critical(label, inst, str(vb.get("extNames") or "")) else "medium"
        title = f"{vb.get('extOutput') or label}{where}"
    else:
        inst = str(vb.get("memErrorName") or vb.get("dskPath") or vb.get("laNames") or vb.get("prNames") or trigger)[:128]
        etype = f"watchdog.{trigger}"[:64]
        sev = "medium"
        msg = vb.get("memSwapErrorMsg") or vb.get("dskErrorMsg") or vb.get("laErrMessage") or vb.get("prErrMessage")
        title = f"CPPM watchdog {trigger} {inst}: {msg or ('failing' if failing else 'OK')}{where}"
    if not failing:
        return Decision(_key(ev, etype, inst, state), etype, "info", title, True, False, inst, False)
    return Decision(_key(ev, etype, inst, state), etype, sev, tag(sev, title), False, True, inst, False)


def _key(ev: Event, etype: str, instance: str, state: NodeState | None) -> str:
    """Dedup key = node|event_type|instance; cluster-wide types key on the cluster (publisher UUID)."""
    scope = str(ev.node_id)
    if etype in CLUSTER_SCOPED and state is not None and state.cluster_uuid:
        scope = f"cluster:{state.cluster_uuid}"
    return f"{scope}|{etype}|{instance}"[:255]


def ticket_context(s: Session, ev: Event, node: Node | None, state: NodeState | None,
                   catalog: dict[str, TrapCatalog], now: datetime) -> TicketContext:
    """Description/evidence/recommendations for a new ticket."""
    attrs = ev.attributes or {}
    vb: dict[str, Any] = attrs.get("vb") or {}
    if ev.source == "trap":
        entry = catalog.get(attrs.get("trap_oid", ""))
        alarm = (entry.alarm_type if entry else None) or "SNMP Trap"
        source = f"SNMP Trap ({ev.event_type}, .{attrs.get('trap_oid', '?')})"
        recommended = _split_actions(entry.recommended_action if entry else None)
        impact = None
        if ev.event_type == "cppmServiceStopNotification":
            svc = str(vb.get("cppmServiceName", "the service"))
            impact = (f"{svc} on this node is stopped. Requests that depend on it will fail; NADs fail over to the "
                      "secondary server if one is configured.")
        evidence = [f"{ev.raw_ref.replace('trap:', 'raw_trap_id=') if ev.raw_ref else 'raw_trap_id=?'}  "
                    f"varbinds={_compact(vb)}"]
    else:
        rule = attrs.get("rule_id")
        if ev.event_type.startswith("threshold.") and rule in THRESHOLD_INFO:
            alarm, impact, recommended = THRESHOLD_INFO[rule]
            source = f"Poll (threshold {attrs.get('metric')} {attrs.get('op')} {attrs.get('threshold')}{attrs.get('unit', '')})"
            evidence = [f"value={attrs.get('value')}{attrs.get('unit', '')}  level={attrs.get('level')}  instance={ev.dedup_instance or '-'}"]
        else:
            alarm, impact, recommended = POLL_INFO.get(ev.event_type, ("Monitoring Event", None, []))
            source = f"Poll ({ev.event_type})"
            evidence = [f"event_id={ev.id}  attributes={_compact({k: v for k, v in attrs.items() if k != 'title'})}"]
    evidence.append(last_poll_line(s, ev.node_id, now))
    return TicketContext(node=node, state=state, alarm_type=alarm, source=source,
                         service=str(vb.get("cppmServiceName")) if vb.get("cppmServiceName") else (attrs.get("service")),
                         trap_message=str(vb["cppmTrapMessage"]) if vb.get("cppmTrapMessage") else None,
                         impact=impact, evidence=evidence, recommended=list(recommended))


def last_poll_line(s: Session, node_id: int | None, now: datetime) -> str:
    """'Last poll: CPU 12% | Mem 61% | Disk 40% | Services: radius=RUNNING tacacs=RUNNING'."""
    if node_id is None:
        return "Last poll: n/a (unregistered sender)"
    vals: dict[str, float] = {}
    for m, v in s.execute(select(Metric.metric, Metric.value).where(
            Metric.node_id == node_id, Metric.metric.in_(("cpu_pct", "mem_pct", "disk_pct")),
            Metric.ts >= now - timedelta(minutes=15)).order_by(Metric.ts.desc())).all():
        vals.setdefault(m, v)
    parts = [f"{label} {vals[k]:.0f}%" if k in vals else f"{label} n/a" for k, label in
             (("cpu_pct", "CPU"), ("mem_pct", "Mem"), ("disk_pct", "Disk"))]
    svc = {x.service_name: x.status for x in s.scalars(select(ServiceStatus).where(ServiceStatus.node_id == node_id))}
    keys = (("radius", "Radius server"), ("tacacs", "TACACS+ server"), ("policy", "Policy server"))
    svc_txt = " ".join(f"{short}={(svc.get(full) or 'n/a').upper()}" for short, full in keys)
    return f"Last poll: {' | '.join(parts)} | Services: {svc_txt}"


def _split_actions(text: str | None) -> list[str]:
    if not text:
        return []
    parts = [p.strip() for p in re.split(r";\s*|\n+", text) if p.strip()]
    return [p[0].upper() + p[1:] for p in parts] or [text]


def _compact(d: dict[str, Any], limit: int = 600) -> str:
    txt = "{" + ", ".join(f"{k}={v}" for k, v in d.items()) + "}"
    return txt if len(txt) <= limit else txt[: limit - 1] + "…"
