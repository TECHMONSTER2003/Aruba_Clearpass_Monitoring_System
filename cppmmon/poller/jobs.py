"""Poll jobs per node (DESIGN §3, §4.3). Each job returns a JobResult; the scheduler persists it.

Intervals (2026-11-17): ICMP 30 s · SNMP system 60 s · SNMP auth sources 5 min · SNMP disk+if 5 min ·
REST services 15 min (backstop: CPPM's 1017/watchdog traps are primary) · REST endpoints 15 min ·
inventory 1 h · REST certs (RADIUS + HTTPS(RSA) only) / licenses 6 h. "Poll now" runs all of them at once.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cppmmon import services as svc
from cppmmon.collectors import cppm_api as capi
from cppmmon.collectors import cppm_snmp as csnmp
from cppmmon.collectors.icmp import ping
from cppmmon.collectors.snmp_client import SnmpClient, SnmpError
from cppmmon.collectors.types import ApiParams, SnmpParams
from cppmmon.db.session import utcnow
from cppmmon.poller.deltas import Delta, counter_delta, cpu_percent
from cppmmon.poller.store import JobResult
from cppmmon.poller.thresholds import MIN_AUTH_VOLUME, Evaluator

log = logging.getLogger(__name__)

DOWN_AFTER = 3  # consecutive failed cycles (ICMP AND SNMP) before NODE DOWN
CRITICAL_SERVICES = ("radius server", "tacacs+ server", "policy server", "db replication service", "async db write service")


@dataclass
class NodeRT:
    """Mutable runtime state for one polled node (credentials decrypted in memory only)."""

    id: int
    name: str
    ip: str
    snmp: SnmpParams
    api: ApiParams | None
    status: str = "unknown"
    sys_index: int | None = None
    policy_index: int = 0
    server_uuid: str | None = None
    icmp_fail: int = 0
    snmp_fail: int = 0
    snmp_ok: bool | None = None  # None until the first SNMP poll completes (success or failure)
    api_fail: int = 0
    api_state: str | None = None
    uptime_s: int | None = None
    cluster_size: int | None = None
    cpu_prev: dict[str, float | None] | None = None
    services_prev: dict[str, bool] = field(default_factory=dict)
    replication_ok: bool | None = None
    is_publisher: bool | None = None
    unsupported: set[str] = field(default_factory=set)


@dataclass
class Ctx:
    counters: dict[tuple[int, str, str], tuple[float, datetime]]
    evaluator: Evaluator
    snmp_sem: asyncio.Semaphore
    api_sem: asyncio.Semaphore


def _event(rt: NodeRT, now: datetime, etype: str, sev: str, title: str, instance: str = "", clear: bool = False,
           **attrs: Any) -> dict[str, Any]:
    return {"ts": now, "node_id": rt.id, "source": "poll", "event_type": etype, "severity": sev, "is_clear": clear,
            "dedup_instance": instance[:128], "processed": 0, "attributes": {"title": title, **attrs}}


def _delta(ctx: Ctx, res: JobResult, rt: NodeRT, metric: str, instance: str, cur: Any, now: datetime,
           kind: str = "reset", rebooted: bool = False) -> Delta:
    if cur is None:
        return Delta(None, 0.0)
    key = (rt.id, metric, instance)
    prev = ctx.counters.get(key)
    d = counter_delta(prev[0] if prev else None, prev[1] if prev else None, float(cur), now, kind, rebooted)  # type: ignore[arg-type]
    ctx.counters[key] = (float(cur), now)
    res.counters.append({"node_id": rt.id, "metric": metric, "instance": instance, "last_value": int(cur), "last_ts": now})
    return d


def _thresholds(ctx: Ctx, res: JobResult, rt: NodeRT, metric: str, value: float | None, now: datetime, instance: str = "") -> None:
    res.events.extend(ctx.evaluator.evaluate(rt.id, rt.name, metric, instance, value, now))


def update_status(rt: NodeRT, res: JobResult, now: datetime) -> None:
    """Multi-signal status (DESIGN §3): DOWN only if ICMP AND SNMP fail 3 consecutive cycles."""
    prev = rt.status
    if rt.icmp_fail >= DOWN_AFTER and rt.snmp_fail >= DOWN_AFTER:
        new = "down"
    elif rt.snmp_fail >= DOWN_AFTER and rt.icmp_fail == 0 and (rt.api is None or rt.api_fail >= 1):
        new = "degraded"
    elif rt.snmp_ok is True:  # only a completed, successful SNMP poll proves "up"
        new = "up"
    else:
        new = prev
    if new == prev:
        return
    rt.status = new
    res.state["status"] = new
    if new == "down":
        res.events.append(_event(rt, now, "node.down", "critical",
                                 f"[CPPM][CRITICAL] NODE DOWN: {rt.name} ({rt.ip}) — no ICMP and no SNMP for {DOWN_AFTER} cycles",
                                 icmp_fail=rt.icmp_fail, snmp_fail=rt.snmp_fail))
    if prev == "down":
        res.events.append(_event(rt, now, "node.down", "info", f"{rt.name} reachable again (status {new})", clear=True))
    if new == "degraded":
        res.events.append(_event(rt, now, "node.degraded", "medium",
                                 f"[CPPM][MEDIUM] Management unreachable on {rt.name}: ICMP OK but SNMP and API failing",
                                 snmp_fail=rt.snmp_fail, api_fail=rt.api_fail))
    if prev == "degraded":
        res.events.append(_event(rt, now, "node.degraded", "info", f"{rt.name} management reachable again", clear=True))
    log.info("node status changed", extra={"node_id": rt.id, "from": prev, "to": new})


# ------------------------------------------------------------------- ICMP

async def job_icmp(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    r = await ping(rt.ip, count=3, timeout_s=2.0)
    if r.ok:
        rt.icmp_fail = 0
        res.metric(rt.id, now, "icmp_rtt_ms", r.latency_ms)
        res.state["last_icmp_ok"] = now
    else:
        rt.icmp_fail += 1
    res.metric(rt.id, now, "icmp_loss_pct", r.details.get("loss_pct", 100.0) if r.details else 100.0)
    update_status(rt, res, now)
    return res


# ------------------------------------------------------------------- SNMP

async def job_snmp_system(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    try:
        async with ctx.snmp_sem, SnmpClient(rt.snmp) as c:
            if rt.sys_index is None:
                rt.sys_index = await csnmp.discover_index(c)
                if rt.sys_index is None:
                    raise SnmpError("cppmSystemTable has no instances", "error")
            d = await csnmp.poll_system(c, rt.sys_index, rt.policy_index)
            if d.get("daily_total") is None and rt.policy_index == 0:
                idx = await csnmp.find_policy_index(c)
                if idx is not None and idx != 0:
                    rt.policy_index = idx
    except SnmpError as exc:
        rt.snmp_fail += 1
        rt.snmp_ok = False
        log.warning("snmp system poll failed", extra={"node_id": rt.id, "kind": exc.kind, "error": str(exc)[:160], "streak": rt.snmp_fail})
        update_status(rt, res, now)
        return res
    rt.snmp_fail = 0
    rt.snmp_ok = True
    res.state.update(last_snmp_ok=now, sys_index=rt.sys_index)
    for k in ("hostname", "version", "model", "serial", "node_type"):
        if d.get(k):
            res.state[k] = str(d[k])[:255]

    # Uptime / reboot: cppmSystemUptime (col 17, seconds), NOT sysUpTime (agent restarts reset it).
    rebooted = False
    up = d.get("uptime")
    if up is not None:
        up = int(up)
        if rt.uptime_s is not None and up + 120 < rt.uptime_s:
            rebooted = True
            res.events.append(_event(rt, now, "node.reboot", "high",
                                     f"[CPPM][HIGH] Reboot detected on {rt.name}: uptime dropped from {rt.uptime_s}s to {up}s",
                                     previous_uptime_s=rt.uptime_s, uptime_s=up))
        rt.uptime_s = up
        res.state["uptime_s"] = up
        res.metric(rt.id, now, "uptime_s", up)

    # Cluster size (cppmNumClusterNodes): a drop means a node left.
    cs = d.get("cluster_size")
    if cs is not None:
        cs = int(cs)
        if rt.cluster_size is not None and cs < rt.cluster_size:
            res.events.append(_event(rt, now, "cluster.size_drop", "high",
                                     f"[CPPM][HIGH] Cluster node count dropped {rt.cluster_size} → {cs} (seen by {rt.name})",
                                     previous=rt.cluster_size, current=cs))
        elif rt.cluster_size is not None and cs > rt.cluster_size:
            res.events.append(_event(rt, now, "cluster.size_drop", "info", f"Cluster node count back to {cs}", clear=True))
        rt.cluster_size = cs
        res.state["cluster_size"] = cs

    # CPU from UCD raw ticks (first poll only stores state).
    ticks = {k.removeprefix("cpu_"): (float(v) if v is not None else None) for k, v in d.items() if k.startswith("cpu_")}
    if rt.cpu_prev is not None and not rebooted:
        cpu = cpu_percent(rt.cpu_prev, ticks)
        res.metric(rt.id, now, "cpu_pct", cpu)
        _thresholds(ctx, res, rt, "cpu_pct", cpu, now)
    rt.cpu_prev = ticks

    # Memory: UCD (KB). memAvailReal on CPPM is *free*, so used = total - free - buffers - cached.
    tot, free, buf, cached = (d.get(k) for k in ("total_kb", "avail_kb", "buffer_kb", "cached_kb"))
    mem_pct = None
    if tot and free is not None:
        used_kb = float(tot) - float(free) - float(buf or 0) - float(cached or 0)
        mem_pct = 100.0 * used_kb / float(tot)
        res.metric(rt.id, now, "mem_used_b", used_kb * 1024)
    elif d.get("mem_total_b") and d.get("mem_free_b") is not None:  # fallback: CPPM-MIB free (includes cache on 6.14)
        mem_pct = 100.0 * (1 - float(d["mem_free_b"]) / float(d["mem_total_b"]))
        res.metric(rt.id, now, "mem_source_cppm_free", 1)
    res.metric(rt.id, now, "mem_pct", mem_pct)
    _thresholds(ctx, res, rt, "mem_pct", mem_pct, now)

    # Disk: CPPM-MIB totals (bytes) cover all CPPM partitions.
    if d.get("disk_total_b") and d.get("disk_free_b") is not None:
        disk = 100.0 * (1 - float(d["disk_free_b"]) / float(d["disk_total_b"]))
        res.metric(rt.id, now, "disk_pct", disk)
        _thresholds(ctx, res, rt, "disk_pct", disk, now)
    for k in ("load1", "load5", "load15"):
        res.metric(rt.id, now, k, d.get(k))

    # Authentications: daily counters reset at 00:00 → negative delta = reset (delta = new value).
    dt = _delta(ctx, res, rt, "daily_total", "", d.get("daily_total"), now, "reset", rebooted)
    df = _delta(ctx, res, rt, "daily_failed", "", d.get("daily_failed"), now, "reset", rebooted)
    _delta(ctx, res, rt, "daily_success", "", d.get("daily_success"), now, "reset", rebooted)
    if dt.value is not None:
        res.metric(rt.id, now, "auth_per_min", dt.per_minute())
        res.metric(rt.id, now, "auth_fail_per_min", df.per_minute())
        if dt.value >= MIN_AUTH_VOLUME and df.value is not None:
            fail_pct = 100.0 * df.value / dt.value
            res.metric(rt.id, now, "auth_fail_pct", fail_pct)
            _thresholds(ctx, res, rt, "auth_fail_pct", fail_pct, now)
        elif dt.value is not None:
            _thresholds(ctx, res, rt, "auth_fail_pct", 0.0, now)  # low volume counts as healthy (allows clears)
    if d.get("daily_total"):
        res.metric(rt.id, now, "auth_success_pct_today", 100.0 * float(d.get("daily_success") or 0) / float(d["daily_total"]))
    update_status(rt, res, now)
    return res


async def job_snmp_auth(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    try:
        async with ctx.snmp_sem, SnmpClient(rt.snmp) as c:
            sources = await csnmp.poll_auth_sources(c)
    except SnmpError as exc:
        log.warning("snmp auth-source poll failed", extra={"node_id": rt.id, "error": str(exc)[:160]})
        return res
    for name, vals in sources.items():
        inst = name[:128]
        fail = _delta(ctx, res, rt, "src_failure", inst, vals.get("src_failure"), now)
        tot = _delta(ctx, res, rt, "src_total", inst, vals.get("src_total"), now)
        if tot.value is not None:
            res.metric(rt.id, now, "auth_src_req_per_min", tot.per_minute(), inst)
        if fail.value is not None:
            fpm = fail.per_minute()
            res.metric(rt.id, now, "auth_src_fail_per_min", fpm, inst)
            _thresholds(ctx, res, rt, "auth_src_fail_per_min", fpm, now, inst)
    return res


async def job_snmp_storage_if(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    try:
        async with ctx.snmp_sem, SnmpClient(rt.snmp) as c:
            storage = await csnmp.poll_storage(c)
            ifaces = await csnmp.poll_interfaces(c)
    except SnmpError as exc:
        log.warning("snmp storage/if poll failed", extra={"node_id": rt.id, "error": str(exc)[:160]})
        return res
    for mount, v in storage.items():
        res.metric(rt.id, now, "disk_mount_pct", v["pct"], mount)
        _thresholds(ctx, res, rt, "disk_mount_pct", v["pct"], now, mount)
    for ifname, v in ifaces.items():
        res.metric(rt.id, now, "if_oper_up", 1.0 if v.get("oper") == 1 else 0.0, ifname)
        for direction in ("in", "out"):
            d = _delta(ctx, res, rt, f"if_{direction}_octets", ifname, v.get(f"{direction}_octets"), now, "wrap32")
            if d.value is not None and d.seconds > 0:
                res.metric(rt.id, now, f"if_{direction}_bps", d.value * 8 / d.seconds, ifname)
        err_total = 0.0
        have = False
        for k in ("in_errors", "out_errors", "in_discards", "out_discards"):
            d = _delta(ctx, res, rt, f"if_{k}", ifname, v.get(k), now, "wrap32")
            if d.value is not None:
                err_total += d.per_minute() or 0.0
                have = True
        if have:
            res.metric(rt.id, now, "if_errors_per_min", err_total, ifname)
            _thresholds(ctx, res, rt, "if_errors_per_min", err_total, now, ifname)
    return res


# ------------------------------------------------------------------- REST

async def _api_call(rt: NodeRT, ctx: Ctx, res: JobResult, now: datetime, key: str,
                    fn: Callable[[capi.CppmApi], Awaitable[Any]]) -> Any:
    """Run one REST fetch with API-state tracking; returns None on failure/unsupported."""
    if rt.api is None or key in rt.unsupported:
        return None
    try:
        async with ctx.api_sem, capi.CppmApi(rt.api) as api:
            out = await fn(api)
    except capi.ApiError as exc:
        if exc.kind == "not_found":
            rt.unsupported.add(key)
            log.info("REST endpoint unsupported on this node; KPI disabled", extra={"node_id": rt.id, "endpoint": key, "detail": str(exc)[:160]})
            return None
        rt.api_fail += 1
        state = "auth_failed" if exc.kind in ("invalid_client", "invalid_grant", "grant_type", "auth", "forbidden") else "unreachable"
        if state != rt.api_state:
            res.state["api_state"] = state
            if state == "auth_failed":
                res.events.append(_event(rt, now, "api.auth_failed", "medium",
                                         f"[CPPM][MEDIUM] API credentials rejected on {rt.name} ({exc.kind})", detail=str(exc)[:200]))
            rt.api_state = state
        log.warning("REST poll failed", extra={"node_id": rt.id, "endpoint": key, "kind": exc.kind, "error": str(exc)[:160]})
        return None
    rt.api_fail = 0
    res.state["last_api_ok"] = now
    if rt.api_state != "ok":
        if rt.api_state == "auth_failed":
            res.events.append(_event(rt, now, "api.auth_failed", "info", f"API credentials accepted again on {rt.name}", clear=True))
        rt.api_state = "ok"
        res.state["api_state"] = "ok"
    return out


async def job_rest_inventory(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    servers = await _api_call(rt, ctx, res, now, "cluster", capi.fetch_cluster)
    if not servers:
        return res
    me = next((s for s in servers if s.get("management_ip") == rt.ip), None)
    res.metric(rt.id, now, "cluster_servers", len(servers))
    if me is None:
        log.warning("node IP not found in /cluster/server", extra={"node_id": rt.id})
        return res
    rt.server_uuid = me.get("server_uuid")
    publisher = next((s for s in servers if s.get("is_publisher")), None)
    if publisher and publisher.get("server_uuid"):
        res.state["cluster_uuid"] = publisher["server_uuid"]  # cluster identity = publisher UUID (groups cluster-wide alerts)
    pub = bool(me.get("is_publisher"))
    if rt.is_publisher is not None and pub != rt.is_publisher:
        res.events.append(_event(rt, now, "cluster.role_change", "high",
                                 f"[CPPM][HIGH] {rt.name} is now {'Publisher' if pub else 'Subscriber'} (role changed)", is_publisher=pub))
    rt.is_publisher = pub
    res.role = "publisher" if pub else "subscriber"
    rep = (me.get("replication_status") or "").upper()
    ok = pub or rep == "ENABLED"
    if not ok and rt.replication_ok is not False:
        res.events.append(_event(rt, now, "cluster.replication", "high",
                                 f"[CPPM][HIGH] Replication status {rep or 'unknown'} on {rt.name}", replication_status=rep))
    if ok and rt.replication_ok is False:
        res.events.append(_event(rt, now, "cluster.replication", "info", f"Replication healthy on {rt.name}", clear=True))
    rt.replication_ok = ok
    return res


async def job_rest_services(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    if rt.server_uuid is None:
        inv = await job_rest_inventory(rt, ctx)
        res.events.extend(inv.events)
        res.state.update(inv.state)
        res.role = inv.role
        if rt.server_uuid is None:
            return res
    uuid = rt.server_uuid
    services = await _api_call(rt, ctx, res, now, "services", lambda api: capi.fetch_services(api, uuid))
    if not services:
        return res
    res.services = services
    for unit, v in services.items():
        name = v.get("display_name") or unit
        running = bool(v.get("is_running"))
        critical = name.lower() in CRITICAL_SERVICES or svc.is_critical(unit)
        prev = rt.services_prev.get(name)
        inst = svc.canonical(unit)  # unit name = same key as trap 1017 and the watchdog trap → one alert per service
        if not running and prev is not False and (critical or prev is True):
            sev = "high" if critical else "medium"
            res.events.append(_event(rt, now, svc.SERVICE_DOWN, sev,
                                     f"[CPPM][{sev.upper()}] Service '{name}' {v.get('state', 'not running')} on {rt.name}",
                                     inst, service=name, unit=unit, state=v.get("state"), signal="rest_poll"))
        if running and prev is False:
            res.events.append(_event(rt, now, svc.SERVICE_DOWN, "info", f"Service '{name}' running again on {rt.name}",
                                     inst, clear=True, signal="rest_poll"))
        rt.services_prev[name] = running
    return res


async def job_rest_endpoints(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    n = await _api_call(rt, ctx, res, now, "endpoints", capi.fetch_endpoint_count)
    res.metric(rt.id, now, "endpoints_total", n)
    return res


def _cn(subject: str | None) -> str:
    for part in (subject or "").split(","):
        if part.strip().upper().startswith("CN="):
            return part.strip()[3:]
    return (subject or "?")[:60]


def monitored_cert_services() -> set[str]:
    """Server-cert service names that are polled (``CPPMMON_CERT_MONITOR_SERVICES``), upper-cased."""
    from cppmmon.config import get_settings

    return {s.strip().upper() for s in get_settings().cert_monitor_services.split(",") if s.strip()}


async def job_rest_certs_licenses(rt: NodeRT, ctx: Ctx) -> JobResult:
    res, now = JobResult(), utcnow()
    # Scope (2026-11-17): only the installed RADIUS and HTTPS(RSA) server certificates are polled.
    # Any other certificate / trusted-root expiry is alerted only when CPPM reports it (trap 1003, syslog).
    server = await _api_call(rt, ctx, res, now, "server-cert", capi.fetch_server_certs)
    if server is not None:
        wanted = monitored_cert_services()
        certs = []
        for c in server:
            if (c.get("service") or "").upper() not in wanted:
                continue
            days = int((c["valid_to"] - now).total_seconds() // 86400) if c.get("valid_to") else None
            certs.append({"cert_type": c["cert_type"], "service": c.get("service"), "subject": c.get("subject"),
                          "issuer": c.get("issuer"), "valid_to": c.get("valid_to"), "days_left": days})
            if days is not None:
                inst = f"server:{c.get('service')}"
                res.metric(rt.id, now, "cert_days_left", days, inst)
                _thresholds(ctx, res, rt, "cert_days_left", float(days), now, inst)
        res.certs = certs
    lic = await _api_call(rt, ctx, res, now, "license-summary", capi.fetch_license_summary)
    if lic is not None:
        details = await _api_call(rt, ctx, res, now, "license-details", capi.fetch_license_details) or {}
        res.licenses = [{"app_name": x["app_name"], "total": x["total"], "used": x["used"],
                         **{k: details.get(x["app_name"], {}).get(k) for k in ("license_type", "activated", "added_on", "expires_at")}}
                        for x in lic]
        for x in lic:
            if x.get("total"):
                pct = 100.0 * float(x.get("used") or 0) / float(x["total"])
                res.metric(rt.id, now, "license_pct", pct, x["app_name"])
                _thresholds(ctx, res, rt, "license_pct", pct, now, x["app_name"])
    return res


@dataclass(frozen=True)
class Job:
    name: str
    interval_s: int
    fn: Callable[[NodeRT, Ctx], Awaitable[JobResult]]
    needs_api: bool = False
    timeout_s: int = 120


JOBS = (
    Job("icmp", 30, job_icmp, timeout_s=20),
    Job("snmp_system", 60, job_snmp_system, timeout_s=50),
    Job("snmp_auth", 300, job_snmp_auth, timeout_s=120),
    Job("snmp_storage_if", 300, job_snmp_storage_if, timeout_s=120),
    Job("rest_services", 900, job_rest_services, needs_api=True, timeout_s=60),
    Job("rest_endpoints", 900, job_rest_endpoints, needs_api=True, timeout_s=60),
    Job("rest_inventory", 3600, job_rest_inventory, needs_api=True, timeout_s=60),
    Job("rest_certs_licenses", 21600, job_rest_certs_licenses, needs_api=True, timeout_s=180),
)
