"""CPPM-MIB specifics: cppmSystemTable index discovery and system info (DESIGN §2.1)."""
from __future__ import annotations

import logging
import time
from typing import Any

from cppmmon.collectors.snmp_client import UNSUPPORTED, SnmpClient, SnmpError
from cppmmon.collectors.types import CheckResult, SnmpParams

log = logging.getLogger(__name__)

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"

# cppmSystemEntry. DESIGN's "…" prefix is 1.3.6.1.4.1.14823.1.6, so "…1.1.1.1.1.<col>.<idx>"
# is the OID below. Verified on lab CPPM 6.14.1 (2026-11-17): instance index 0.
CPPM_SYSTEM_TABLE = "1.3.6.1.4.1.14823.1.6.1.1.1.1.1"
INDEX_CANDIDATES = (1, 0, 2, 3, 4, 5)

# cppmSystemTable columns read at test time (DESIGN §2.1; layout verified on 6.14.1)
SYS_COLS = {
    1: "model",
    2: "serial",
    3: "version",
    4: "hostname",
    5: "node_type",
    7: "cluster_size",
    8: "mgmt_ip",
    16: "num_cpus",
    17: "uptime",
}
# CPPM VMs report placeholder strings for hardware-only columns (e.g. serial "None").
_PLACEHOLDERS = {"", "None", "none", "N/A", "NA"}

HINT_TIMEOUT = (
    "No SNMP response on UDP/161. In CPPM: Administration › Server Manager › Server Configuration › "
    "(select server) › System Monitor (SNMP) — enable SNMP, set the v2c community / v3 user to match, "
    "and allow this monitor's IP. Also check nothing filters UDP/161 between the two."
)
HINT_AUTH = (
    "SNMPv3 credentials rejected. Match the user, auth/priv protocols and keys with "
    "CPPM System Monitor › SNMPv3 users."
)
HINT_NO_CPPM_MIB = (
    "SNMP answers but the CPPM-MIB (cppmSystemTable) is empty. Confirm this IP is a ClearPass node "
    "and that the SNMP view includes .1.3.6.1.4.1.14823."
)


def col_oid(col: int, index: int) -> str:
    """OID of ``cppmSystemTable`` column ``col`` at instance ``index``."""
    return f"{CPPM_SYSTEM_TABLE}.{col}.{index}"


async def discover_index(client: SnmpClient) -> int | None:
    """Find the cppmSystemTable instance index.

    GET the hostname column at every candidate index in **one PDU**; the first
    candidate (in preference order) that is not NoSuchInstance wins. Falls back to
    walking the hostname column.
    """
    oids = {i: col_oid(4, i) for i in INDEX_CANDIDATES}
    got = await client.get(list(oids.values()))
    for idx in INDEX_CANDIDATES:
        if got[oids[idx]] is not UNSUPPORTED:
            return idx
    walked = await client.walk(f"{CPPM_SYSTEM_TABLE}.4")
    for oid in walked:
        tail = oid.rsplit(".", 1)[-1]
        if tail.isdigit():
            return int(tail)
    return None


async def system_info(client: SnmpClient, index: int) -> dict[str, Any]:
    """Read the cppmSystemTable columns in one PDU; missing columns come back as None."""
    oids = {name: col_oid(col, index) for col, name in SYS_COLS.items()}
    got = await client.get(list(oids.values()))
    out: dict[str, Any] = {}
    for name, oid in oids.items():
        val = got[oid]
        out[name] = None if val is UNSUPPORTED or (isinstance(val, str) and val.strip() in _PLACEHOLDERS) else val
    return out


# ----------------------------------------------------------------- polling
# OIDs verified on lab CPPM 6.14.1 (docs/API_NOTES.md). UCD wait/kernel/interrupt are
# absent on CPPM; they are requested anyway and ignored when NoSuchObject.
UCD_CPU = {name: f"1.3.6.1.4.1.2021.11.{n}.0" for name, n in
           (("user", 50), ("nice", 51), ("system", 52), ("idle", 53), ("wait", 54), ("kernel", 55), ("interrupt", 56))}
UCD_MEM = {"total_kb": "1.3.6.1.4.1.2021.4.5.0", "avail_kb": "1.3.6.1.4.1.2021.4.6.0",
           "buffer_kb": "1.3.6.1.4.1.2021.4.14.0", "cached_kb": "1.3.6.1.4.1.2021.4.15.0"}
UCD_LOAD = {f"load{m}": f"1.3.6.1.4.1.2021.10.1.3.{i}" for i, m in ((1, 1), (2, 5), (3, 15))}
POLICY_SERVER_ENTRY = "1.3.6.1.4.1.14823.1.6.1.1.2.3.1"  # instance .0 on 6.14 (not hostname-indexed)
POLICY_COLS = {14: "ps_auth_success", 15: "ps_auth_failure", 16: "ps_auth_total",
               17: "daily_success", 18: "daily_failed", 19: "daily_total"}
AUTH_SOURCE_ENTRY = "1.3.6.1.4.1.14823.1.6.1.1.2.2.1"  # col 2 = name; 3..6 assumed success/failure/total/time
AUTH_SOURCE_COLS = {3: "src_success", 4: "src_failure", 5: "src_total", 6: "src_time"}
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"  # .3 descr .4 units .5 size .6 used
IF_TABLE = "1.3.6.1.2.1.2.2.1"  # .2 descr .8 oper .10 inOct .13 inDisc .14 inErr .16 outOct .19 outDisc .20 outErr
IF_COLS = {8: "oper", 10: "in_octets", 13: "in_discards", 14: "in_errors", 16: "out_octets", 19: "out_discards", 20: "out_errors"}
IF_SKIP = ("lo", "docker", "br-", "veth", "virbr")


def _num(v: Any) -> float | None:
    if v is UNSUPPORTED or v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


async def poll_system(client: SnmpClient, index: int, policy_index: int = 0) -> dict[str, Any]:
    """One PDU: cppmSystemTable, sysUpTime, UCD CPU ticks/memory/load and policy-server counters."""
    sys_oids = {name: col_oid(col, index) for col, name in SYS_COLS.items()}
    sys_oids.update(mem_total_b=col_oid(12, index), mem_free_b=col_oid(13, index),
                    disk_total_b=col_oid(14, index), disk_free_b=col_oid(15, index))
    pol = {name: f"{POLICY_SERVER_ENTRY}.{col}.{policy_index}" for col, name in POLICY_COLS.items()}
    oids = {**sys_oids, "sys_uptime_ticks": SYS_UPTIME, **{f"cpu_{k}": v for k, v in UCD_CPU.items()},
            **UCD_MEM, **UCD_LOAD, **pol}
    got = await client.get(list(oids.values()))
    out: dict[str, Any] = {}
    for name, oid in oids.items():
        v = got[oid]
        if v is UNSUPPORTED or (isinstance(v, str) and v.strip() in _PLACEHOLDERS):
            out[name] = None
        elif name.startswith("load"):
            out[name] = _num(v)
        else:
            out[name] = v
    return out


async def find_policy_index(client: SnmpClient) -> int | None:
    """policyServerTable instance (0 on 6.14); walks the total column if .0 is absent."""
    rows = await client.walk(f"{POLICY_SERVER_ENTRY}.16", max_rows=10)
    for oid in rows:
        tail = oid.rsplit(".", 1)[-1]
        if tail.isdigit():
            return int(tail)
    return None


async def poll_auth_sources(client: SnmpClient) -> dict[str, dict[str, Any]]:
    """Per auth source counters keyed by source name (radiusServerAuthTable)."""
    names = await client.walk(f"{AUTH_SOURCE_ENTRY}.2", max_rows=200)
    by_idx = {oid.rsplit(".", 1)[-1]: str(name) for oid, name in names.items()}
    out: dict[str, dict[str, Any]] = {n: {} for n in by_idx.values()}
    for col, key in AUTH_SOURCE_COLS.items():
        vals = await client.walk(f"{AUTH_SOURCE_ENTRY}.{col}", max_rows=200)
        for oid, v in vals.items():
            idx = oid.rsplit(".", 1)[-1]
            if idx in by_idx:
                out[by_idx[idx]][key] = v
    return out


async def poll_storage(client: SnmpClient) -> dict[str, dict[str, float]]:
    """hrStorage per mount: {descr: {"size_b", "used_b", "pct"}} (swap/memory entries skipped)."""
    cols = {c: await client.walk(f"{HR_STORAGE}.{c}", max_rows=200) for c in (3, 4, 5, 6)}
    idx = {oid.rsplit(".", 1)[-1]: str(v) for oid, v in cols[3].items()}
    get = lambda c, i: _num(cols[c].get(f"{HR_STORAGE}.{c}.{i}"))  # noqa: E731
    out: dict[str, dict[str, float]] = {}
    for i, descr in idx.items():
        if not descr.startswith("/"):
            continue
        units, size, used = get(4, i), get(5, i), get(6, i)
        if units and size:
            out[descr] = {"size_b": units * size, "used_b": units * (used or 0), "pct": 100.0 * (used or 0) / size}
    return out


async def poll_interfaces(client: SnmpClient) -> dict[str, dict[str, Any]]:
    """IF-MIB counters for physical interfaces (lo/docker/bridges/veth skipped)."""
    descr = await client.walk(f"{IF_TABLE}.2", max_rows=200)
    names = {oid.rsplit(".", 1)[-1]: str(v) for oid, v in descr.items() if not str(v).startswith(IF_SKIP)}
    out: dict[str, dict[str, Any]] = {n: {} for n in names.values()}
    for col, key in IF_COLS.items():
        vals = await client.walk(f"{IF_TABLE}.{col}", max_rows=200)
        for oid, v in vals.items():
            i = oid.rsplit(".", 1)[-1]
            if i in names:
                out[names[i]][key] = v
    return out


async def test_snmp(params: SnmpParams) -> CheckResult:
    """Test Connection: sysName, CPPM index discovery, hostname/version/model."""
    t0 = time.perf_counter()
    try:
        async with SnmpClient(params) as c:
            base = await c.get([SYS_NAME, SYS_DESCR, SYS_UPTIME])
            latency = (time.perf_counter() - t0) * 1000
            sys_name = base[SYS_NAME] if base[SYS_NAME] is not UNSUPPORTED else None
            idx = await discover_index(c)
            details: dict[str, Any] = {
                "snmp_version": params.version,
                "sys_name": sys_name,
                "sys_descr": (str(base[SYS_DESCR])[:200] if base[SYS_DESCR] is not UNSUPPORTED else None),
                "sys_uptime_s": (int(base[SYS_UPTIME]) // 100 if base[SYS_UPTIME] is not UNSUPPORTED else None),
                "sys_index": idx,
            }
            if idx is None:
                return CheckResult("snmp", ok=False, latency_ms=round(latency, 1), summary=f"sysName {sys_name}",
                                   error="cppmSystemTable has no instances", hint=HINT_NO_CPPM_MIB, details=details)
            info = await system_info(c, idx)
            details.update(info)
    except SnmpError as exc:
        hint = HINT_AUTH if exc.kind == "auth" else HINT_TIMEOUT if exc.kind == "timeout" else None
        if exc.kind == "config":
            hint = "Complete the SNMP credentials on the node form."
        return CheckResult("snmp", ok=False, latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                           error=str(exc), hint=hint, details={"snmp_version": params.version, "kind": exc.kind})
    except OSError as exc:
        return CheckResult("snmp", ok=False, error=f"{exc.__class__.__name__}: {exc}", hint=HINT_TIMEOUT)

    summary = f"{details.get('hostname') or sys_name} · index {idx}"
    if details.get("version"):
        summary += f" · CPPM {details['version']}"
    return CheckResult("snmp", ok=True, latency_ms=round(latency, 1), summary=summary, details=details)
