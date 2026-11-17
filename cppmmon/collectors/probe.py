"""Test Connection orchestration: ICMP, SNMP and API checks run concurrently."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from cppmmon.collectors.cppm_api import test_api
from cppmmon.collectors.cppm_snmp import test_snmp
from cppmmon.collectors.icmp import ping
from cppmmon.collectors.types import ApiParams, CheckResult, SnmpParams

log = logging.getLogger(__name__)


async def _guard(name: str, coro: Any) -> CheckResult:
    """Never let one check's unexpected exception hide the others' results."""
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001 - reported to the operator, logged with traceback
        log.exception("check crashed", extra={"check": name})
        return CheckResult(name, ok=False, error=f"internal error: {exc.__class__.__name__}: {exc}")


async def run_probe(host: str, snmp: SnmpParams | None, api: ApiParams | None) -> list[CheckResult]:
    """Run all three checks concurrently. A missing ``snmp``/``api`` yields a skipped result."""
    tasks = [_guard("icmp", ping(host))]
    tasks.append(_guard("snmp", test_snmp(snmp)) if snmp else asyncio.sleep(0, CheckResult("snmp", ok=False, skipped=True, summary="not configured")))
    tasks.append(_guard("api", test_api(api)) if api else asyncio.sleep(0, CheckResult("api", ok=False, skipped=True, summary="API disabled for this node")))
    results = list(await asyncio.gather(*tasks))
    log.info("probe finished", extra={"host": host, "results": {r.name: ("skip" if r.skipped else r.ok) for r in results}})
    return results


def probe_sync(host: str, snmp: SnmpParams | None, api: ApiParams | None) -> list[CheckResult]:
    """Blocking wrapper for Flask/CLI callers (ADR-004: asyncio.run in a worker thread)."""
    return asyncio.run(run_probe(host, snmp, api))
