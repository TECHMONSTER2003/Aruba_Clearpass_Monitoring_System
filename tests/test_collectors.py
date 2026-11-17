"""Collector unit tests: CPPM index discovery, per-OID parsing, REST client error mapping."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from cppmmon.collectors import cppm_api
from cppmmon.collectors.cppm_snmp import CPPM_SYSTEM_TABLE, discover_index, system_info
from cppmmon.collectors.snmp_client import UNSUPPORTED
from cppmmon.collectors.types import ApiParams, SnmpParams


class FakeSnmp:
    """Agent stand-in: a flat {oid: value} table; missing OIDs are NoSuchInstance."""

    def __init__(self, table: dict[str, Any]) -> None:
        self.table = table
        self.get_calls: list[list[str]] = []

    async def get(self, oids: list[str]) -> dict[str, Any]:
        self.get_calls.append(oids)
        return {o: self.table.get(o, UNSUPPORTED) for o in oids}

    async def walk(self, base: str) -> dict[str, Any]:
        return {o: v for o, v in self.table.items() if o.startswith(base + ".")}


def test_cppm_system_oids_match_lab_appliance() -> None:
    """Regression: OIDs observed on lab CPPM 6.14.1 (hostname at index 0)."""
    from cppmmon.collectors.cppm_snmp import col_oid

    assert col_oid(4, 0) == "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.4.0"  # cppmSystemHostname
    assert col_oid(12, 0) == "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.12.0"  # cppmSystemMemoryTotal


@pytest.mark.asyncio
async def test_placeholder_serial_is_none() -> None:
    t = CPPM_SYSTEM_TABLE
    info = await system_info(FakeSnmp({f"{t}.2.0": "None", f"{t}.1.0": "CLABV"}), 0)
    assert info["serial"] is None and info["model"] == "CLABV"


@pytest.mark.asyncio
async def test_index_discovery_single_pdu_prefers_first_present() -> None:
    fake = FakeSnmp({f"{CPPM_SYSTEM_TABLE}.4.0": "cppm-lab", f"{CPPM_SYSTEM_TABLE}.4.2": "other"})
    assert await discover_index(fake) == 0  # index 1 missing → 0 is next in preference order
    assert len(fake.get_calls) == 1 and len(fake.get_calls[0]) == 6  # one PDU, all candidates


@pytest.mark.asyncio
async def test_index_discovery_walk_fallback() -> None:
    fake = FakeSnmp({f"{CPPM_SYSTEM_TABLE}.4.17": "cppm-odd-index"})
    assert await discover_index(fake) == 17


@pytest.mark.asyncio
async def test_system_info_missing_column_does_not_shift() -> None:
    t = CPPM_SYSTEM_TABLE
    fake = FakeSnmp({f"{t}.1.1": "C2000V", f"{t}.3.1": "6.12.1.268", f"{t}.4.1": "cppm-lab"})  # serial (col 2) absent
    info = await system_info(fake, 1)
    assert info["model"] == "C2000V" and info["serial"] is None
    assert info["version"] == "6.12.1.268" and info["hostname"] == "cppm-lab"


def test_snmp_params_repr_hides_secrets() -> None:
    p = SnmpParams(host="10.0.0.1", community="topsecret", v3_auth_key="k" * 10)
    assert "topsecret" not in repr(p) and "kkkk" not in repr(p)


def _api(handler: Any) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


PARAMS = ApiParams(host="cppm.lab", grant_type="password", client_id="mon", username="u", password="p")


@pytest.mark.asyncio
async def test_api_success_reports_version() -> None:
    cppm_api._TOKENS.clear()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/oauth":
            body = json.loads(req.content)
            assert body["grant_type"] == "password" and body["username"] == "u" and "client_secret" not in body
            return httpx.Response(200, json={"access_token": "T", "expires_in": 28800})
        assert req.headers["Authorization"] == "Bearer T"
        if req.url.path == "/api/cppm-version":
            return httpx.Response(200, json={"app_major_version": 6, "app_minor_version": 12,
                                             "app_service_release": 1, "app_build_number": 268})
        return httpx.Response(404)

    r = await cppm_api.test_api(PARAMS, _api(handler))
    assert r.ok and r.details["cppm_version"] == "6.12.1.268" and r.details["server_version"] == "unsupported"


@pytest.mark.parametrize(("body", "kind"), [
    ({"error": "invalid_client"}, "invalid_client"),
    ({"error": "invalid_grant", "error_description": "bad password"}, "invalid_grant"),
    ({"title": "Bad Request", "detail": "unauthorized_client"}, "grant_type"),
])
@pytest.mark.asyncio
async def test_api_oauth_errors_classified(body: dict, kind: str) -> None:
    cppm_api._TOKENS.clear()
    r = await cppm_api.test_api(PARAMS, _api(lambda _req: httpx.Response(400, json=body)))
    assert not r.ok and r.details["kind"] == kind and r.hint


@pytest.mark.asyncio
async def test_api_401_refreshes_once_then_retries() -> None:
    cppm_api._TOKENS.clear()
    calls = {"oauth": 0, "get": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/oauth":
            calls["oauth"] += 1
            return httpx.Response(200, json={"access_token": f"T{calls['oauth']}", "expires_in": 3600})
        calls["get"] += 1
        return httpx.Response(401) if req.headers["Authorization"] == "Bearer T1" else httpx.Response(200, json={"ok": 1})

    async with cppm_api.CppmApi(PARAMS, _api(handler)) as api:
        assert await api.get("/anything") == {"ok": 1}
    assert calls == {"oauth": 2, "get": 2}


@pytest.mark.asyncio
async def test_api_forbidden_has_operator_profile_hint() -> None:
    cppm_api._TOKENS.clear()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/oauth":
            return httpx.Response(200, json={"access_token": "T", "expires_in": 3600})
        return httpx.Response(403, json={"detail": "Forbidden"})

    r = await cppm_api.test_api(PARAMS, _api(handler))
    assert not r.ok and r.details["kind"] == "forbidden" and "operator profile" in (r.hint or "")
