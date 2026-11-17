"""Async SNMP wrapper (pysnmp 7.x asyncio API), v2c and v3.

Results are always returned **per OID** (dict keyed by the requested OID), never
by position, so a missing object cannot shift other values (CLAUDE.md §4.1).
"""
from __future__ import annotations

import logging
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usm3DESEDEPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)
from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

from cppmmon.collectors.types import SnmpParams

log = logging.getLogger(__name__)

AUTH_PROTOCOLS: dict[str, Any] = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA-224": usmHMAC128SHA224AuthProtocol,
    "SHA-256": usmHMAC192SHA256AuthProtocol,
    "SHA-384": usmHMAC256SHA384AuthProtocol,
    "SHA-512": usmHMAC384SHA512AuthProtocol,
}
PRIV_PROTOCOLS: dict[str, Any] = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES-192": usmAesCfb192Protocol,
    "AES-256": usmAesCfb256Protocol,
}

UNSUPPORTED = object()  # sentinel: NoSuchObject / NoSuchInstance / EndOfMibView


class SnmpError(Exception):
    """Transport or protocol failure (timeout, auth failure, error-status)."""

    def __init__(self, message: str, kind: str = "error") -> None:
        super().__init__(message)
        self.kind = kind  # timeout | auth | status | config | error


def _auth_data(p: SnmpParams) -> CommunityData | UsmUserData:
    if p.version == "2c":
        if not p.community:
            raise SnmpError("SNMP v2c community is not set", "config")
        return CommunityData(p.community, mpModel=1)
    if not p.v3_user:
        raise SnmpError("SNMPv3 user is not set", "config")
    auth = AUTH_PROTOCOLS.get(p.v3_auth_proto or "", usmNoAuthProtocol)
    priv = PRIV_PROTOCOLS.get(p.v3_priv_proto or "", usmNoPrivProtocol)
    if auth is not usmNoAuthProtocol and not p.v3_auth_key:
        raise SnmpError("SNMPv3 auth protocol set but auth key is empty", "config")
    if priv is not usmNoPrivProtocol and (auth is usmNoAuthProtocol or not p.v3_priv_key):
        raise SnmpError("SNMPv3 privacy needs an auth protocol and a priv key", "config")
    return UsmUserData(
        p.v3_user,
        authKey=p.v3_auth_key if auth is not usmNoAuthProtocol else None,
        privKey=p.v3_priv_key if priv is not usmNoPrivProtocol else None,
        authProtocol=auth,
        privProtocol=priv,
    )


def _classify(indication: Any) -> SnmpError:
    text = str(indication)
    low = text.lower()
    if "timeout" in low or "no snmp response" in low:
        return SnmpError(text, "timeout")
    if any(k in low for k in ("wrongdigest", "unknownusername", "unknown user", "authentication", "decryption", "unsupportedsecuritylevel", "unknownengineid", "notintimewindow")):
        return SnmpError(text, "auth")
    return SnmpError(text, "error")


def _py(value: Any) -> Any:
    """Convert a pysnmp value to a plain Python value (or UNSUPPORTED)."""
    if isinstance(value, (NoSuchInstance, NoSuchObject, EndOfMibView)):
        return UNSUPPORTED
    cls = value.__class__.__name__
    if cls in ("Integer", "Integer32", "Counter32", "Counter64", "Gauge32", "Unsigned32", "TimeTicks"):
        return int(value)
    if cls == "OctetString":
        raw = bytes(value)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex(":")
    if cls == "ObjectIdentifier":
        return str(value)
    return value.prettyPrint()


class SnmpClient:
    """One SNMP session (engine + transport) for one node. Use as an async context manager."""

    def __init__(self, params: SnmpParams) -> None:
        self.p = params
        self._engine: SnmpEngine | None = None
        self._target: UdpTransportTarget | None = None
        self._auth = _auth_data(params)

    async def __aenter__(self) -> "SnmpClient":
        self._engine = SnmpEngine()
        self._target = await UdpTransportTarget.create((self.p.host, self.p.port), timeout=self.p.timeout_s, retries=self.p.retries)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._engine is not None:
            self._engine.close_dispatcher()

    async def get(self, oids: list[str]) -> dict[str, Any]:
        """GET ``oids`` in one PDU; returns ``{requested_oid: value | UNSUPPORTED}``."""
        assert self._engine and self._target
        err_ind, err_status, err_index, var_binds = await get_cmd(
            self._engine, self._auth, self._target, ContextData(), *[ObjectType(ObjectIdentity(o)) for o in oids],
            lookupMib=False,  # keep numeric OIDs in responses (no MIB name resolution)
        )
        if err_ind:
            raise _classify(err_ind)
        if err_status:
            bad = oids[int(err_index) - 1] if err_index and int(err_index) <= len(oids) else "?"
            raise SnmpError(f"{err_status.prettyPrint()} at {bad}", "status")
        out: dict[str, Any] = {o: UNSUPPORTED for o in oids}
        for vb in var_binds:
            oid = str(vb[0])
            if oid in out:
                out[oid] = _py(vb[1])
        return out

    async def walk(self, base_oid: str, max_rows: int = 5000) -> dict[str, Any]:
        """GETBULK-walk a subtree; returns ``{full_oid: value}`` (lexicographic order)."""
        assert self._engine and self._target
        out: dict[str, Any] = {}
        prefix = base_oid.rstrip(".") + "."
        async for err_ind, err_status, _idx, var_binds in bulk_walk_cmd(
            self._engine, self._auth, self._target, ContextData(), 0, 25,
            ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False, lookupMib=False,
        ):
            if err_ind:
                raise _classify(err_ind)
            if err_status:
                raise SnmpError(err_status.prettyPrint(), "status")
            for vb in var_binds:
                oid = str(vb[0])
                if not oid.startswith(prefix):
                    return out
                val = _py(vb[1])
                if val is not UNSUPPORTED:
                    out[oid] = val
            if len(out) >= max_rows:
                log.warning("walk truncated", extra={"base": base_oid, "rows": len(out)})
                break
        return out
