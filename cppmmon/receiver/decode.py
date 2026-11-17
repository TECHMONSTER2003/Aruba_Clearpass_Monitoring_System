"""SNMP v1/v2c trap decoding from raw UDP payloads (pysnmp proto API + pyasn1).

Raw decoding (instead of ``ntfrcv``) is deliberate: ntfrcv silently drops traps
whose community is not configured, but CLAUDE.md §4.3 requires storing them with
``community_ok=false`` for troubleshooting, and we need the UDP source address.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pyasn1.codec.ber import decoder
from pyasn1.error import PyAsn1Error
from pysnmp.proto import api

SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
GENERIC_TRAPS = "1.3.6.1.6.3.1.1.5"  # RFC 3584 v1 generic → v2 trap OID


class TrapDecodeError(Exception):
    """Payload is not a decodable SNMP v1/v2c trap/inform."""


@dataclass
class DecodedTrap:
    version: str  # "1" | "2c"
    community: str
    trap_oid: str | None
    varbinds: list[tuple[str, Any]] = field(default_factory=list)  # excludes sysUpTime/snmpTrapOID
    uptime_ticks: int | None = None
    agent_addr: str | None = None  # v1 only
    is_inform: bool = False


def to_py(value: Any) -> Any:
    """pyasn1/pysnmp value → JSON-safe Python value."""
    while hasattr(value, "getComponent") and value.__class__.__name__ in ("ObjectSyntax", "SimpleSyntax", "ApplicationSyntax", "NetworkAddress"):
        value = value.getComponent()
    cls = value.__class__.__name__
    if cls in ("Integer", "Integer32", "Counter32", "Counter64", "Gauge32", "Unsigned32", "TimeTicks"):
        return int(value)
    if cls == "IpAddress":
        return ".".join(str(b) for b in bytes(value))
    if cls == "ObjectIdentifier" or cls == "ObjectName":
        return str(value)
    if cls in ("OctetString", "Opaque", "Bits"):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8")
            return text if text.isprintable() or not text else raw.hex(":")
        except UnicodeDecodeError:
            return raw.hex(":")
    if cls == "Null":
        return None
    return value.prettyPrint()


def decode_trap(data: bytes) -> DecodedTrap:
    """Decode one datagram. Raises :class:`TrapDecodeError` for anything that is not a trap."""
    try:
        ver = int(api.decodeMessageVersion(data))
        pmod = api.PROTOCOL_MODULES.get(ver)
        if pmod is None:
            raise TrapDecodeError(f"unsupported SNMP message version {ver} (v3 traps are Phase 6)")
        msg, _rest = decoder.decode(data, asn1Spec=pmod.Message())
        community = bytes(pmod.apiMessage.get_community(msg)).decode("utf-8", errors="replace")
        pdu = pmod.apiMessage.get_pdu(msg)
    except (PyAsn1Error, ValueError, KeyError) as exc:
        raise TrapDecodeError(f"malformed SNMP message: {exc.__class__.__name__}") from exc

    if ver == api.SNMP_VERSION_1:
        if not pdu.isSameTypeWith(pmod.TrapPDU()):
            raise TrapDecodeError("v1 PDU is not a Trap")
        t = pmod.apiTrapPDU
        enterprise = str(t.get_enterprise(pdu))
        generic, specific = int(t.get_generic_trap(pdu)), int(t.get_specific_trap(pdu))
        trap_oid = f"{enterprise}.0.{specific}" if generic == 6 else f"{GENERIC_TRAPS}.{generic + 1}"
        vbs = [(str(o), to_py(v)) for o, v in t.get_varbinds(pdu)]
        return DecodedTrap("1", community, trap_oid, vbs, int(t.get_timestamp(pdu)), to_py(t.get_agent_address(pdu)))

    is_inform = pdu.isSameTypeWith(pmod.InformRequestPDU())
    if not (pdu.isSameTypeWith(pmod.SNMPv2TrapPDU()) or is_inform):
        raise TrapDecodeError(f"v2c PDU is not a Trap/Inform ({pdu.__class__.__name__})")
    trap_oid: str | None = None
    uptime: int | None = None
    vbs: list[tuple[str, Any]] = []
    for o, v in pmod.apiPDU.get_varbinds(pdu):
        oid = str(o)
        if oid == SNMP_TRAP_OID:
            trap_oid = str(to_py(v))
        elif oid == SYS_UPTIME:
            uptime = int(to_py(v) or 0)
        else:
            vbs.append((oid, to_py(v)))
    return DecodedTrap("2c", community, trap_oid, vbs, uptime, None, is_inform)
