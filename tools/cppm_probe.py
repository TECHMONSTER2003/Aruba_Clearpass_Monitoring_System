#!/usr/bin/env python3
"""cppm_probe: test one CPPM (ICMP / SNMP / API) from the shell.

Stored node (credentials decrypted from the DB; run as the cppmmon user):
    sudo -u cppmmon /opt/cppmmon/venv/bin/python /opt/cppmmon/tools/cppm_probe.py --node cppm-pub-01

Ad hoc (secrets are prompted, never taken from argv so they don't show in `ps`):
    cppm_probe.py --ip 10.10.10.5 --snmp v2c
    cppm_probe.py --ip 10.10.10.5 --snmp v3 --v3-user mon --v3-auth SHA --v3-priv AES
    cppm_probe.py --ip 10.10.10.5 --no-snmp --api-client-id claude-admin --grant password --api-user admin

Exit status: 0 if every executed check passed, 1 otherwise, 2 on usage/DB errors.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import or_, select  # noqa: E402
from sqlalchemy.exc import SQLAlchemyError  # noqa: E402

from cppmmon.collectors.probe import probe_sync  # noqa: E402
from cppmmon.collectors.snmp_client import AUTH_PROTOCOLS, PRIV_PROTOCOLS  # noqa: E402
from cppmmon.collectors.types import ApiParams, CheckResult, SnmpParams  # noqa: E402

GREEN, RED, GREY, DIM, RESET = "\033[32m", "\033[31m", "\033[90m", "\033[2m", "\033[0m"


def _from_db(ref: str) -> tuple[str, SnmpParams, ApiParams | None]:
    from cppmmon.db.models import Node
    from cppmmon.db.session import session_scope
    from cppmmon.node_creds import api_params, snmp_params

    with session_scope() as s:
        node = s.scalar(select(Node).where(or_(Node.name == ref, Node.ip == ref)))
        if node is None:
            raise SystemExit(f"error: no node named or with IP '{ref}'")
        return node.ip, snmp_params(node), api_params(node)


def _ask(prompt: str) -> str:
    return getpass.getpass(f"{prompt}: ")


def _adhoc(a: argparse.Namespace) -> tuple[str, SnmpParams | None, ApiParams | None]:
    ip = str(ipaddress.ip_address(a.ip))
    snmp: SnmpParams | None = None
    if a.snmp == "v2c":
        snmp = SnmpParams(host=ip, port=a.snmp_port, version="2c", community=_ask("SNMP community"))
    elif a.snmp == "v3":
        snmp = SnmpParams(
            host=ip, port=a.snmp_port, version="3", v3_user=a.v3_user,
            v3_auth_proto=a.v3_auth, v3_auth_key=_ask("SNMPv3 auth key") if a.v3_auth else None,
            v3_priv_proto=a.v3_priv, v3_priv_key=_ask("SNMPv3 priv key") if a.v3_priv else None,
        )
    api: ApiParams | None = None
    if a.api_client_id:
        secret = _ask("API client secret (Enter for none)") or None
        pw = _ask("API password") if a.grant == "password" else None
        api = ApiParams(host=ip, grant_type=a.grant, client_id=a.api_client_id, client_secret=secret,
                        username=a.api_user, password=pw, verify_tls=a.verify_tls)
    return ip, snmp, api


def _print(results: list[CheckResult], color: bool) -> None:
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda _code, s: s)
    for r in results:
        status = c(GREY, "SKIP") if r.skipped else (c(GREEN, "PASS") if r.ok else c(RED, "FAIL"))
        ms = f"{r.latency_ms:>8.1f} ms" if r.latency_ms is not None and not r.skipped else " " * 11
        text = r.summary if (r.ok or r.skipped) else (r.error or "failed")
        print(f"  {status}  {r.name.upper():<5} {ms}  {text}")
        if r.hint and not r.ok and not r.skipped:
            print(c(DIM, f"              hint: {r.hint}"))


def main() -> int:
    p = argparse.ArgumentParser(description="Test one CPPM node (ICMP / SNMP / API)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--node", help="stored node name or IP (uses DB credentials)")
    src.add_argument("--ip", help="ad-hoc target IP")
    p.add_argument("--snmp", choices=("v2c", "v3"), default=None, help="ad hoc: SNMP version to test")
    p.add_argument("--no-snmp", action="store_true", help="ad hoc: skip SNMP")
    p.add_argument("--snmp-port", type=int, default=161)
    p.add_argument("--v3-user")
    p.add_argument("--v3-auth", choices=sorted(AUTH_PROTOCOLS))
    p.add_argument("--v3-priv", choices=sorted(PRIV_PROTOCOLS))
    p.add_argument("--api-client-id")
    p.add_argument("--grant", choices=("client_credentials", "password"), default="client_credentials")
    p.add_argument("--api-user")
    p.add_argument("--verify-tls", action="store_true")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    a = p.parse_args()

    try:
        if a.node:
            host, snmp, api = _from_db(a.node)
        else:
            if a.snmp is None and not a.no_snmp:
                a.snmp = "v2c"
            if a.no_snmp:
                a.snmp = None
            if a.snmp == "v3" and not a.v3_user:
                p.error("--v3-user is required with --snmp v3")
            if a.grant == "password" and a.api_client_id and not a.api_user:
                p.error("--api-user is required with --grant password")
            host, snmp, api = _adhoc(a)
    except SQLAlchemyError as exc:
        print(f"error: database: {exc.__class__.__name__}", file=sys.stderr)
        return 2

    results = probe_sync(host, snmp, api)
    if a.json:
        print(json.dumps({"host": host, "checks": [r.to_dict() for r in results]}, indent=2, default=str))
    else:
        print(f"CPPM probe → {host}")
        _print(results, sys.stdout.isatty())
    return 0 if all(r.ok for r in results if not r.skipped) else 1


if __name__ == "__main__":
    sys.exit(main())
