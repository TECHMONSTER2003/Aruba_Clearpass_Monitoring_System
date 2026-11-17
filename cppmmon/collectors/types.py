"""Shared collector types: connection parameters and per-check results."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SnmpParams:
    """Everything needed to talk SNMP to one node. Holds plaintext secrets: never log it."""

    host: str
    port: int = 161
    version: str = "2c"  # "2c" | "3"
    community: str | None = None
    v3_user: str | None = None
    v3_auth_proto: str | None = None  # see snmp_client.AUTH_PROTOCOLS
    v3_auth_key: str | None = None
    v3_priv_proto: str | None = None  # see snmp_client.PRIV_PROTOCOLS
    v3_priv_key: str | None = None
    timeout_s: float = 3.0
    retries: int = 2

    def __repr__(self) -> str:  # keep secrets out of tracebacks / logs
        return f"SnmpParams(host={self.host!r}, port={self.port}, version={self.version!r}, v3_user={self.v3_user!r})"


@dataclass(frozen=True)
class ApiParams:
    """CPPM REST connection parameters. Holds plaintext secrets: never log it."""

    host: str
    grant_type: str = "client_credentials"  # | "password"
    client_id: str = ""
    client_secret: str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool = False
    timeout_s: float = 10.0

    def __repr__(self) -> str:
        return f"ApiParams(host={self.host!r}, grant_type={self.grant_type!r}, client_id={self.client_id!r}, verify_tls={self.verify_tls})"


@dataclass
class CheckResult:
    """Outcome of one Test Connection check (ICMP / SNMP / API)."""

    name: str
    ok: bool
    skipped: bool = False
    latency_ms: float | None = None
    summary: str = ""
    error: str | None = None
    hint: str | None = None  # CPPM-side or network fix, shown to the operator
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
