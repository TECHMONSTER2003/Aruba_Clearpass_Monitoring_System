"""CPPM REST API client: OAuth2 token cache + tolerant GETs (DESIGN §2.3, CLAUDE.md §4.2)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from cryptography import x509

from cppmmon.collectors.types import ApiParams, CheckResult

log = logging.getLogger(__name__)

HINT_CONNECT = "HTTPS/443 to the CPPM is unreachable from this monitor. Check routing/ACLs and that the IP is the management interface."
HINT_TLS = "The CPPM HTTPS certificate is not trusted. For a lab with a self-signed cert, turn off 'Verify TLS' on this node; for production, install the issuing CA on the monitor."
HINT_CLIENT = (
    "API client rejected (invalid_client). In CPPM: Guest › Administration › API Services › API Clients — check the "
    "Client ID, that the client is enabled, its grant type matches, and the secret (confidential clients only)."
)
HINT_GRANT = "Username/password rejected (invalid_grant) for the password grant. Check the CPPM admin/operator credentials."
HINT_GRANT_TYPE = "The API client does not allow this grant type. Match 'Grant type' on the node with the API client's 'Grant Types' in CPPM."
HINT_FORBIDDEN = "Token issued but the API client's operator profile lacks read privileges. Assign a read-only operator profile with API access."


class ApiError(Exception):
    """REST failure with a classification used for operator hints."""

    def __init__(self, message: str, kind: str, status: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind  # connect | tls | timeout | invalid_client | invalid_grant | grant_type | auth | forbidden | not_found | http
        self.status = status


@dataclass
class _Token:
    value: str
    refresh_at: float  # monotonic time at 80% of expires_in


_TOKENS: dict[tuple[str, str, str, str], _Token] = {}


def _error_text(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:200]
    if isinstance(body, dict):
        parts = [str(body.get(k)) for k in ("error", "error_description", "title", "detail") if body.get(k)]
        return " · ".join(parts) or str(body)[:200]
    return str(body)[:200]


def _classify_oauth(resp: httpx.Response) -> ApiError:
    if resp.status_code == 403 and "html" in resp.headers.get("content-type", "").lower() + resp.text[:100].lower():
        # CPPM's web tier answers with an HPE "Error 403" page when the source IP is not allowed.
        return ApiError("HTTP 403 Forbidden (HTML error page): access to the CPPM API is restricted", "ip_restricted", 403)
    text = _error_text(resp)
    low = text.lower()
    if "invalid_client" in low:
        return ApiError(text, "invalid_client", resp.status_code)
    if "invalid_grant" in low:
        return ApiError(text, "invalid_grant", resp.status_code)
    if "unauthorized_client" in low or "unsupported_grant_type" in low:
        return ApiError(text, "grant_type", resp.status_code)
    return ApiError(f"HTTP {resp.status_code}: {text}", "auth", resp.status_code)


class CppmApi:
    """Async CPPM REST client for one node. Use as an async context manager."""

    def __init__(self, params: ApiParams, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.p = params
        self.base = f"https://{params.host}/api"
        self._client: httpx.AsyncClient | None = None
        self._transport = transport  # tests inject httpx.MockTransport
        self._key = (params.host, params.client_id, params.grant_type, params.username or "")

    async def __aenter__(self) -> "CppmApi":
        self._client = httpx.AsyncClient(verify=self.p.verify_tls, timeout=self.p.timeout_s, transport=self._transport,
                                         headers={"Accept": "application/json", "User-Agent": "cppmmon"})
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def _request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        assert self._client
        try:
            return await self._client.request(method, url, **kw)
        except httpx.ConnectTimeout as exc:
            raise ApiError(f"connect timeout to {self.p.host}:443", "timeout") from exc
        except httpx.ConnectError as exc:
            msg = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate" in msg.lower():
                raise ApiError(f"TLS verification failed: {msg[:160]}", "tls") from exc
            raise ApiError(f"connect error: {msg[:160]}", "connect") from exc
        except httpx.TimeoutException as exc:
            raise ApiError(f"request timed out after {self.p.timeout_s:.0f}s", "timeout") from exc
        except httpx.HTTPError as exc:
            raise ApiError(f"{exc.__class__.__name__}: {exc}", "http") from exc

    async def fetch_token(self) -> tuple[str, int]:
        """POST /api/oauth. Returns ``(access_token, expires_in)``; caches at 80% lifetime."""
        payload: dict[str, str] = {"grant_type": self.p.grant_type, "client_id": self.p.client_id}
        if self.p.client_secret:
            payload["client_secret"] = self.p.client_secret
        if self.p.grant_type == "password":
            payload["username"] = self.p.username or ""
            payload["password"] = self.p.password or ""
        resp = await self._request("POST", f"{self.base}/oauth", json=payload)
        if resp.status_code != 200:
            raise _classify_oauth(resp)
        body = resp.json()
        token, expires = body.get("access_token"), int(body.get("expires_in") or 3600)
        if not token:
            raise ApiError("oauth response had no access_token", "auth", resp.status_code)
        _TOKENS[self._key] = _Token(token, time.monotonic() + expires * 0.8)
        return token, expires

    async def token(self) -> str:
        """Cached token, refreshed at 80% of ``expires_in``."""
        cached = _TOKENS.get(self._key)
        if cached and time.monotonic() < cached.refresh_at:
            return cached.value
        return (await self.fetch_token())[0]

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET ``/api{path}``. On 401: refresh once and retry once (CLAUDE.md §4.2)."""
        for attempt in (1, 2):
            tok = await self.token()
            resp = await self._request("GET", f"{self.base}{path}", params=params,
                                       headers={"Authorization": f"Bearer {tok}"})
            if resp.status_code == 401 and attempt == 1:
                _TOKENS.pop(self._key, None)
                continue
            if resp.status_code == 401:
                raise ApiError("401 after token refresh", "auth", 401)
            if resp.status_code == 403:
                raise ApiError(f"403 on {path}: {_error_text(resp)}", "forbidden", 403)
            if resp.status_code == 404:
                raise ApiError(f"404 on {path}", "not_found", 404)
            if resp.status_code == 500 and "insight" in resp.text.lower():
                # e.g. /api/session on 6.14 without Insight enabled: treat as unsupported
                raise ApiError(f"500 on {path}: {_error_text(resp)}", "not_found", 500)
            if resp.status_code >= 400:
                raise ApiError(f"HTTP {resp.status_code} on {path}: {_error_text(resp)}", "http", resp.status_code)
            return resp.json()
        raise ApiError("unreachable", "http")


# ------------------------------------------------------------- poll fetchers
# Shapes verified on lab CPPM 6.14.1 (docs/API_NOTES.md).

def _items(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict):
        emb = body.get("_embedded", {})
        if isinstance(emb, dict) and isinstance(emb.get("items"), list):
            return emb["items"]
        if isinstance(body.get("items"), list):
            return body["items"]
    return []


async def fetch_cluster(api: CppmApi) -> list[dict[str, Any]]:
    """GET /cluster/server → server list (uuid, management_ip, is_publisher, replication_status, ...)."""
    return _items(await api.get("/cluster/server"))


async def fetch_services(api: CppmApi, server_uuid: str) -> dict[str, dict[str, Any]]:
    """GET /server/service/{uuid} → {unit: {display_name, state, is_running, description}}."""
    body = await api.get(f"/server/service/{server_uuid}")
    return {k: v for k, v in body.items() if isinstance(v, dict) and "state" in v} if isinstance(body, dict) else {}


def pem_not_after(pem: str | None) -> datetime | None:
    """Expiry (naive UTC) from a PEM certificate, or None if it cannot be parsed."""
    if not pem or "BEGIN CERTIFICATE" not in pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("ascii", errors="ignore"))
    except ValueError:
        return None
    return cert.not_valid_after_utc.replace(tzinfo=None)


_TZ_OFFSETS = {"IST": timedelta(hours=5, minutes=30), "UTC": timedelta(0), "GMT": timedelta(0)}


def parse_cppm_date(text: str | None) -> datetime | None:
    """'Mar 12, 2027 17:10:44 IST' → naive UTC (fallback when no PEM is present)."""
    if not text:
        return None
    parts = text.rsplit(" ", 1)
    try:
        dt = datetime.strptime(parts[0], "%b %d, %Y %H:%M:%S")
    except ValueError:
        return None
    return dt - _TZ_OFFSETS.get(parts[1] if len(parts) > 1 else "UTC", timedelta(0))


async def fetch_server_certs(api: CppmApi) -> list[dict[str, Any]]:
    """GET /server-cert → [{service, cert_type, subject, issuer, valid_to, validity}] (PEM bodies dropped)."""
    out = []
    for i in _items(await api.get("/server-cert")):
        out.append({
            "service": i.get("service_name"), "cert_type": "server",
            "subject": (i.get("subject") or "")[:512], "issuer": (i.get("issued_by") or "")[:512],
            "valid_to": pem_not_after(i.get("cert_file")) or parse_cppm_date(i.get("expiry_date")),
            "validity": i.get("validity"),
        })
    return out


async def fetch_trust_list(api: CppmApi, page: int = 100, max_items: int = 2000) -> list[dict[str, Any]]:
    """GET /cert-trust-list (paged) → enabled trusted CAs with expiry parsed from the PEM."""
    out: list[dict[str, Any]] = []
    offset = 0
    while offset < max_items:
        body = await api.get("/cert-trust-list", {"limit": page, "offset": offset})
        items = _items(body)
        for i in items:
            if not i.get("enabled"):
                continue
            pem = i.get("cert_file")
            subject = issuer = None
            try:
                c = x509.load_pem_x509_certificate((pem or "").encode("ascii", errors="ignore"))
                subject, issuer = c.subject.rfc4514_string()[:512], c.issuer.rfc4514_string()[:512]
            except ValueError:
                pass
            out.append({"service": ",".join(i.get("cert_usage") or [])[:64] or None, "cert_type": "trust",
                        "subject": subject, "issuer": issuer, "valid_to": pem_not_after(pem), "validity": None})
        if len(items) < page:
            break
        offset += page
    return out


async def fetch_license_summary(api: CppmApi) -> list[dict[str, Any]]:
    """GET /application-license/summary → [{app_name, total, used}]."""
    return [{"app_name": i.get("license_type"), "total": i.get("licensed_count"), "used": i.get("used_count")}
            for i in _items(await api.get("/application-license/summary")) if i.get("license_type")]


async def fetch_license_details(api: CppmApi) -> dict[str, dict[str, Any]]:
    """GET /application-license → {product_name: {license_type, activated, added_on, expires_at}} (keys never read)."""
    out: dict[str, dict[str, Any]] = {}
    for i in _items(await api.get("/application-license")):
        name = i.get("product_name")
        if not name:
            continue
        added = None
        try:
            added = datetime.fromisoformat(i["license_added_on"]).astimezone(timezone.utc).replace(tzinfo=None) if i.get("license_added_on") else None
        except ValueError:
            pass
        dur = int(i.get("duration") or 0)
        expires = added + timedelta(days=dur) if added and dur > 0 and (i.get("duration_units") or "days") == "days" else None
        prev = out.get(name)
        if prev is None or (expires and (prev["expires_at"] is None or expires < prev["expires_at"])):
            out[name] = {"license_type": i.get("license_type"), "activated": i.get("activation_status"),
                         "added_on": added, "expires_at": expires}
    return out


async def fetch_endpoint_count(api: CppmApi) -> int | None:
    """Active endpoint count via calculate_count (never pages through endpoints)."""
    body = await api.get("/endpoint", {"calculate_count": "true", "limit": 1})
    return int(body["count"]) if isinstance(body, dict) and body.get("count") is not None else None


def _version_string(v: dict[str, Any]) -> str | None:
    parts = [v.get(k) for k in ("app_major_version", "app_minor_version", "app_service_release")]
    if all(p is not None for p in parts):
        s = ".".join(str(p) for p in parts)
        return f"{s}.{v['app_build_number']}" if v.get("app_build_number") is not None else s
    return None


HINT_IP_RESTRICTED = (
    "The CPPM refused this monitor's source IP before authentication. Allow the monitor's IP in CPPM "
    "(Administration › Server Manager › Server Configuration › select server › Network › Restrict Access) "
    "and in any firewall/ACL in front of the CPPM."
)

_HINTS = {
    "ip_restricted": HINT_IP_RESTRICTED,
    "connect": HINT_CONNECT, "timeout": HINT_CONNECT, "tls": HINT_TLS, "invalid_client": HINT_CLIENT,
    "invalid_grant": HINT_GRANT, "grant_type": HINT_GRANT_TYPE, "forbidden": HINT_FORBIDDEN,
}


async def test_api(params: ApiParams, transport: httpx.AsyncBaseTransport | None = None) -> CheckResult:
    """Test Connection: fresh OAuth token, then /cppm-version (+ /server/version if present)."""
    if not params.client_id:
        return CheckResult("api", ok=False, error="API client ID is not set", hint="Fill in the API section of the node form.")
    t0 = time.perf_counter()
    details: dict[str, Any] = {"grant_type": params.grant_type, "verify_tls": params.verify_tls}
    try:
        async with CppmApi(params, transport) as api:
            _tok, expires = await api.fetch_token()
            token_ms = (time.perf_counter() - t0) * 1000
            details["token_expires_in_s"] = expires
            details["token_ms"] = round(token_ms, 1)
            ver = await api.get("/cppm-version")
            details["cppm_version"] = _version_string(ver) if isinstance(ver, dict) else None
            if isinstance(ver, dict):
                details.update({k: ver.get(k) for k in ("hardware_version", "fips_enabled", "eval_license", "cloud_mode") if k in ver})
            try:
                sv = await api.get("/server/version")
                if isinstance(sv, dict):
                    details["server_version"] = {k: sv.get(k) for k in ("cppm_version", "guest_version", "installed_patches") if k in sv}
            except ApiError as exc:
                if exc.kind not in ("not_found", "forbidden"):
                    raise
                details["server_version"] = "unsupported" if exc.kind == "not_found" else "forbidden"
    except ApiError as exc:
        return CheckResult("api", ok=False, latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                           error=str(exc), hint=_HINTS.get(exc.kind), details={**details, "kind": exc.kind, "status": exc.status})

    summary = f"token OK ({details['token_expires_in_s']}s)"
    if details.get("cppm_version"):
        summary += f" · CPPM {details['cppm_version']}"
    return CheckResult("api", ok=True, latency_ms=details["token_ms"], summary=summary, details=details)
