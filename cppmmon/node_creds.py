"""Build collector connection params from a ``Node`` row (decrypting secrets in memory only)."""
from __future__ import annotations

from cppmmon.collectors.types import ApiParams, SnmpParams
from cppmmon.crypto import decrypt
from cppmmon.db.models import Node


def snmp_params(node: Node) -> SnmpParams:
    """SNMP params for ``node``."""
    return SnmpParams(
        host=node.ip,
        port=node.snmp_port or 161,
        version=node.snmp_version,
        community=decrypt(node.snmp_community_enc),
        v3_user=node.snmp_v3_user,
        v3_auth_proto=node.snmp_v3_auth_proto,
        v3_auth_key=decrypt(node.snmp_v3_auth_key_enc),
        v3_priv_proto=node.snmp_v3_priv_proto,
        v3_priv_key=decrypt(node.snmp_v3_priv_key_enc),
    )


def api_params(node: Node) -> ApiParams | None:
    """API params for ``node``, or None when the API is disabled."""
    if not node.api_enabled:
        return None
    return ApiParams(
        host=node.ip,
        grant_type=node.api_grant_type or "client_credentials",
        client_id=node.api_client_id or "",
        client_secret=decrypt(node.api_client_secret_enc),
        username=node.api_username,
        password=decrypt(node.api_password_enc),
        verify_tls=bool(node.api_verify_tls),
    )
