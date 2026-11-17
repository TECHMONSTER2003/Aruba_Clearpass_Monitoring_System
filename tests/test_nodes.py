"""Nodes CRUD: validation, write-only encrypted secrets, roles, Test Connection persistence."""
from __future__ import annotations

from typing import Any

import pytest
from flask.testing import FlaskClient
from sqlalchemy import select

from cppmmon.collectors.types import CheckResult
from cppmmon.config import get_settings
from cppmmon.crypto import decrypt
from cppmmon.db.models import Node, NodeState, User
from cppmmon.db.session import session_scope
from cppmmon.web.app import create_app
from cppmmon.web.auth import hash_password

BASE = {
    "name": "cppm-lab-01", "ip": "192.0.2.10", "site": "Lab", "snmp_version": "2c", "snmp_port": "161",
    "snmp_community": "c0mmunity-xyz", "trap_community": "trap-xyz",
    "api_enabled": "on", "api_grant_type": "password", "api_client_id": "monitor",
    "api_username": "apiuser", "api_password": "api-pass-123",
}


def _client(role: str = "admin") -> FlaskClient:
    with session_scope() as s:
        s.add(User(username=f"u-{role}", password_hash=hash_password("pw-1234567890"), role=role))
    c = create_app(get_settings(), testing=True).test_client()
    assert c.post("/login", data={"username": f"u-{role}", "password": "pw-1234567890"}).status_code == 302
    return c


def _node() -> Node:
    with session_scope() as s:
        return s.scalar(select(Node))


def test_create_encrypts_secrets_and_never_renders_them() -> None:
    c = _client()
    r = c.post("/nodes/new", data=BASE)
    assert r.status_code == 302 and "test=1" in r.headers["Location"]
    n = _node()
    assert n.snmp_community_enc and "c0mmunity" not in n.snmp_community_enc
    assert decrypt(n.snmp_community_enc) == "c0mmunity-xyz"
    assert decrypt(n.api_password_enc) == "api-pass-123" and n.api_grant_type == "password"
    page = c.get(f"/nodes/{n.id}").get_data(as_text=True)
    for secret in ("c0mmunity-xyz", "trap-xyz", "api-pass-123"):
        assert secret not in page
    assert "leave blank to keep" in page
    with session_scope() as s:
        assert s.get(NodeState, n.id) is not None


def test_edit_blank_secret_keeps_and_clear_removes() -> None:
    c = _client()
    c.post("/nodes/new", data=BASE)
    n = _node()
    upd = {**BASE, "snmp_community": "", "trap_community": "", "clear_trap_community": "on", "api_password": "", "name": "renamed"}
    assert c.post(f"/nodes/{n.id}", data=upd).status_code == 302
    n2 = _node()
    assert n2.name == "renamed"
    assert decrypt(n2.snmp_community_enc) == "c0mmunity-xyz"
    assert n2.trap_community_enc is None
    assert decrypt(n2.api_password_enc) == "api-pass-123"


@pytest.mark.parametrize(("patch", "msg"), [
    ({"ip": "300.1.1.1"}, "valid IPv4"),
    ({"snmp_community": ""}, "Community is required"),
    ({"api_password": ""}, "Password is required"),
    ({"snmp_version": "3", "snmp_v3_user": ""}, "User is required"),
    ({"snmp_version": "3", "snmp_v3_user": "mon", "snmp_v3_auth_proto": "SHA", "snmp_v3_auth_key": "short"}, "at least 8"),
])
def test_validation(patch: dict, msg: str) -> None:
    c = _client()
    r = c.post("/nodes/new", data={**BASE, **patch})
    assert r.status_code == 400 and msg in r.get_data(as_text=True)


def test_duplicate_ip_rejected() -> None:
    c = _client()
    c.post("/nodes/new", data=BASE)
    r = c.post("/nodes/new", data={**BASE, "name": "dup"})
    assert r.status_code == 400 and "already exists" in r.get_data(as_text=True)


def test_viewer_cannot_create_or_delete() -> None:
    admin = _client("admin")
    admin.post("/nodes/new", data=BASE)
    viewer = _client("viewer")
    assert viewer.post("/nodes/new", data=BASE).status_code == 403
    assert viewer.post(f"/nodes/{_node().id}/delete", data={"confirm": BASE["name"]}).status_code == 403
    assert viewer.get(f"/nodes/{_node().id}").status_code == 200


def test_delete_requires_exact_name() -> None:
    c = _client()
    c.post("/nodes/new", data=BASE)
    nid = _node().id
    c.post(f"/nodes/{nid}/delete", data={"confirm": "wrong"})
    assert _node() is not None
    from cppmmon.db.models import Alert, Event
    from cppmmon.db.session import utcnow

    with session_scope() as s:
        s.add(Alert(dedup_key=f"{nid}|node.down|", open_marker=1, node_id=nid, rule_id="node.down", severity="critical",
                    state="open", title="down", first_seen=utcnow(), last_seen=utcnow()))
    c.post(f"/nodes/{nid}/delete", data={"confirm": BASE["name"]})
    assert _node() is None
    with session_scope() as s:  # deletion queued an engine clear for the node's open alert
        ev = s.scalar(select(Event).where(Event.source == "internal"))
        assert ev.is_clear and ev.attributes["clears"] == "node.down" and "node deleted" in ev.attributes["manual_by"]


def test_cluster_discovery_adds_members_with_copied_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    members = [
        {"name": "pub.lab", "management_ip": "192.0.2.10", "is_publisher": True, "server_uuid": "u1", "replication_status": "ENABLED"},
        {"name": "sub1.lab", "management_ip": "192.0.2.11", "is_publisher": False, "server_uuid": "u2", "replication_status": "ENABLED"},
        {"name": "sub2.lab", "management_ip": "192.0.2.12", "is_publisher": False, "server_uuid": "u3", "replication_status": "ENABLED"},
    ]
    monkeypatch.setattr("cppmmon.web.routes.nodes._cluster_members", lambda src: members)
    c = _client()
    c.post("/nodes/new", data={**BASE, "ip": "192.0.2.10"})
    src = _node()
    page = c.get(f"/nodes/{src.id}/discover").get_data(as_text=True)
    assert "sub1.lab" in page and "2 not monitored yet" in page
    r = c.post(f"/nodes/{src.id}/discover", data={"ip": ["192.0.2.11"], "copy_snmp": "on", "copy_api": "on", "copy_trap": "on"})
    assert r.status_code == 302
    with session_scope() as s:
        new = s.scalar(select(Node).where(Node.ip == "192.0.2.11"))
        assert new.role == "subscriber" and new.name == "sub1.lab"
        assert decrypt(new.snmp_community_enc) == "c0mmunity-xyz" and decrypt(new.api_password_enc) == "api-pass-123"
        assert s.scalar(select(Node).where(Node.ip == "192.0.2.12")) is None  # not ticked → not added
    again = c.post(f"/nodes/{src.id}/discover", data={"ip": ["192.0.2.11"]})  # already monitored → no duplicate
    assert again.status_code == 302


def test_test_connection_persists_result(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_probe(host: str, snmp: Any, api: Any) -> list[CheckResult]:
        seen.update(host=host, community=snmp.community, api_pw=api.password)
        return [
            CheckResult("icmp", ok=True, latency_ms=0.7, summary="0.70 ms avg"),
            CheckResult("snmp", ok=True, latency_ms=12, summary="cppm-lab · index 1",
                        details={"sys_index": 1, "hostname": "cppm-lab", "version": "6.12.1"}),
            CheckResult("api", ok=False, error="invalid_client", hint="check client", details={"kind": "invalid_client"}),
        ]

    monkeypatch.setattr("cppmmon.web.routes.nodes.probe_sync", fake_probe)
    c = _client()
    c.post("/nodes/new", data=BASE)
    n = _node()
    # Blank secrets in the form → stored values are used for the test
    r = c.post("/nodes/test", data={**BASE, "node_id": n.id, "snmp_community": "", "api_password": ""})
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "2/3 checks passed" in html and "check client" in html
    assert seen == {"host": "192.0.2.10", "community": "c0mmunity-xyz", "api_pw": "api-pass-123"}
    with session_scope() as s:
        st = s.get(NodeState, n.id)
        assert st.sys_index == 1 and st.hostname == "cppm-lab" and st.api_state == "auth_failed"
        assert "c0mmunity" not in str(st.last_test)
