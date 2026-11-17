"""Render tests for the event and catalog pages (and later dashboards)."""
from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from cppmmon.catalog import loader
from cppmmon.config import get_settings
from cppmmon.crypto import encrypt
from cppmmon.db.models import Node, NodeState, TrapCatalog, User
from cppmmon.db.session import session_scope
from cppmmon.receiver.directory import load_snapshot
from cppmmon.receiver.persist import persist_batch, record_hash
from cppmmon.web.app import create_app
from cppmmon.web.auth import hash_password

SEED = Path(__file__).resolve().parents[1] / "catalog" / "cppm_traps.yaml"
B = "1.3.6.1.4.1.14823.1.6.1.1.200"


@pytest.fixture()
def client(tmp_path: Path) -> FlaskClient:
    with session_scope() as s:
        s.add(User(username="adm", password_hash=hash_password("pw-1234567890"), role="admin"))
        loader.apply(s, loader.parse(SEED.read_bytes(), SEED.name), seed=True)
        n = Node(name="cppm-lab", ip="10.0.0.5", trap_community_enc=encrypt("tc"), snmp_community_enc=encrypt("x"))
        s.add(n)
        s.flush()
        s.add(NodeState(node_id=n.id))
    snap = load_snapshot()
    ts = "2026-11-17T08:00:00.000"
    persist_batch([
        {"kind": "trap", "received_at": datetime.fromisoformat(ts), "src_ip": "10.0.0.5", "version": "2c", "community_ok": True,
         "trap_oid": f"{B}.1017", "varbinds": [(f"{B}.100.17", "Radius server")], "uptime_ticks": 100, "agent_addr": None,
         "dedup_hash": record_hash("10.0.0.5", ts, "a")},
        {"kind": "trap", "received_at": datetime.fromisoformat(ts), "src_ip": "192.0.2.1", "version": "2c", "community_ok": False,
         "trap_oid": f"{B}.9999", "varbinds": [], "uptime_ticks": 1, "agent_addr": None, "dedup_hash": record_hash("x", ts, "b")},
        {"kind": "syslog", "received_at": datetime.fromisoformat(ts), "src_ip": "10.0.0.5", "transport": "tcp",
         "msg": "<134>1 2026-11-17T13:30:00+05:30 cppm CPPM - - - CEF:0|Aruba Networks|ClearPass|6.14|SystemEvents|x|5|msg=<script>",
         "truncated": False, "dedup_hash": "c"},
    ], snap)
    c = create_app(get_settings(), testing=True).test_client()
    c.post("/login", data={"username": "adm", "password": "pw-1234567890"})
    return c


def test_traps_page_and_tail(client: FlaskClient) -> None:
    html = client.get("/traps").get_data(as_text=True)
    assert "cppmServiceStopNotification" in html and "Radius server" in html
    assert "UNKNOWN_TRAP" in html and "Unregistered" in html
    r = client.get("/traps/rows?after_id=0")
    assert r.status_code == 200 and r.headers["X-Max-Id"] == "2"
    r2 = client.get("/traps/rows?after_id=2")
    assert r2.get_data(as_text=True).strip() == "" and r2.headers["X-Max-Id"] == "2"
    assert "UNKNOWN_TRAP" in client.get("/traps?kind=unknown").get_data(as_text=True)
    assert "cppmServiceStop" not in client.get("/traps?kind=badcomm").get_data(as_text=True)


def test_syslog_page_escapes_messages(client: FlaskClient) -> None:
    html = client.get("/syslog").get_data(as_text=True)
    assert "cef" in html and "&lt;script&gt;" in html and "<script>" not in html.split("</table>")[0].split("<tbody")[1]
    assert client.get("/syslog/rows?after_id=0").headers["X-Max-Id"] == "1"


def test_catalog_upload_preview_apply(client: FlaskClient) -> None:
    assert "cppmServiceStopNotification" in client.get("/catalog/").get_data(as_text=True)
    csv = f"oid,name,severity\n{B}.1017,cppmServiceStopNotification,critical\n{B}.3000,myTrap,low\n".encode()
    r = client.post("/catalog/preview", data={"file": (io.BytesIO(csv), "db.csv")}, content_type="multipart/form-data")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "myTrap" in html and "critical" in html
    token = html.split('name="token" value="')[1].split('"')[0]
    client.post("/catalog/apply", data={"token": token})
    with session_scope() as s:
        assert s.get(TrapCatalog, f"{B}.3000").name == "myTrap"
        assert s.get(TrapCatalog, f"{B}.1017").severity == "critical"
    assert client.post("/catalog/apply", data={"token": "../../etc/passwd"}).status_code == 400
