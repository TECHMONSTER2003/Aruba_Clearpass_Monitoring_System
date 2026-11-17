from __future__ import annotations

from flask.testing import FlaskClient
import pytest

from cppmmon.config import get_settings
from cppmmon.db.models import AuditLog, User
from cppmmon.db.session import session_scope
from cppmmon.web.app import create_app
from cppmmon.web.auth import hash_password


@pytest.fixture()
def client() -> FlaskClient:
    with session_scope() as s:
        s.add(User(username="noc-admin", password_hash=hash_password("correct-horse-1"), role="admin"))
    app = create_app(get_settings(), testing=True)
    return app.test_client()


def test_login_page_renders(client: FlaskClient) -> None:
    r = client.get("/login")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "ClearPass Monitor" in body and 'name="password"' in body
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_dashboard_requires_login(client: FlaskClient) -> None:
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_wrong_password_rejected_and_audited(client: FlaskClient) -> None:
    r = client.post("/login", data={"username": "noc-admin", "password": "nope"})
    assert r.status_code == 200
    assert "Invalid username or password" in r.get_data(as_text=True)
    with session_scope() as s:
        assert s.query(AuditLog).filter_by(action="login.failure").count() == 1


def test_login_then_dashboard_and_health(client: FlaskClient) -> None:
    r = client.post("/login", data={"username": "noc-admin", "password": "correct-horse-1"})
    assert r.status_code == 302
    dash = client.get("/")
    assert dash.status_code == 200 and "No ClearPass nodes yet" in dash.get_data(as_text=True)
    assert client.get("/health").status_code == 200


def test_open_redirect_blocked(client: FlaskClient) -> None:
    r = client.post("/login?next=//evil.example/x", data={"username": "noc-admin", "password": "correct-horse-1"})
    assert r.status_code == 302 and "evil.example" not in r.headers["Location"]


def test_csrf_enforced_when_enabled() -> None:
    app = create_app(get_settings(), testing=True)
    app.config["WTF_CSRF_ENABLED"] = True
    r = app.test_client().post("/login", data={"username": "x", "password": "y"})
    assert r.status_code == 400


def test_healthz(client: FlaskClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json() == {"status": "ok", "db": "ok"}
