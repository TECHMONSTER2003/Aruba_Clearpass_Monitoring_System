"""Local login (bcrypt), Flask-Login wiring and role guard."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from functools import wraps
from typing import Any
from urllib.parse import urlsplit

import bcrypt
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from cppmmon.db.models import AuditLog, User
from cppmmon.db.session import session_scope, utcnow

log = logging.getLogger("cppmmon.web.auth")
bp = Blueprint("auth", __name__)
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"

# Constant-cost dummy hash so unknown usernames take as long as wrong passwords.
_DUMMY_HASH = bcrypt.hashpw(b"cppmmon-timing-equaliser", bcrypt.gensalt(rounds=12))


class SessionUser(UserMixin):
    """Lightweight user object kept in the Flask-Login session."""

    def __init__(self, uid: int, username: str, role: str) -> None:
        self.id = uid
        self.username = username
        self.role = role

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


@login_manager.user_loader
def _load_user(user_id: str) -> SessionUser | None:
    try:
        with session_scope() as s:
            u = s.get(User, int(user_id))
            return SessionUser(u.id, u.username, u.role) if u else None
    except (SQLAlchemyError, ValueError) as exc:
        log.error("user load failed", extra={"error": exc.__class__.__name__})
        return None


def hash_password(password: str) -> str:
    """bcrypt-hash a password (cost 12)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, password_hash: str | None) -> bool:
    """Check a password; always spends one bcrypt round even for unknown users."""
    target = password_hash.encode("ascii") if password_hash else _DUMMY_HASH
    ok = bcrypt.checkpw(password.encode("utf-8"), target)
    return ok and password_hash is not None


def admin_required(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Route guard: 403 unless the current user is an admin."""

    @wraps(fn)
    @login_required
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


def _safe_next(target: str | None) -> str:
    if target and not urlsplit(target).netloc and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("main.dashboard")


@bp.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """Render the login page / authenticate."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    error: str | None = None
    username = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()[:64]
        password = request.form.get("password") or ""
        try:
            with session_scope() as s:
                user = s.scalar(select(User).where(User.username == username))
                ok = verify_password(password, user.password_hash if user else None)
                s.add(AuditLog(user=username or None, action="login.success" if ok else "login.failure",
                               target=request.remote_addr, detail=None))
                if ok and user is not None:
                    user.last_login = utcnow()
                    login_user(SessionUser(user.id, user.username, user.role), remember=False)
                    log.info("login ok", extra={"user": username, "src": request.remote_addr})
                    return redirect(_safe_next(request.args.get("next")))
        except SQLAlchemyError as exc:
            log.error("login db error", extra={"error": exc.__class__.__name__})
            error = "Database unavailable. Check the cppmmon services and try again."
        else:
            log.warning("login failed", extra={"user": username, "src": request.remote_addr})
            time.sleep(0.4)
            error = "Invalid username or password."
    return render_template("login.html", error=error, username=username)


@bp.post("/logout")
@login_required
def logout() -> Any:
    """End the session (POST + CSRF only)."""
    log.info("logout", extra={"user": current_user.username})
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
