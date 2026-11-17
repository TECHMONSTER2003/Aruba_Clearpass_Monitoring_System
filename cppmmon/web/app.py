"""Flask application factory (gunicorn: ``cppmmon.web.app:create_app()``)."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import Flask, Response, render_template
from flask_wtf.csrf import CSRFError, CSRFProtect

from cppmmon import __version__
from cppmmon.config import Settings, get_settings
from cppmmon.logging_setup import setup_logging

log = logging.getLogger("cppmmon.web")
csrf = CSRFProtect()

_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def create_app(settings: Settings | None = None, testing: bool = False) -> Flask:
    """Build the Flask app. ``settings`` and ``testing`` are for the test-suite."""
    cfg = settings or get_settings()
    if not testing:
        setup_logging("web", cfg.log_dir, cfg.log_level)

    secret = cfg.web_secret.get_secret_value()
    if not secret and not testing:
        raise RuntimeError("CPPMMON_WEB_SECRET is not set (see /etc/cppmmon/cppmmon.env)")

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret or "test-only",
        TESTING=testing,
        WTF_CSRF_ENABLED=not testing,
        WTF_CSRF_TIME_LIMIT=None,  # token lives as long as the session
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cfg.web_cookie_secure,
        SESSION_COOKIE_NAME="cppmmon_session",
        REMEMBER_COOKIE_DURATION=timedelta(hours=cfg.web_session_hours),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=cfg.web_session_hours),
        CPPMMON_SETTINGS=cfg,
    )

    csrf.init_app(app)

    from cppmmon.web.auth import bp as auth_bp
    from cppmmon.web.auth import login_manager
    from cppmmon.web.routes.main import bp as main_bp
    from cppmmon.web.routes.alerts import bp as alerts_bp
    from cppmmon.web.routes.catalog import bp as catalog_bp
    from cppmmon.web.routes.events import bp as events_bp
    from cppmmon.web.routes.nodes import bp as nodes_bp

    login_manager.init_app(app)
    for bp in (auth_bp, main_bp, nodes_bp, events_bp, catalog_bp, alerts_bp):
        app.register_blueprint(bp)

    @app.errorhandler(403)
    def _forbidden(_err: Exception) -> tuple[str, int]:
        return render_template("error.html", code=403, title="Not allowed",
                               message="Your role cannot perform this action. Ask an administrator."), 403

    tz = ZoneInfo(cfg.display_tz)

    @app.template_filter("localtime")
    def _localtime(value: datetime | None, fmt: str = "%d %b %Y %H:%M:%S") -> str:
        """Render a naive-UTC datetime in the display zone."""
        if value is None:
            return "—"
        return value.replace(tzinfo=timezone.utc).astimezone(tz).strftime(fmt)

    @app.template_filter("ago")
    def _ago(value: datetime | None) -> str:
        """Human 'time since' for a naive-UTC datetime."""
        if value is None:
            return "never"
        secs = int((datetime.now(timezone.utc).replace(tzinfo=None) - value).total_seconds())
        if secs < 60:
            return f"{max(secs, 0)}s ago"
        if secs < 3600:
            return f"{secs // 60}m ago"
        if secs < 86400:
            return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"

    @app.context_processor
    def _globals() -> dict[str, object]:
        return {"app_version": __version__, "display_tz": cfg.display_tz, "tz_label": "IST" if cfg.display_tz == "Asia/Kolkata" else cfg.display_tz}

    @app.after_request
    def _security_headers(resp: Response) -> Response:
        resp.headers.setdefault("Content-Security-Policy", _CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    @app.errorhandler(CSRFError)
    def _csrf_error(err: CSRFError) -> tuple[str, int]:
        log.warning("csrf rejected", extra={"reason": err.description})
        return render_template("error.html", code=400, title="Session expired",
                               message="Your form session expired. Go back, reload the page and try again."), 400

    @app.errorhandler(404)
    def _not_found(_err: Exception) -> tuple[str, int]:
        return render_template("error.html", code=404, title="Page not found",
                               message="The page you asked for does not exist."), 404

    @app.errorhandler(500)
    def _server_error(err: Exception) -> tuple[str, int]:
        log.error("unhandled error", exc_info=err)
        return render_template("error.html", code=500, title="Something went wrong",
                               message="The error has been logged. Check /var/log/cppmmon/web.log."), 500

    log.info("web app created", extra={"version": __version__})
    return app
