"""Runtime configuration, read from the environment / /etc/cppmmon/cppmmon.env."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All tunables for every cppmmon service. Prefix: ``CPPMMON_``."""

    model_config = SettingsConfigDict(
        env_prefix="CPPMMON_",
        env_file="/etc/cppmmon/cppmmon.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database. SQLAlchemy URL, e.g. mysql+pymysql://cppmmon:***@127.0.0.1/cppmmon
    db_url: SecretStr = SecretStr("sqlite:////var/lib/cppmmon/cppmmon.db")

    # Paths
    secret_key_file: Path = Path("/etc/cppmmon/secret.key")
    data_dir: Path = Path("/var/lib/cppmmon")
    log_dir: Path = Path("/var/log/cppmmon")

    # Web
    web_secret: SecretStr = SecretStr("")
    web_session_hours: int = 8
    web_cookie_secure: bool = False  # True once served behind HTTPS

    # Receiver
    receiver_bind: str = "0.0.0.0"
    receiver_trap_port: int = 162
    receiver_syslog_port: int = 514
    syslog_max_bytes: int = 65536
    syslog_repeat_window_s: int = 60  # 0 disables repeat suppression

    # Retention (DESIGN §6), days
    retain_raw_syslog_days: int = 30
    retain_raw_traps_days: int = 90
    retain_events_days: int = 30
    retain_metrics_days: int = 7
    retain_metrics_5m_days: int = 90

    # Presentation: everything is stored in UTC, rendered in this zone
    display_tz: str = "Asia/Kolkata"

    # Certificates polled over REST (CPPM server-cert service names). Anything else is only
    # alerted when CPPM itself reports it (trap 1003 / syslog).
    cert_monitor_services: str = "RADIUS,HTTPS(RSA)"

    # Tickets (DESIGN §8)
    ticket_assignment_group: str = "Network Operations"
    ticket_caller: str = "CPPM-Monitor (automation)"

    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")

    @property
    def spool_dir(self) -> Path:
        """Directory for JSONL spool files written while the DB is unavailable."""
        return self.data_dir / "spool"

    @property
    def tickets_dir(self) -> Path:
        """Root directory for ticket .txt files and alerts.log."""
        return self.data_dir / "tickets"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
