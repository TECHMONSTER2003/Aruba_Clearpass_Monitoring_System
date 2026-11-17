"""SQLAlchemy models. One-to-one with docs/DESIGN.md §6 (MySQL 8, InnoDB, utf8mb4).

All timestamps are stored as naive UTC.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# BIGINT PK on MySQL; SQLite only auto-increments a plain INTEGER PK.
BigId = BigInteger().with_variant(Integer(), "sqlite")
# DATETIME(3) on MySQL for millisecond ordering of ingest rows.
TsMs = DateTime().with_variant(mysql.DATETIME(fsp=3), "mysql")
LongText = Text().with_variant(mysql.MEDIUMTEXT(), "mysql")

SEVERITIES = ("critical", "high", "medium", "low", "info")


class Base(DeclarativeBase):
    """Declarative base for every cppmmon table."""


# Every table: InnoDB + utf8mb4 on MySQL (ignored by SQLite).
_MYSQL: dict[str, Any] = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

# ---------------------------------------------------------------- inventory


class Node(Base):
    __tablename__ = "nodes"
    __table_args__ = _MYSQL

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    site: Mapped[Optional[str]] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(Enum("publisher", "subscriber", "unknown", name="node_role"), default="unknown")
    snmp_version: Mapped[str] = mapped_column(Enum("2c", "3", name="snmp_version"), default="2c")
    snmp_community_enc: Mapped[Optional[str]] = mapped_column(Text)
    snmp_v3_user: Mapped[Optional[str]] = mapped_column(String(64))
    snmp_v3_auth_proto: Mapped[Optional[str]] = mapped_column(String(16))
    snmp_v3_auth_key_enc: Mapped[Optional[str]] = mapped_column(Text)
    snmp_v3_priv_proto: Mapped[Optional[str]] = mapped_column(String(16))
    snmp_v3_priv_key_enc: Mapped[Optional[str]] = mapped_column(Text)
    snmp_port: Mapped[int] = mapped_column(Integer, default=161)
    api_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # OAuth grant: DESIGN assumes client_credentials; the lab API client is a
    # public client using the password grant, so both are supported.
    api_grant_type: Mapped[str] = mapped_column(
        Enum("client_credentials", "password", name="api_grant_type"), default="client_credentials"
    )
    api_client_id: Mapped[Optional[str]] = mapped_column(String(128))
    api_client_secret_enc: Mapped[Optional[str]] = mapped_column(Text)
    api_username: Mapped[Optional[str]] = mapped_column(String(128))
    api_password_enc: Mapped[Optional[str]] = mapped_column(Text)
    api_verify_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    trap_community_enc: Mapped[Optional[str]] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    maintenance_until: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class NodeState(Base):
    __tablename__ = "node_state"
    __table_args__ = _MYSQL

    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(Enum("up", "degraded", "down", "unknown", name="node_status"), default="unknown")
    sys_index: Mapped[Optional[int]] = mapped_column(Integer)
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    version: Mapped[Optional[str]] = mapped_column(String(64))
    model: Mapped[Optional[str]] = mapped_column(String(64))
    serial: Mapped[Optional[str]] = mapped_column(String(64))
    node_type: Mapped[Optional[str]] = mapped_column(String(32))
    cluster_size: Mapped[Optional[int]] = mapped_column(Integer)
    cluster_uuid: Mapped[Optional[str]] = mapped_column(String(64))
    uptime_s: Mapped[Optional[int]] = mapped_column(BigInteger)
    api_state: Mapped[Optional[str]] = mapped_column(String(32))  # ok | auth_failed | unreachable | disabled
    last_icmp_ok: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_snmp_ok: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_api_ok: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_trap_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_syslog_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_test_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_test: Mapped[Optional[dict]] = mapped_column(JSON)  # Test Connection result (no secrets)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


# -------------------------------------------------------------- time series


class Metric(Base):
    __tablename__ = "metrics"
    __table_args__ = (Index("ix_metrics_node_metric_ts", "node_id", "metric", "ts"), _MYSQL)

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(TsMs)
    metric: Mapped[str] = mapped_column(String(64))
    value: Mapped[float] = mapped_column(Float)
    instance: Mapped[str] = mapped_column(String(128), default="")


class Metric5m(Base):
    __tablename__ = "metrics_5m"
    __table_args__ = _MYSQL

    node_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    metric: Mapped[str] = mapped_column(String(64), primary_key=True)
    instance: Mapped[str] = mapped_column(String(128), primary_key=True, default="")
    bucket: Mapped[datetime] = mapped_column(DateTime, primary_key=True)
    avg: Mapped[float] = mapped_column(Float)
    min: Mapped[float] = mapped_column(Float)
    max: Mapped[float] = mapped_column(Float)


class CounterState(Base):
    __tablename__ = "counter_state"
    __table_args__ = _MYSQL

    node_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    metric: Mapped[str] = mapped_column(String(64), primary_key=True)
    instance: Mapped[str] = mapped_column(String(128), primary_key=True, default="")
    last_value: Mapped[int] = mapped_column(BigInteger)
    last_ts: Mapped[datetime] = mapped_column(TsMs)


class ServiceStatus(Base):
    __tablename__ = "service_status"
    __table_args__ = _MYSQL

    node_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    status: Mapped[str] = mapped_column(String(32))
    raw: Mapped[Optional[dict]] = mapped_column(JSON)
    ts: Mapped[datetime] = mapped_column(DateTime)


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (Index("ix_certificates_node", "node_id"), _MYSQL)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer)
    cert_type: Mapped[str] = mapped_column(String(32))
    service: Mapped[Optional[str]] = mapped_column(String(64))
    subject: Mapped[Optional[str]] = mapped_column(String(512))
    issuer: Mapped[Optional[str]] = mapped_column(String(512))
    valid_to: Mapped[Optional[datetime]] = mapped_column(DateTime)
    days_left: Mapped[Optional[int]] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(DateTime)


class License(Base):
    __tablename__ = "licenses"
    __table_args__ = _MYSQL

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[Optional[int]] = mapped_column(Integer)
    app_name: Mapped[str] = mapped_column(String(128))
    total: Mapped[Optional[int]] = mapped_column(Integer)
    used: Mapped[Optional[int]] = mapped_column(Integer)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    license_type: Mapped[Optional[str]] = mapped_column(String(32))  # Permanent / Evaluation / Subscription
    activated: Mapped[Optional[bool]] = mapped_column(Boolean)
    added_on: Mapped[Optional[datetime]] = mapped_column(DateTime)
    ts: Mapped[datetime] = mapped_column(DateTime)


class PollRequest(Base):
    """'Poll now' requests from the UI; the poller picks them up within ~2 s."""

    __tablename__ = "poll_requests"
    __table_args__ = (Index("ix_poll_requests_picked", "picked_at"), _MYSQL)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[Optional[int]] = mapped_column(Integer)  # NULL = all enabled nodes
    requested_by: Mapped[Optional[str]] = mapped_column(String(64))
    requested_at: Mapped[datetime] = mapped_column(DateTime)
    picked_at: Mapped[Optional[datetime]] = mapped_column(DateTime)


# ---------------------------------------------------------- reactive ingest


class TrapCatalog(Base):
    __tablename__ = "trap_catalog"
    __table_args__ = _MYSQL

    oid: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    category: Mapped[Optional[str]] = mapped_column(String(64))
    alarm_type: Mapped[Optional[str]] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(Enum(*SEVERITIES, name="severity"), default="info")
    create_ticket: Mapped[bool] = mapped_column(Boolean, default=False)
    clear_oid: Mapped[Optional[str]] = mapped_column(Text)  # comma-separated: a stop can be cleared by start OR restart
    clear_match_field: Mapped[Optional[str]] = mapped_column(String(64))
    dedup_field: Mapped[Optional[str]] = mapped_column(String(64))
    title_tpl: Mapped[Optional[str]] = mapped_column(Text)
    description_tpl: Mapped[Optional[str]] = mapped_column(Text)
    recommended_action: Mapped[Optional[str]] = mapped_column(Text)
    source_ref: Mapped[Optional[str]] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class VarbindCatalog(Base):
    __tablename__ = "varbind_catalog"
    __table_args__ = _MYSQL

    oid_prefix: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))


class RawTrap(Base):
    __tablename__ = "raw_traps"
    __table_args__ = (
        Index("ix_raw_traps_received", "received_at"),
        Index("ix_raw_traps_node_received", "node_id", "received_at"),
        _MYSQL,
    )

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(TsMs)
    src_ip: Mapped[str] = mapped_column(String(45))
    node_id: Mapped[Optional[int]] = mapped_column(Integer)
    snmp_version: Mapped[str] = mapped_column(String(4))
    community_ok: Mapped[bool] = mapped_column(Boolean)
    trap_oid: Mapped[Optional[str]] = mapped_column(String(128))
    trap_name: Mapped[Optional[str]] = mapped_column(String(128))
    varbinds: Mapped[Optional[dict]] = mapped_column(JSON)
    dedup_hash: Mapped[Optional[str]] = mapped_column(String(40), unique=True)  # spool replay idempotency


class RawSyslog(Base):
    __tablename__ = "raw_syslog"
    __table_args__ = (
        Index("ix_raw_syslog_received", "received_at"),
        Index("ix_raw_syslog_node_received", "node_id", "received_at"),
        _MYSQL,
    )

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(TsMs)
    src_ip: Mapped[str] = mapped_column(String(45))
    node_id: Mapped[Optional[int]] = mapped_column(Integer)
    transport: Mapped[str] = mapped_column(String(8))
    facility: Mapped[Optional[int]] = mapped_column(SmallInteger)
    severity: Mapped[Optional[int]] = mapped_column(SmallInteger)
    host: Mapped[Optional[str]] = mapped_column(String(255))
    app: Mapped[Optional[str]] = mapped_column(String(128))
    msg: Mapped[str] = mapped_column(LongText)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    fmt: Mapped[str] = mapped_column(
        Enum("cef", "leef", "cppm_std", "rfc5424", "rfc3164", "raw", name="syslog_fmt"), default="raw"
    )
    parsed: Mapped[Optional[dict]] = mapped_column(JSON)
    dedup_hash: Mapped[Optional[str]] = mapped_column(String(40), unique=True)


# --------------------------------------------------------------- decisioning


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_processed_id", "processed", "id"), Index("ix_events_ts", "ts"), _MYSQL)

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(TsMs)
    node_id: Mapped[Optional[int]] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(Enum("trap", "syslog", "poll", "internal", name="event_source"))
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(Enum(*SEVERITIES, name="severity"))
    is_clear: Mapped[bool] = mapped_column(Boolean, default=False)
    dedup_instance: Mapped[str] = mapped_column(String(128), default="")
    attributes: Mapped[Optional[dict]] = mapped_column(JSON)
    raw_ref: Mapped[Optional[str]] = mapped_column(String(64))
    processed: Mapped[int] = mapped_column(SmallInteger, default=0)


class Threshold(Base):
    __tablename__ = "thresholds"
    __table_args__ = _MYSQL

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    metric: Mapped[str] = mapped_column(String(64))
    instance_glob: Mapped[str] = mapped_column(String(128), default="*")
    op: Mapped[str] = mapped_column(Enum(">", ">=", "<", "<=", name="threshold_op"), default=">")
    warn_value: Mapped[Optional[float]] = mapped_column(Float)
    crit_value: Mapped[Optional[float]] = mapped_column(Float)
    clear_value: Mapped[Optional[float]] = mapped_column(Float)
    sustain_s: Mapped[int] = mapped_column(Integer, default=300)
    severity_warn: Mapped[str] = mapped_column(Enum(*SEVERITIES, name="severity"), default="medium")
    severity_crit: Mapped[str] = mapped_column(Enum(*SEVERITIES, name="severity"), default="high")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("dedup_key", "open_marker", name="uq_open"),
        Index("ix_alerts_state", "state", "last_seen"),
        Index("ix_alerts_dedup_key", "dedup_key"),
        Index("ix_alerts_node_state", "node_id", "state"),
        _MYSQL,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(255))
    open_marker: Mapped[Optional[int]] = mapped_column(SmallInteger)  # 1 while open, NULL when closed
    node_id: Mapped[Optional[int]] = mapped_column(Integer)
    rule_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(Enum(*SEVERITIES, name="severity"))
    state: Mapped[str] = mapped_column(Enum("open", "cleared", "suppressed", name="alert_state"), default="open")
    flapping: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_alert_id: Mapped[Optional[int]] = mapped_column(Integer)  # suppression parent (node down)
    suppress_reason: Mapped[Optional[str]] = mapped_column(String(32))  # node_down | maintenance
    clear_pending_at: Mapped[Optional[datetime]] = mapped_column(DateTime)  # flapping: clear after 30 min quiet
    last_update_note_at: Mapped[Optional[datetime]] = mapped_column(DateTime)  # rate-limits "re-occurred" lines
    attributes: Mapped[Optional[dict]] = mapped_column(JSON)  # first event's attributes (vb, values) for the ticket
    title: Mapped[str] = mapped_column(String(512))
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    cleared_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    ticket_id: Mapped[Optional[int]] = mapped_column(Integer)


class Ticket(Base):
    __tablename__ = "tickets"
    __table_args__ = (Index("ix_tickets_alert", "alert_id"), _MYSQL)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ticket_no: Mapped[str] = mapped_column(String(32), unique=True)
    alert_id: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    priority: Mapped[str] = mapped_column(String(16))
    short_description: Mapped[str] = mapped_column(String(512))
    file_path: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(Enum("new", "resolved", name="ticket_status"), default="new")
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)


class TicketSequence(Base):
    """Daily ticket counter (NNNN in CPPM-YYYYMMDD-NNNN). Held in the DB, never a file count."""

    __tablename__ = "ticket_seq"
    __table_args__ = _MYSQL

    day: Mapped[str] = mapped_column(String(8), primary_key=True)  # YYYYMMDD
    last_seq: Mapped[int] = mapped_column(Integer, default=0)


# ------------------------------------------------------------------------ ops


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_ts", "ts"), _MYSQL)

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    user: Mapped[Optional[str]] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[Optional[str]] = mapped_column(String(255))
    detail: Mapped[Optional[dict]] = mapped_column(JSON)


class User(Base):
    __tablename__ = "users"
    __table_args__ = _MYSQL

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(Enum("admin", "operator", "viewer", name="user_role"), default="viewer")
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ServiceHeartbeat(Base):
    """Liveness + counters each service writes periodically (feeds the Health page)."""

    __tablename__ = "service_heartbeat"
    __table_args__ = _MYSQL

    service: Mapped[str] = mapped_column(String(32), primary_key=True)
    pid: Mapped[Optional[int]] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime)
    last_beat: Mapped[datetime] = mapped_column(DateTime)
    stats: Mapped[Optional[dict]] = mapped_column(JSON)
