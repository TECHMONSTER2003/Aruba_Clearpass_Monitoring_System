"""Engine + session factory shared by all services."""
from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from cppmmon.config import get_settings

log = logging.getLogger(__name__)


def utcnow() -> datetime:
    """Naive UTC 'now' (the storage convention for every DATETIME column)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _sqlite_pragmas(dbapi_conn, _record) -> None:  # type: ignore[no-untyped-def]
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


@lru_cache(maxsize=1)
def get_engine(url: str | None = None) -> Engine:
    """Create (once) the SQLAlchemy engine for the configured DB URL."""
    db_url = url or get_settings().db_url.get_secret_value()
    if db_url.startswith("sqlite"):
        engine = create_engine(db_url, future=True)
        event.listen(engine, "connect", _sqlite_pragmas)
    else:
        engine = create_engine(
            db_url,
            future=True,
            pool_pre_ping=True,
            pool_recycle=1800,
            pool_size=5,
            max_overflow=5,
            connect_args={"charset": "utf8mb4"},
        )
    log.info("db engine created", extra={"dialect": engine.dialect.name})
    return engine


@lru_cache(maxsize=1)
def _factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back and re-raise on error."""
    session = _factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
