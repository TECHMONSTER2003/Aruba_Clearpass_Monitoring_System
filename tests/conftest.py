"""Test fixtures: isolated SQLite DB + Fernet key in a temp dir, never /etc."""
from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point settings at a temp SQLite DB + key and reset all cached singletons."""
    key = tmp_path / "secret.key"
    key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv("CPPMMON_DB_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("CPPMMON_SECRET_KEY_FILE", str(key))
    monkeypatch.setenv("CPPMMON_LOG_DIR", str(tmp_path / "log"))
    monkeypatch.setenv("CPPMMON_DATA_DIR", str(tmp_path / "data"))
    # Ignore any real /etc/cppmmon/cppmmon.env on the host running the tests.
    monkeypatch.setitem(os.environ, "CPPMMON_WEB_SECRET", "test-secret")

    from cppmmon import config, crypto
    from cppmmon.db import session
    from cppmmon.db.models import Base

    config.get_settings.cache_clear()
    crypto._fernet.cache_clear()
    session.get_engine.cache_clear()
    session._factory.cache_clear()
    Base.metadata.create_all(session.get_engine())
    yield tmp_path
    session.get_engine().dispose()
    config.get_settings.cache_clear()
    crypto._fernet.cache_clear()
    session.get_engine.cache_clear()
    session._factory.cache_clear()
