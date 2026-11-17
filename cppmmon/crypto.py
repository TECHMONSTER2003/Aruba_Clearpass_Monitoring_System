"""Fernet helpers for credentials stored at rest (``*_enc`` columns)."""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from cppmmon.config import get_settings

log = logging.getLogger(__name__)


class CryptoError(Exception):
    """Raised when a secret cannot be decrypted (wrong key or corrupt value)."""


@lru_cache(maxsize=1)
def _fernet(key_file: Path | None = None) -> Fernet:
    path = key_file or get_settings().secret_key_file
    try:
        key = path.read_bytes().strip()
    except OSError as exc:
        raise CryptoError(f"cannot read secret key file {path}: {exc.strerror}") from exc
    return Fernet(key)


def encrypt(plaintext: str | None) -> str | None:
    """Encrypt ``plaintext``. ``None`` and empty strings stay ``None``."""
    if not plaintext:
        return None
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str | None) -> str | None:
    """Decrypt a value produced by :func:`encrypt`. Never logs the value."""
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        log.error("secret decrypt failed (key mismatch or corrupt value)")
        raise CryptoError("decrypt failed") from exc


def generate_key() -> bytes:
    """Return a new Fernet key (used by install.sh via the admin CLI)."""
    return Fernet.generate_key()
