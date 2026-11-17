from __future__ import annotations

import pytest

from cppmmon import crypto


def test_roundtrip() -> None:
    token = crypto.encrypt("s3cret-community")
    assert token and "s3cret" not in token
    assert crypto.decrypt(token) == "s3cret-community"


def test_empty_values_stay_none() -> None:
    assert crypto.encrypt("") is None
    assert crypto.encrypt(None) is None
    assert crypto.decrypt(None) is None


def test_tampered_token_raises() -> None:
    token = crypto.encrypt("x")
    assert token
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt(token[:-4] + "AAAA")
