"""Config loader: defaults are safe and secrets are never defaulted or printed."""

import pytest

from core.config import Settings


def test_defaults_match_decisions() -> None:
    s = Settings(_env_file=None)
    assert s.gemini_model == "gemini-3.5-flash-lite"
    assert s.approval_expiry_minutes == 15
    assert s.audit_hash_algorithm == "sha256"


def test_secrets_have_no_default() -> None:
    s = Settings(_env_file=None)
    assert s.gemini_api_key is None
    assert s.postgres_password is None
    assert s.approver_password is None


def test_missing_gemini_key_raises() -> None:
    s = Settings(_env_file=None)
    with pytest.raises(RuntimeError):
        s.require_gemini_key()


def test_missing_db_password_raises() -> None:
    s = Settings(_env_file=None)
    with pytest.raises(RuntimeError):
        _ = s.database_url


def test_secret_not_leaked_in_repr() -> None:
    s = Settings(_env_file=None, gemini_api_key="not-a-real-key-123456")
    assert "not-a-real-key-123456" not in repr(s)
