"""Argument redaction for the audit log (Stage 5, `docs/threat-model.md` section 5).

The audit log keeps the *shape* of a call, not its secrets. `sanitize_args` turns the raw
arguments into values that are safe to store for good:

- by field name: `password`, `token`, `secret`, `key` and similar become `[redacted]`;
  `account_number` and similar keep only the last 4 digits (`****7766`)
- by pattern: gateway-style keys (`afk_...`) and bearer tokens become `[redacted-key]`;
  any run of 8 or more digits keeps only its last 4
- long free text (comments, messages) is replaced by `[text:N chars]`; IDs and numbers stay,
  because detections need values such as `limit`

The function is idempotent, so it can be applied again at storage time as a second line of
defence. The full original arguments are never stored; only their SHA-256 (`args_hash`) is.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[redacted]"
REDACTED_KEY = "[redacted-key]"
MAX_TEXT_LENGTH = 64
MAX_DEPTH = 3

_SECRET_NAMES = ("password", "passwd", "secret", "token", "key", "credential", "authorization")
_ACCOUNT_NAMES = ("account", "iban", "card")
_KEY_PATTERN = re.compile(r"afk_[A-Za-z0-9_\-]{8,}|bearer\s+\S+", re.IGNORECASE)
_LONG_DIGITS = re.compile(r"\d{8,}")


def _last4(value: object) -> str:
    digits = re.sub(r"\D", "", str(value))
    return "****" + digits[-4:] if len(digits) >= 4 else "****"


def _redact_text(text: str) -> str:
    text = _KEY_PATTERN.sub(REDACTED_KEY, text)
    text = _LONG_DIGITS.sub(lambda m: _last4(m.group()), text)
    if len(text) > MAX_TEXT_LENGTH:
        return f"[text:{len(text)} chars]"
    return text


def _redact_value(name: str, value: Any, depth: int) -> Any:
    lowered = name.lower()
    if any(part in lowered for part in _SECRET_NAMES):
        return REDACTED
    if any(part in lowered for part in _ACCOUNT_NAMES):
        return _last4(value)
    if isinstance(value, bool) or value is None or isinstance(value, float):
        return value
    if isinstance(value, int):
        return _last4(value) if len(str(abs(value))) >= 8 else value
    if isinstance(value, str):
        return _redact_text(value)
    if depth >= MAX_DEPTH:
        return "[nested]"
    if isinstance(value, Mapping):
        return {str(k): _redact_value(str(k), v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact_value(name, v, depth + 1) for v in value]
    return _redact_text(str(value))


def sanitize_args(args: Mapping[str, Any]) -> dict[str, Any]:
    """Arguments that are safe to store permanently."""
    return {str(k): _redact_value(str(k), v, 0) for k, v in args.items()}
