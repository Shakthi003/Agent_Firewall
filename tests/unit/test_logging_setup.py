"""Structured logging: one JSON object per line, no stack traces."""

import json
import logging

from core.logging_setup import AUDIT_LOGGER, JsonFormatter


def make(name: str, message: str, *, exc: bool = False) -> dict[str, object]:
    exc_info = None
    if exc:
        try:
            raise ValueError("secret-value-123")
        except ValueError:
            import sys

            exc_info = sys.exc_info()
    record = logging.LogRecord(name, logging.INFO, __file__, 1, message, None, exc_info)
    line = JsonFormatter().format(record)
    assert "\n" not in line
    return json.loads(line)


def test_plain_record_has_time_level_logger_message() -> None:
    out = make("agent_firewall.api", "hello")
    assert out["level"] == "INFO"
    assert out["logger"] == "agent_firewall.api"
    assert out["message"] == "hello"
    assert str(out["time"]).endswith("+00:00")


def test_audit_event_is_embedded_as_an_object() -> None:
    out = make(AUDIT_LOGGER, json.dumps({"decision": "BLOCK", "tool": "x"}))
    assert out["event"] == {"decision": "BLOCK", "tool": "x"}
    assert "message" not in out


def test_exception_logs_type_only() -> None:
    out = make("agent_firewall.api", "boom", exc=True)
    assert out["exc_type"] == "ValueError"
    assert "secret-value-123" not in json.dumps(out)
