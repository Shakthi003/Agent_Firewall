"""Structured logging: one JSON object per line on stderr.

Call `configure_logging()` once at start-up. Every record has `time`, `level`, `logger` and
`message`. Audit events (logger `agent_firewall.audit`) are already JSON, so they are embedded as
an `event` object instead of an escaped string. Exceptions are logged as `exc_type` only, never a
stack trace, so a log line cannot leak internals or argument values.
"""

import json
import logging
import sys
from datetime import UTC, datetime

AUDIT_LOGGER = "agent_firewall.audit"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        line: dict[str, object] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
        }
        message = record.getMessage()
        if record.name == AUDIT_LOGGER:
            try:
                line["event"] = json.loads(message)
            except ValueError:
                line["message"] = message
        else:
            line["message"] = message
        if record.exc_info and record.exc_info[0] is not None:
            line["exc_type"] = record.exc_info[0].__name__
        return json.dumps(line, sort_keys=True, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
