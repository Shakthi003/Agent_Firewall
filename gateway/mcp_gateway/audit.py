"""Audit events (Stage 2 interface; the PostgreSQL hash-chained store arrives in Stage 5).

One event per request. The gateway builds events that follow `docs/threat-model.md` section 5:
the raw API key is never recorded, and arguments are recorded only as their names plus a hash
of the full original arguments, never as values.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Protocol

ExecutionStatus = Literal["not_executed", "ok", "tool_error", "timeout", "error"]
Method = Literal["tools/list", "tools/call"]

logger = logging.getLogger("agent_firewall.audit")


@dataclass(frozen=True)
class AuditEvent:
    timestamp: float
    correlation_id: str
    method: Method
    decision: str
    reason_code: str
    agent_id: str | None = None
    role: str | None = None
    key_version: int | None = None
    auth_failure: str | None = None
    tool: str | None = None
    server: str | None = None
    policy_version: str | None = None
    args_hash: str | None = None
    arg_names: tuple[str, ...] = ()
    spoofed_fields: tuple[str, ...] = ()
    spoof_attempt: bool = False
    execution_status: ExecutionStatus = "not_executed"
    latency_ms: float = 0.0
    tool_count: int | None = None  # tools/list only: how many tools were returned
    extra: dict[str, Any] = field(default_factory=dict)


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...


class InMemoryAuditSink:
    """Keeps events in a list. For tests and local runs."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class LoggingAuditSink:
    """Writes each event as one JSON log line (the default until Stage 5)."""

    def record(self, event: AuditEvent) -> None:
        logger.info(json.dumps(asdict(event), sort_keys=True, default=str))


def hash_args(args: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON form of the arguments."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
