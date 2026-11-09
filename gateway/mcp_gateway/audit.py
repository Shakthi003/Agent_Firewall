"""Audit events (Stage 2 interface; Stage 5 adds the hash-chained PostgreSQL store).

One event per request. The gateway builds events that follow `docs/threat-model.md` section 5:
the raw API key is never recorded. Arguments are recorded as their names, a hash of the full
original arguments, and a redacted copy (`sanitized_args`, see `monitoring/audit/redact.py`).

Three fields are deliberately separate (AC-35): `decision` is what the policy engine said,
`enforcement_action` is what the gateway then did, and `anomaly_score` is what the behaviour
monitor thought. The score never feeds back into the decision.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Literal, Protocol

ExecutionStatus = Literal["not_executed", "ok", "tool_error", "timeout", "error"]
Method = Literal["tools/list", "tools/call", "approval/decide"]

logger = logging.getLogger("agent_firewall.audit")


def enforcement_for(method: str, decision: str) -> str:
    """What the gateway did, derived from the request kind and the decision."""
    if method == "approval/decide":
        return "recorded" if decision in ("APPROVED", "REJECTED") else "blocked"
    if decision == "ALLOW":
        return "listed" if method == "tools/list" else "forwarded"
    if decision == "REQUIRE_APPROVAL":
        return "paused"
    return "blocked"


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
    approval_id: str | None = None  # Stage 4: the approval this call created or spent
    approver_id: str | None = None  # Stage 4: who approved or rejected (approval/decide only)
    sanitized_args: dict[str, Any] = field(default_factory=dict)  # Stage 5: redacted, never raw
    enforcement_action: str | None = None  # Stage 5: derived from method + decision if not given
    anomaly_score: float | None = None  # Stage 5: set by the behaviour monitor, 0.0 to 1.0
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.enforcement_action is None:
            object.__setattr__(
                self, "enforcement_action", enforcement_for(self.method, self.decision)
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        """Rebuild an event from its stored JSON form (lists become tuples again)."""
        known = {f.name for f in fields(cls)}
        values = {k: v for k, v in data.items() if k in known}
        for name in ("arg_names", "spoofed_fields"):
            if name in values:
                values[name] = tuple(values[name])
        return cls(**values)


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...

    def check(self) -> None:
        """Raise if events can no longer be recorded. The gateway calls this before it forwards
        anything, so an unavailable audit store means a denial, not an unrecorded call."""
        ...


class InMemoryAuditSink:
    """Keeps events in a list. For tests and local runs."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    def check(self) -> None:
        return None


class LoggingAuditSink:
    """Writes each event as one JSON log line."""

    def record(self, event: AuditEvent) -> None:
        logger.info(json.dumps(asdict(event), sort_keys=True, default=str))

    def check(self) -> None:
        return None


class FanOutAuditSink:
    """Writes every event to several sinks. All sinks are tried even if one fails; the first
    failure is raised afterwards, and `check` fails if any sink's check fails."""

    def __init__(self, sinks: Sequence[AuditSink]) -> None:
        self._sinks = tuple(sinks)

    def record(self, event: AuditEvent) -> None:
        first: Exception | None = None
        for sink in self._sinks:
            try:
                sink.record(event)
            except Exception as exc:
                first = first or exc
        if first is not None:
            raise first

    def check(self) -> None:
        for sink in self._sinks:
            sink.check()


def hash_args(args: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON form of the arguments."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
