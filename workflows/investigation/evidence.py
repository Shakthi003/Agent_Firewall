"""Read-only audit evidence for the investigation workflow (Stage 6, AC-42).

`AuditEvidence` is the workflow's ONLY window onto the system. It can do two things: fetch
sanitized audit events (with the alerts that point at them) and verify the hash chain. It is
built on two narrow read-only protocols, so it has no way to write an event, create an alert,
change a policy, approve a request or call a tool. `READ_ONLY_TOOLS` lists everything the
workflow may ever do, and a test pins that list.

Everything handed to the LLM is data, not instructions: events are passed through
`sanitize_args` a second time, and long free text is already replaced by a length marker in the
store, so hostile text from a tool result cannot reach the model through this path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from monitoring.audit.redact import sanitize_args
from monitoring.audit.store import StoredEvent, VerifyResult
from monitoring.detection.rules import Alert

READ_ONLY_TOOLS = ("fetch_events", "verify_chain")

# Fields of an audit event shown to the model. Keys, hashes of keys and raw args are not here.
_EVENT_FIELDS = (
    "timestamp",
    "correlation_id",
    "method",
    "agent_id",
    "role",
    "tool",
    "decision",
    "reason_code",
    "enforcement_action",
    "execution_status",
    "policy_version",
    "auth_failure",
    "spoof_attempt",
    "spoofed_fields",
    "approval_id",
    "approver_id",
    "anomaly_score",
    "arg_names",
)


class EventSource(Protocol):
    def events(
        self,
        *,
        after_seq: int = 0,
        limit: int | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> list[StoredEvent]: ...

    def verify(self) -> VerifyResult: ...


class AlertSource(Protocol):
    def list_alerts(
        self, *, agent_id: str | None = None, rule: str | None = None
    ) -> list[Alert]: ...


@dataclass(frozen=True)
class Evidence:
    events: list[dict[str, Any]]  # each has `event_id` (the audit seq)
    alerts: list[dict[str, Any]]  # each cites `event_ids` (audit seqs)
    truncated: bool

    @property
    def seqs(self) -> set[int]:
        return {e["event_id"] for e in self.events}


class AuditEvidence:
    def __init__(self, source: EventSource, alerts: AlertSource | None = None) -> None:
        self._source = source
        self._alerts = alerts

    def fetch_events(
        self,
        *,
        agent_id: str | None = None,
        after_seq: int = 0,
        limit: int = 200,
        correlation_id: str | None = None,
    ) -> Evidence:
        # One extra row tells us whether the limit cut something off.
        stored = self._source.events(
            after_seq=after_seq, limit=limit + 1, agent_id=agent_id, correlation_id=correlation_id
        )
        truncated = len(stored) > limit
        stored = stored[:limit]
        events = [_view(s) for s in stored]
        seq_of = {s.event.correlation_id: s.seq for s in stored}
        return Evidence(events, self._alerts_for(agent_id, seq_of), truncated)

    def verify_chain(self) -> VerifyResult:
        return self._source.verify()

    def _alerts_for(self, agent_id: str | None, seq_of: dict[str, int]) -> list[dict[str, Any]]:
        if self._alerts is None:
            return []
        found: list[dict[str, Any]] = []
        for alert in self._alerts.list_alerts(agent_id=agent_id):
            ids = sorted({seq_of[c] for c in alert.evidence if c in seq_of})
            if ids:  # an alert about events outside this scope is not evidence here
                found.append(
                    {
                        "rule": alert.rule,
                        "severity": alert.severity,
                        "agent_id": alert.agent_id,
                        "detail": alert.detail,
                        "event_ids": ids,
                    }
                )
        return found


def _view(stored: StoredEvent) -> dict[str, Any]:
    event = stored.event
    view: dict[str, Any] = {"event_id": stored.seq}
    for name in _EVENT_FIELDS:
        value = getattr(event, name)
        if value in (None, False, (), ""):
            continue
        view[name] = list(value) if isinstance(value, tuple) else value
    if event.sanitized_args:
        view["args"] = sanitize_args(event.sanitized_args)
    return view
