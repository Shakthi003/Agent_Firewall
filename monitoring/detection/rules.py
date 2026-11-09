"""Rule-based behaviour monitor (Stage 5): spots allowed-but-abusive behaviour.

The policy engine decides whether ONE call is allowed. This monitor looks at the pattern of an
agent's calls over time. Five deterministic rules:

    BURST             many calls from one agent in a few seconds
    LARGE_EXPORT      a result limit above what the tool normally needs (even if it was stopped)
    REPEATED_DENIALS  several BLOCKed calls from one agent in a short time
    UNUSUAL_SEQUENCE  a read followed by a sensitive action that normal workflows never chain
    OFF_HOURS         activity outside business hours (UTC), only meaningful on real or
                      simulated clocks

It reads events and returns a score (0.0 to 1.0) and alerts. It never sees the gateway, the policy
or the downstream servers, so it cannot allow, block or pause anything: the deterministic policy
decision is made first and is final (AC-38). What a high score DOES is fixed in
`RESPONSE_BY_LEVEL`: alert a human. Nothing more.

Deterministic by construction: no randomness, no wall clock. Everything is computed from the
event timestamps, so the same events in the same order give the same alerts (AC-37).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from gateway.mcp_gateway.audit import AuditEvent

RuleName = Literal["BURST", "LARGE_EXPORT", "REPEATED_DENIALS", "UNUSUAL_SEQUENCE", "OFF_HOURS"]
RiskLevel = Literal["normal", "elevated", "high"]
UNAUTHENTICATED = "(unauthenticated)"

# What a risk level does. Deliberately limited to "none" and "alert": pausing or blocking is
# decided only by the deterministic policy (policies/policy.yaml), never by a score.
RESPONSE_BY_LEVEL: dict[RiskLevel, str] = {"normal": "none", "elevated": "alert", "high": "alert"}
ELEVATED_FROM = 0.4
HIGH_FROM = 0.7


def risk_level(score: float) -> RiskLevel:
    if score >= HIGH_FROM:
        return "high"
    if score >= ELEVATED_FROM:
        return "elevated"
    return "normal"


@dataclass(frozen=True)
class RuleConfig:
    burst_calls: int = 15
    burst_window_s: float = 10.0
    # tool -> the largest `limit` that is not suspicious; anything above fires LARGE_EXPORT.
    # These sit well above the policy limits (export 100, list 50) on purpose: the policy already
    # stops a call just over its limit, and an honest near-miss (limit 100 on a list) should not
    # raise an alert. The alert is for asking for several times more than the policy allows.
    limit_ceilings: tuple[tuple[str, int], ...] = (("export_records", 500), ("list_invoices", 200))
    denial_count: int = 3
    denial_window_s: float = 60.0
    # (earlier tool, later tool): the later call within the window after the earlier one
    suspicious_sequences: tuple[tuple[str, str], ...] = (
        ("get_invoice", "update_beneficiary_bank_details"),
        ("get_invoice", "export_records"),
        ("update_ticket", "delete_resource"),
        ("get_service_status", "disable_monitoring"),
        ("repo_get_metadata", "read_env_secrets"),
    )
    sequence_window_s: float = 120.0
    business_hours_utc: tuple[int, int] = (6, 22)  # [start, end)
    cooldown_s: float = 60.0  # one alert per (rule, agent) per cooldown; the score is not damped
    scores: tuple[tuple[str, float], ...] = (
        ("BURST", 0.6),
        ("LARGE_EXPORT", 0.7),
        ("REPEATED_DENIALS", 0.8),
        ("UNUSUAL_SEQUENCE", 0.8),
        ("OFF_HOURS", 0.4),
    )

    def score_for(self, rule: str) -> float:
        return dict(self.scores)[rule]

    @property
    def retention_s(self) -> float:
        return max(self.burst_window_s, self.denial_window_s, self.sequence_window_s)


@dataclass(frozen=True)
class Alert:
    rule: RuleName
    agent_id: str
    timestamp: float
    score: float
    severity: RiskLevel
    detail: str
    evidence: tuple[str, ...]  # correlation IDs of the events behind the alert


@dataclass(frozen=True)
class MonitorResult:
    score: float  # 0.0 when no rule hit
    alerts: tuple[Alert, ...]  # new alerts (cooldown applied)
    hits: tuple[str, ...]  # every rule that hit on this event, cooldown or not


@dataclass
class _AgentState:
    # (timestamp, tool, decision, correlation_id) of recent calls, oldest first
    recent: deque[tuple[float, str, str, str]] = field(default_factory=deque)
    last_alert: dict[str, float] = field(default_factory=dict)


class BehaviourMonitor:
    """Feed it events in order with `observe`. Keeps a short in-memory window per agent."""

    def __init__(self, config: RuleConfig | None = None) -> None:
        self._config = config or RuleConfig()
        self._ceilings = dict(self._config.limit_ceilings)
        self._state: dict[str, _AgentState] = {}

    def observe(self, event: AuditEvent) -> MonitorResult:
        """Score one event. Only `tools/call` events count; everything else scores 0."""
        if event.method != "tools/call":
            return MonitorResult(0.0, (), ())
        cfg = self._config
        key = event.agent_id or UNAUTHENTICATED
        state = self._state.setdefault(key, _AgentState())
        ts = event.timestamp
        tool = event.tool or "(unknown)"
        state.recent.append((ts, tool, event.decision, event.correlation_id))
        while state.recent and ts - state.recent[0][0] > cfg.retention_s:
            state.recent.popleft()

        details: dict[str, tuple[str, tuple[str, ...]]] = {}

        in_burst = [r for r in state.recent if ts - r[0] <= cfg.burst_window_s]
        if len(in_burst) >= cfg.burst_calls:
            details["BURST"] = (
                f"{len(in_burst)} calls in {cfg.burst_window_s:g}s",
                tuple(r[3] for r in in_burst[-cfg.burst_calls :]),
            )

        ceiling = self._ceilings.get(tool)
        limit = event.sanitized_args.get("limit")
        if ceiling is not None and isinstance(limit, int) and limit > ceiling:
            details["LARGE_EXPORT"] = (
                f"{tool} with limit {limit} (normal ceiling {ceiling})",
                (event.correlation_id,),
            )

        if event.decision == "BLOCK":
            denied = [
                r for r in state.recent if r[2] == "BLOCK" and ts - r[0] <= cfg.denial_window_s
            ]
            if len(denied) >= cfg.denial_count:
                details["REPEATED_DENIALS"] = (
                    f"{len(denied)} blocked calls in {cfg.denial_window_s:g}s",
                    tuple(r[3] for r in denied),
                )

        earlier = [
            r
            for r in state.recent
            if r[3] != event.correlation_id and ts - r[0] <= cfg.sequence_window_s
        ]
        for first, second in cfg.suspicious_sequences:
            if tool == second:
                match = [r for r in earlier if r[1] == first]
                if match:
                    details["UNUSUAL_SEQUENCE"] = (
                        f"{first} followed by {second} within {cfg.sequence_window_s:g}s",
                        (match[-1][3], event.correlation_id),
                    )
                    break

        start, end = cfg.business_hours_utc
        hour = datetime.fromtimestamp(ts, UTC).hour
        if not start <= hour < end:
            details["OFF_HOURS"] = (
                f"call at {hour:02d}:00 UTC, outside {start:02d}:00-{end:02d}:00",
                (event.correlation_id,),
            )

        hits = tuple(sorted(details))
        alerts: list[Alert] = []
        for rule in hits:
            score = cfg.score_for(rule)
            last = state.last_alert.get(rule)
            if last is not None and ts - last < cfg.cooldown_s:
                continue
            state.last_alert[rule] = ts
            text, evidence = details[rule]
            alerts.append(
                Alert(
                    rule=rule,  # type: ignore[arg-type]
                    agent_id=key,
                    timestamp=ts,
                    score=score,
                    severity=risk_level(score),
                    detail=text,
                    evidence=evidence,
                )
            )
        top = max((cfg.score_for(r) for r in hits), default=0.0)
        return MonitorResult(top, tuple(alerts), hits)

    def run(self, events: list[AuditEvent]) -> list[Alert]:
        """All alerts for a list of events, in order. A fresh monitor on the same events always
        gives the same alerts."""
        found: list[Alert] = []
        for event in events:
            found.extend(self.observe(event).alerts)
        return found
