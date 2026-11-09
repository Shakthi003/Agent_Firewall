"""Optional anomaly model (Stage 5): an Isolation Forest over short time windows.

Why it exists: the rules catch the attacks they were written for. The model asks a different
question, "does this stretch of an agent's activity look unlike its normal activity?", which can
catch a pattern no rule names (the simulator's `slow_scrape`).

How it is used, and what it is NOT:

- It is trained on windows of *normal* traffic only (novelty detection), so it needs no attack
  labels to learn, and the labels are used only to measure it.
- It produces a score between 0 and 1. A score is evidence for a human, not a decision. The
  model is not imported by the gateway or the policy engine and cannot allow, block or pause a
  call (AC-38); the deterministic policy has already decided before any score exists.
- A fixed `random_state` makes training and scoring repeatable.

Features, per agent per window (default 5 minutes):
    calls, distinct tools, share of calls that were not ALLOW, largest `limit` argument,
    shortest gap between calls, share of calls outside business hours, share of calls that
    were a sensitive-tool attempt.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from gateway.mcp_gateway.audit import AuditEvent

FEATURE_NAMES = (
    "calls",
    "distinct_tools",
    "non_allow_share",
    "max_limit",
    "min_gap_s",
    "off_hours_share",
    "sensitive_share",
)
SENSITIVE_TOOLS = frozenset(
    {
        "initiate_payment",
        "update_beneficiary_bank_details",
        "export_records",
        "restart_service",
        "delete_resource",
        "disable_monitoring",
        "repo_push_commit",
        "repo_delete_branch",
        "read_env_secrets",
        "read_payroll",
        "get_employee_record",
    }
)
WINDOW_SECONDS = 300
_NO_GAP = 300.0  # min_gap_s for a window with a single call


@dataclass(frozen=True)
class Window:
    agent_id: str
    start: float
    events: tuple[AuditEvent, ...]

    @property
    def correlation_ids(self) -> frozenset[str]:
        return frozenset(e.correlation_id for e in self.events)


def windows_of(events: Sequence[AuditEvent], seconds: int = WINDOW_SECONDS) -> list[Window]:
    """Group `tools/call` events by (agent, fixed time bucket). Order is by start, then agent."""
    buckets: dict[tuple[str, int], list[AuditEvent]] = defaultdict(list)
    for e in events:
        if e.method != "tools/call":
            continue
        buckets[(e.agent_id or "(unauthenticated)", int(e.timestamp // seconds))].append(e)
    return [
        Window(agent, bucket * seconds, tuple(sorted(evs, key=lambda e: e.timestamp)))
        for (agent, bucket), evs in sorted(buckets.items(), key=lambda kv: (kv[0][1], kv[0][0]))
    ]


def features(window: Window) -> list[float]:
    evs = window.events
    n = len(evs)
    ts = [e.timestamp for e in evs]
    gaps = [b - a for a, b in zip(ts, ts[1:], strict=False)]
    limits = [
        v
        for e in evs
        if isinstance(v := e.sanitized_args.get("limit"), int) and not isinstance(v, bool)
    ]
    off = sum(1 for e in evs if not 6 <= datetime.fromtimestamp(e.timestamp, UTC).hour < 22)
    return [
        float(n),
        float(len({e.tool for e in evs})),
        sum(1 for e in evs if e.decision != "ALLOW") / n,
        float(max(limits, default=0)),
        float(min(gaps, default=_NO_GAP)),
        off / n,
        sum(1 for e in evs if e.tool in SENSITIVE_TOOLS) / n,
    ]


class AnomalyModel:
    def __init__(
        self,
        *,
        random_state: int = 7,
        n_estimators: int = 200,
        false_alarm_rate: float = 0.01,
    ) -> None:
        self._forest = IsolationForest(
            n_estimators=n_estimators, random_state=random_state, contamination="auto"
        )
        self._false_alarm_rate = false_alarm_rate
        self._threshold = 0.0
        self._fitted = False

    def fit(self, normal_windows: Sequence[Window]) -> AnomalyModel:
        if len(normal_windows) < 20:
            raise ValueError("need at least 20 normal windows to fit the model")
        x = np.array([features(w) for w in normal_windows])
        self._forest.fit(x)
        # Only `false_alarm_rate` of the *training* windows score above this threshold.
        self._threshold = float(np.quantile(self._raw(x), 1 - self._false_alarm_rate))
        self._fitted = True
        return self

    def _raw(self, x: np.ndarray) -> np.ndarray:
        return -self._forest.score_samples(x)  # higher = more anomalous

    def scores(self, windows: Sequence[Window]) -> list[float]:
        """Anomaly score per window, 0.0 to 1.0. 0.5 is the alarm threshold: below it the window
        looks like training data, above it the window is unlike anything seen in training."""
        if not self._fitted:
            raise RuntimeError("fit the model first")
        if not windows:
            return []
        raw = self._raw(np.array([features(w) for w in windows]))
        scaled = 0.5 + (raw - self._threshold) / max(2 * (1 - self._threshold), 1e-9)
        return [float(min(max(s, 0.0), 1.0)) for s in scaled]

    def flags(self, windows: Sequence[Window]) -> list[bool]:
        return [s >= 0.5 for s in self.scores(windows)]
