"""Per-agent rate limit (Stage 3, P-012).

A token bucket per agent ID. The bucket holds at most `burst` tokens, refills at
`calls_per_minute / 60` tokens per second, and every call takes one token. Starting full, an
agent can therefore make `burst` calls at once and then `calls_per_minute` per minute
sustained. Both numbers come from settings (`RATE_LIMIT_CALLS_PER_MINUTE`, `RATE_LIMIT_BURST`).

The key is the verified agent ID, never a name the agent supplied. State is in memory: a gateway
restart gives every agent a full bucket again.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucketRateLimiter:
    def __init__(
        self,
        calls_per_minute: float,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if calls_per_minute <= 0:
            raise ValueError("calls_per_minute must be greater than zero")
        if burst < 1:
            raise ValueError("burst must be at least 1")
        self._rate = calls_per_minute / 60.0
        self._burst = float(burst)
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, agent_id: str) -> bool:
        """Take one token for this agent. False means the limit is exceeded; nothing is taken."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(agent_id)
            if bucket is None:
                bucket = self._buckets[agent_id] = _Bucket(self._burst, now)
            else:
                elapsed = max(0.0, now - bucket.updated)
                bucket.tokens = min(self._burst, bucket.tokens + elapsed * self._rate)
                bucket.updated = now
            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            return True
