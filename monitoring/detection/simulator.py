"""Seeded agent-traffic simulator (Stage 5): labelled normal and attack events for detection tests.

Same seed, same traffic, byte for byte (AC-37). Timestamps come from a fixed start date, never
from the wall clock, and correlation IDs are counters.

Traffic is grouped into *episodes*, the unit detections are scored on:

    normal            an everyday workflow session (the tools and pacing of the Stage 1
                      workflows, 9:00-17:00 UTC, with an occasional harmless blocked call)
    burst             a flood of calls in a few seconds
    large_export      a bulk export / listing far above the normal limit
    repeated_denials  several blocked destructive calls in a row
    unusual_sequence  a read followed by a sensitive action no normal workflow chains
    off_hours         ordinary calls in the middle of the night
    slow_scrape       a steady trickle of reads, too slow for any rule: the case the rules were
                      NOT written for, used to see what the anomaly model adds

Decisions and reason codes follow `policies/policy.yaml`.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from gateway.mcp_gateway.audit import AuditEvent
from monitoring.audit.redact import sanitize_args

START = datetime(2026, 3, 2, tzinfo=UTC)  # a Monday
POLICY_VERSION = "sim-1.0"

AGENTS = {
    "finance-agent": "finance",
    "it-ops-agent": "it_ops",
    "developer-agent": "developer",
}
_SERVER_OF = {
    "get_invoice": "company_data",
    "get_payment_status": "company_data",
    "initiate_payment": "company_data",
    "get_customer_record": "company_data",
    "list_invoices": "company_data",
    "export_records": "company_data",
    "update_beneficiary_bank_details": "company_data",
    "get_service_status": "operations",
    "update_ticket": "operations",
    "send_notification": "operations",
    "restart_service": "operations",
    "delete_resource": "operations",
    "disable_monitoring": "operations",
    "repo_get_metadata": "developer_tools",
    "repo_get_build_status": "developer_tools",
    "repo_create_branch": "developer_tools",
    "repo_open_pull_request": "developer_tools",
    "repo_push_commit": "developer_tools",
    "read_env_secrets": "developer_tools",
}

ATTACK_KINDS = (
    "burst",
    "large_export",
    "repeated_denials",
    "unusual_sequence",
    "off_hours",
    "slow_scrape",
)
RULE_COVERED = ("burst", "large_export", "repeated_denials", "unusual_sequence", "off_hours")

_ALLOW = ("ALLOW", "ALLOWED_BY_POLICY")
Step = tuple[str, dict[str, Any], str, str]  # tool, args, decision, reason


@dataclass(frozen=True)
class Episode:
    kind: str  # "normal" or one of ATTACK_KINDS
    agent_id: str
    events: tuple[AuditEvent, ...]

    @property
    def is_attack(self) -> bool:
        return self.kind != "normal"


class _Builder:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self._n = 0

    def event(
        self,
        agent_id: str,
        ts: float,
        tool: str,
        args: dict[str, Any],
        decision: str = "ALLOW",
        reason: str = "ALLOWED_BY_POLICY",
    ) -> AuditEvent:
        self._n += 1
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
        return AuditEvent(
            timestamp=round(ts, 3),
            correlation_id=f"sim-{self._n:07d}",
            method="tools/call",
            decision=decision,
            reason_code=reason,
            agent_id=agent_id,
            role=AGENTS[agent_id],
            key_version=1,
            tool=tool,
            server=_SERVER_OF[tool],
            policy_version=POLICY_VERSION,
            args_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            arg_names=tuple(sorted(args)),
            sanitized_args=sanitize_args(args),
            execution_status="ok" if decision == "ALLOW" else "not_executed",
            latency_ms=round(self.rng.uniform(4, 60), 3),
        )

    def run(
        self, agent_id: str, t: float, steps: list[Step], gap: tuple[float, float]
    ) -> list[AuditEvent]:
        events = []
        for tool, args, decision, reason in steps:
            t += self.rng.uniform(*gap)
            events.append(self.event(agent_id, t, tool, args, decision, reason))
        return events


def _invoice(rng: random.Random) -> str:
    return f"INV-{rng.randint(1, 300):04d}"


def _customer(rng: random.Random) -> str:
    return f"CUS-{rng.randint(1, 50):03d}"


class TrafficSimulator:
    def __init__(self, seed: int = 42) -> None:
        self._seed = seed

    def generate(
        self,
        *,
        days: int = 5,
        sessions_per_agent_per_day: int = 8,
        attacks_per_kind: int = 6,
        attack_kinds: Iterable[str] = ATTACK_KINDS,
    ) -> list[Episode]:
        """Episodes in time order. Deterministic for a given seed and arguments."""
        rng = random.Random(self._seed)  # noqa: S311  # a simulator, not security
        build = _Builder(rng)
        episodes: list[Episode] = []

        for day in range(days):
            day_start = (START + timedelta(days=day)).timestamp()
            for agent_id in AGENTS:
                t = day_start + 9 * 3600 + rng.uniform(0, 600)
                for _ in range(sessions_per_agent_per_day):
                    steps = self._normal_steps(rng, AGENTS[agent_id])
                    events = build.run(agent_id, t, steps, (3, 25))
                    episodes.append(Episode("normal", agent_id, tuple(events)))
                    t = events[-1].timestamp + rng.uniform(300, 1500)  # 5 to 25 minutes apart

        for kind in attack_kinds:
            for _ in range(attacks_per_kind):
                episodes.append(self._attack(build, kind, rng.randrange(max(days, 1))))

        episodes.sort(key=lambda e: (e.events[0].timestamp, e.events[0].correlation_id))
        return episodes

    # ---- normal traffic

    @staticmethod
    def _normal_steps(rng: random.Random, role: str) -> list[Step]:
        steps: list[Step] = []
        if role == "finance":
            kind = rng.choice(("pay", "review", "export"))
            if kind == "pay":
                inv = _invoice(rng)
                steps = [
                    ("get_invoice", {"invoice_id": inv}, *_ALLOW),
                    ("get_payment_status", {"invoice_id": inv}, *_ALLOW),
                    (
                        "initiate_payment",
                        {"invoice_id": inv, "amount": rng.randint(100, 4900)},
                        *_ALLOW,
                    ),
                ]
            elif kind == "review":
                steps = [
                    ("list_invoices", {"limit": rng.choice((10, 20, 50))}, *_ALLOW),
                    ("get_customer_record", {"customer_id": _customer(rng)}, *_ALLOW),
                ]
            else:
                limit = rng.randint(20, 100)
                steps = [("export_records", {"table": "invoices", "limit": limit}, *_ALLOW)]
            if rng.random() < 0.04:  # a harmless mistake: asks for too many rows once
                steps.append(("list_invoices", {"limit": 100}, "BLOCK", "ARG_LIMIT_EXCEEDED"))
        elif role == "it_ops":
            svc = rng.choice(("billing-api", "search", "notifier"))
            ticket = f"TCK-{rng.randint(1, 40):03d}"
            steps = [
                ("get_service_status", {"service": svc, "env": "staging"}, *_ALLOW),
                ("update_ticket", {"ticket_id": ticket, "comment": "checked"}, *_ALLOW),
            ]
            if rng.random() < 0.4:
                steps.append(
                    ("send_notification", {"channel": "ops", "message": "checked"}, *_ALLOW)
                )
            if rng.random() < 0.15:
                steps.append(("restart_service", {"service": svc, "env": "dev"}, *_ALLOW))
        else:
            repo = rng.choice(("web-portal", "billing-service", "docs"))
            steps = [
                ("repo_get_metadata", {"repo": repo}, *_ALLOW),
                ("repo_get_build_status", {"repo": repo, "branch": "main"}, *_ALLOW),
            ]
            if rng.random() < 0.4:
                steps.append(("get_service_status", {"service": "search", "env": "dev"}, *_ALLOW))
            if rng.random() < 0.3:
                branch = f"feature/{rng.randint(1, 99)}"
                steps.append(("repo_create_branch", {"repo": repo, "branch": branch}, *_ALLOW))
            if rng.random() < 0.04:
                steps.append(
                    (
                        "repo_push_commit",
                        {"repo": repo, "branch": "main"},
                        "BLOCK",
                        "PROTECTED_BRANCH",
                    )
                )
        return steps

    # ---- attacks

    def _attack(self, build: _Builder, kind: str, day: int) -> Episode:
        rng = build.rng
        hours = rng.uniform(1, 4) if kind == "off_hours" else rng.uniform(9.5, 16.5)
        t = (START + timedelta(days=day)).timestamp() + hours * 3600
        agent_id = rng.choice(tuple(AGENTS))
        steps: list[Step] = []
        gap = (3.0, 10.0)

        if kind == "burst":
            agent_id = "finance-agent"
            n = rng.randint(25, 40)
            for i in range(n):
                if i < n * 2 // 3:
                    steps.append(("get_invoice", {"invoice_id": _invoice(rng)}, *_ALLOW))
                else:
                    steps.append(
                        (
                            "get_invoice",
                            {"invoice_id": _invoice(rng)},
                            "BLOCK",
                            "RATE_LIMIT_EXCEEDED",
                        )
                    )
            gap = (0.1, 0.35)
        elif kind == "large_export":
            agent_id = "finance-agent"
            for _ in range(rng.randint(1, 2)):
                if rng.random() < 0.6:
                    limit = rng.choice((1000, 2000, 5000))
                    steps.append(
                        (
                            "export_records",
                            {"table": "invoices", "limit": limit},
                            "REQUIRE_APPROVAL",
                            "APPROVAL_REQUIRED",
                        )
                    )
                else:
                    limit = rng.choice((500, 1000, 2000))
                    steps.append(("list_invoices", {"limit": limit}, "BLOCK", "ARG_LIMIT_EXCEEDED"))
            gap = (2.0, 15.0)
        elif kind == "repeated_denials":
            agent_id = "it-ops-agent"
            prod = "PROD_DESTRUCTIVE_DENIED"
            attempts: list[Step] = [
                ("delete_resource", {"resource_id": "RES-001", "env": "prod"}, "BLOCK", prod),
                ("disable_monitoring", {"service": "auth", "env": "prod"}, "BLOCK", prod),
                (
                    "restart_service",
                    {"service": "auth", "env": "prod"},
                    "BLOCK",
                    "RESTRICTED_SERVICE",
                ),
                ("delete_resource", {"resource_id": "RES-002", "env": "prod"}, "BLOCK", prod),
                ("disable_monitoring", {"service": "monitoring", "env": "prod"}, "BLOCK", prod),
            ]
            steps = attempts[: rng.randint(4, 5)]
            gap = (2.0, 8.0)
        elif kind == "unusual_sequence":
            if rng.random() < 0.5:
                agent_id = "finance-agent"
                steps = [
                    ("get_invoice", {"invoice_id": "INV-0001"}, *_ALLOW),
                    (
                        "update_beneficiary_bank_details",
                        {"beneficiary_id": "BEN-001", "account_number": "99887766"},
                        "REQUIRE_APPROVAL",
                        "APPROVAL_REQUIRED",
                    ),
                ]
            else:
                agent_id = "it-ops-agent"
                steps = [
                    ("update_ticket", {"ticket_id": "TCK-002", "comment": "looking"}, *_ALLOW),
                    (
                        "delete_resource",
                        {"resource_id": "RES-001", "env": "prod"},
                        "BLOCK",
                        "PROD_DESTRUCTIVE_DENIED",
                    ),
                ]
            gap = (5.0, 40.0)
        elif kind == "off_hours":
            for _ in range(rng.randint(3, 6)):
                if AGENTS[agent_id] == "finance":
                    steps.append(("get_invoice", {"invoice_id": _invoice(rng)}, *_ALLOW))
                elif AGENTS[agent_id] == "it_ops":
                    steps.append(
                        ("get_service_status", {"service": "search", "env": "staging"}, *_ALLOW)
                    )
                else:
                    steps.append(("repo_get_metadata", {"repo": "web-portal"}, *_ALLOW))
            gap = (5.0, 30.0)
        elif kind == "slow_scrape":
            agent_id = "finance-agent"
            for _ in range(rng.randint(40, 60)):
                steps.append(("get_customer_record", {"customer_id": _customer(rng)}, *_ALLOW))
            gap = (3.5, 6.5)  # about 10-16 a minute: under every rule threshold
        else:
            raise ValueError(f"unknown attack kind: {kind}")
        return Episode(kind, agent_id, tuple(build.run(agent_id, t, steps, gap)))


def all_events(episodes: Iterable[Episode]) -> list[AuditEvent]:
    """Every event of every episode in time order, as the gateway would have seen them."""
    events = [e for ep in episodes for e in ep.events]
    events.sort(key=lambda e: (e.timestamp, e.correlation_id))
    return events
