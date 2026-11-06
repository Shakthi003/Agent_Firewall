"""The Stage 3 policy engine: YAML rules behind the `PolicyEngine` interface.

For every call the gateway has already established who the agent is, that the tool is approved
and granted to its role, and that the arguments match the tool's schema. The engine then decides:

    1. rate limit (P-012)       one token per call from the agent's bucket
    2. the tool's rules         first matching rule wins, otherwise the tool's default

The result is always a `PolicyDecision` with a reason code and the policy version. The engine
is deterministic and has no model in it. If anything inside `evaluate` raises, the gateway
catches it and denies the call with `POLICY_UNAVAILABLE`; there is no bypass for read-only tools.

The engine refuses to be built if the policy and the tool registry disagree: every approved tool
needs a policy entry, no entry may name an unknown tool, and a rule may only test arguments the
tool really declares (or `role`). A typo therefore stops the gateway at start-up instead of
silently never matching.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from gateway.identity.registry import Identity
from gateway.policy.decision import (
    POLICY_ALLOWED,
    RATE_LIMIT_EXCEEDED,
    UNKNOWN_TOOL,
    PolicyDecision,
)
from gateway.policy.policy_file import (
    LoadedPolicy,
    Outcome,
    PolicyFileError,
    Rule,
    load_policy,
)
from gateway.policy.rate_limit import TokenBucketRateLimiter

ROLE_FIELD = "role"


class RuleEngine:
    def __init__(
        self,
        policy: LoadedPolicy,
        *,
        tool_arguments: Mapping[str, Collection[str]],
        limiter: TokenBucketRateLimiter,
    ) -> None:
        """`tool_arguments` maps every approved tool to the argument names it declares."""
        _check_consistency(policy, tool_arguments)
        self._tools = policy.file.tools
        self._version = policy.version
        self._limiter = limiter

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        tool_arguments: Mapping[str, Collection[str]],
        limiter: TokenBucketRateLimiter,
    ) -> RuleEngine:
        return cls(load_policy(path), tool_arguments=tool_arguments, limiter=limiter)

    @property
    def version(self) -> str:
        return self._version

    def evaluate(self, identity: Identity, tool: str, args: dict[str, Any]) -> PolicyDecision:
        if not self._limiter.allow(identity.agent_id):
            return PolicyDecision("BLOCK", RATE_LIMIT_EXCEEDED, self._version)
        policy = self._tools.get(tool)
        if policy is None:  # the gateway checks the registry first; this is defence in depth
            return PolicyDecision("BLOCK", UNKNOWN_TOOL, self._version)
        facts = {**args, ROLE_FIELD: identity.role}  # the verified role wins over any argument
        outcome: Outcome = next((r for r in policy.rules if _matches(r, facts)), policy.default)
        return PolicyDecision(outcome.decision, outcome.reason or POLICY_ALLOWED, self._version)


# ---------------------------------------------------------------------- matching


def _matches(rule: Rule, facts: Mapping[str, Any]) -> bool:
    for field, tests in rule.when.items():
        present = field in facts
        value = facts.get(field)
        for operator, operand in tests.items():
            if operator == "exists":
                if present != operand:
                    return False
            elif not present or not _test(operator, value, operand):
                return False
    return True


def _test(operator: str, value: Any, operand: Any) -> bool:
    if operator == "eq":
        return _equal(value, operand)
    if operator == "ne":
        return _comparable(value, operand) and not _equal(value, operand)
    if operator in ("gt", "gte", "lt", "lte"):
        if not _is_number(value):
            return False
        return {
            "gt": value > operand,
            "gte": value >= operand,
            "lt": value < operand,
            "lte": value <= operand,
        }[operator]
    if operator == "in":
        return any(_equal(value, item) for item in operand)
    if operator == "not_in":
        return all(_comparable(value, item) for item in operand) and not any(
            _equal(value, item) for item in operand
        )
    if operator == "glob":
        return isinstance(value, str) and any(fnmatch.fnmatchcase(value, p) for p in operand)
    return False  # an operator the loader would have rejected


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _comparable(a: Any, b: Any) -> bool:
    """Same kind of value: bool with bool, number with number, text with text."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool)
    if _is_number(a) and _is_number(b):
        return True
    return isinstance(a, str) and isinstance(b, str)


def _equal(a: Any, b: Any) -> bool:
    return _comparable(a, b) and a == b


# ---------------------------------------------------------------------- start-up checks


def _check_consistency(policy: LoadedPolicy, tool_arguments: Mapping[str, Collection[str]]) -> None:
    in_policy = set(policy.file.tools)
    approved = set(tool_arguments)
    problems: list[str] = []
    if approved - in_policy:
        problems.append(f"approved tools with no policy entry: {sorted(approved - in_policy)}")
    if in_policy - approved:
        problems.append(f"policy entries for unapproved tools: {sorted(in_policy - approved)}")
    for name in sorted(in_policy & approved):
        allowed = set(tool_arguments[name]) | {ROLE_FIELD}
        for rule in policy.file.tools[name].rules:
            unknown = set(rule.when) - allowed
            if unknown:
                problems.append(f"{name}: a rule tests undeclared fields {sorted(unknown)}")
    if problems:
        raise PolicyFileError("; ".join(problems))
