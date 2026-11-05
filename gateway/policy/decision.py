"""Policy decision types and the Stage 2 pass-through policy.

The gateway asks a policy engine for a decision on every call that passed identity, registry,
grant and schema checks. Stage 2 plugs in `AllowAllPolicy` (allow everything) to prove that
MCP behaviour is preserved. Stage 3 replaces it with the YAML rule engine behind the same
`PolicyEngine` interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol

from gateway.identity.registry import Identity

Decision = Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]

# Reason codes from docs/permission-matrix.md section 5 (P-001 .. P-013), plus the codes the
# gateway itself uses.
UNKNOWN_TOOL = "UNKNOWN_TOOL"  # P-001
UNREGISTERED_AGENT = "UNREGISTERED_AGENT"  # P-002
TOOL_NOT_GRANTED = "TOOL_NOT_GRANTED"  # P-003
INVALID_ARGUMENTS = "INVALID_ARGUMENTS"  # P-004
POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"  # P-013
ALLOW_ALL = "ALLOW_ALL"  # Stage 2 only: no rules are applied
DOWNSTREAM_TIMEOUT = "DOWNSTREAM_TIMEOUT"  # execution failed after an ALLOW
DOWNSTREAM_ERROR = "DOWNSTREAM_ERROR"  # execution failed after an ALLOW

ALLOW_ALL_VERSION = "pass-through-0"


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason_code: str
    policy_version: str


class PolicyEngine(Protocol):
    def evaluate(self, identity: Identity, tool: str, args: dict[str, Any]) -> PolicyDecision: ...


class AllowAllPolicy:
    """Allows every call that reached it. Not a security control: Stage 3 replaces it."""

    def evaluate(self, identity: Identity, tool: str, args: dict[str, Any]) -> PolicyDecision:
        return PolicyDecision("ALLOW", ALLOW_ALL, ALLOW_ALL_VERSION)
