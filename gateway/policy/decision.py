"""Policy decision types, reason codes and the Stage 2 pass-through policy.

The gateway asks a policy engine for a decision on every call that passed identity, registry,
grant and schema checks. Stage 2 plugged in `AllowAllPolicy` (allow everything) to prove that
MCP behaviour is preserved. Stage 3 replaces it with the YAML rule engine
(`gateway/policy/engine.py`) behind the same `PolicyEngine` interface. `AllowAllPolicy` stays
only as a test double and must never be used in a running gateway.
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
ARG_LIMIT_EXCEEDED = "ARG_LIMIT_EXCEEDED"  # P-005
SENSITIVE_TABLE_EXPORT = "SENSITIVE_TABLE_EXPORT"  # P-006
PROD_DESTRUCTIVE_DENIED = "PROD_DESTRUCTIVE_DENIED"  # P-007
PROTECTED_BRANCH = "PROTECTED_BRANCH"  # P-008
RESTRICTED_SERVICE = "RESTRICTED_SERVICE"  # P-009
SECRETS_ACCESS_DENIED = "SECRETS_ACCESS_DENIED"  # P-010
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"  # P-011
RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"  # P-012
POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"  # P-013
DESTRUCTIVE_TOOL_DENIED = "DESTRUCTIVE_TOOL_DENIED"  # P-014
POLICY_ALLOWED = "ALLOWED_BY_POLICY"  # the reason code of every ALLOW from the rule engine
ALLOW_ALL = "ALLOW_ALL"  # Stage 2 test double only: no rules are applied
DOWNSTREAM_TIMEOUT = "DOWNSTREAM_TIMEOUT"  # execution failed after an ALLOW
DOWNSTREAM_ERROR = "DOWNSTREAM_ERROR"  # execution failed after an ALLOW

# Reason codes a policy file may use. A typo in a policy file is a start-up error, not a rule.
POLICY_FILE_REASON_CODES = frozenset(
    {
        UNKNOWN_TOOL,
        TOOL_NOT_GRANTED,
        ARG_LIMIT_EXCEEDED,
        SENSITIVE_TABLE_EXPORT,
        PROD_DESTRUCTIVE_DENIED,
        PROTECTED_BRANCH,
        RESTRICTED_SERVICE,
        SECRETS_ACCESS_DENIED,
        APPROVAL_REQUIRED,
        DESTRUCTIVE_TOOL_DENIED,
        POLICY_ALLOWED,
    }
)

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
