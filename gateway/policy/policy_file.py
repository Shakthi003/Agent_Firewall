"""Policy file format and loader (Stage 3).

A policy file is YAML. For every approved tool it lists ordered rules and a default outcome:

    tools:
      export_records:
        rules:
          - when: {table: {eq: invoices}, limit: {lte: 100}}
            decision: ALLOW
        default: {decision: BLOCK, reason: SENSITIVE_TABLE_EXPORT}

Evaluation (see `gateway/policy/engine.py`): rules are tried top to bottom, the first rule whose
`when` matches wins, and if none matches the `default` applies. Every field in `when` must match
(AND); to express OR, write two rules. Operators: eq, ne, gt, gte, lt, lte, in, not_in, glob,
exists. `when` can test any tool argument and `role` (the caller's verified role).

A field that is absent from the call matches no operator except `exists: false`, and a value of
the wrong type matches nothing. So a rule can never match by accident, and a call that does not
fit an "allow only these cases" rule falls to the default.

Loading is strict. Unknown keys, an unknown operator or reason code, a wrongly typed operand or a
rule with an empty `when` make the file invalid, and an invalid file stops the gateway from
starting (fail closed).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gateway.policy.decision import POLICY_ALLOWED, POLICY_FILE_REASON_CODES, Decision

DEFAULT_POLICY_FILENAME = "policy.yaml"

Operator = Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "glob", "exists"]
_ORDERING = ("gt", "gte", "lt", "lte")
_LISTS = ("in", "not_in", "glob")
_VERSION_TEXT = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$"


class PolicyFileError(Exception):
    """The policy file is missing, malformed or inconsistent with the tool registry."""


class Outcome(BaseModel):
    """A decision with its reason code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    reason: str | None = None

    @model_validator(mode="after")
    def _reason_matches_decision(self) -> Self:
        if self.decision == "ALLOW":
            if self.reason is not None:
                raise ValueError("an ALLOW outcome must not carry a reason code")
            return self
        if self.reason is None:
            raise ValueError(f"a {self.decision} outcome needs a reason code")
        if self.reason == POLICY_ALLOWED or self.reason not in POLICY_FILE_REASON_CODES:
            raise ValueError(f"unknown or unsuitable reason code {self.reason!r}")
        return self


class Rule(Outcome):
    when: dict[str, dict[Operator, Any]] = Field(min_length=1)
    note: str = ""  # free text for people reading the file; never shown to agents

    @field_validator("when")
    @classmethod
    def _operands_have_the_right_type(
        cls, when: dict[str, dict[Operator, Any]]
    ) -> dict[str, dict[Operator, Any]]:
        for field, tests in when.items():
            if not tests:
                raise ValueError(f"field {field!r} has no operator")
            for operator, operand in tests.items():
                _check_operand(field, operator, operand)
        return when


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[Rule, ...] = ()
    default: Outcome


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    policy_version: Annotated[str, Field(pattern=_VERSION_TEXT)]
    tools: dict[str, ToolPolicy] = Field(min_length=1)


class LoadedPolicy(BaseModel):
    """A validated policy plus the version string recorded on every decision."""

    model_config = ConfigDict(frozen=True)

    file: PolicyFile
    version: str  # "<policy_version>+<first 8 hex of the file's SHA-256>"


def load_policy(path: Path) -> LoadedPolicy:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise PolicyFileError(f"Policy file not found: {path}") from exc
    except OSError as exc:
        raise PolicyFileError(f"Policy file {path} cannot be read: {exc}") from exc
    try:
        parsed = PolicyFile.model_validate(yaml.safe_load(raw))
    except (yaml.YAMLError, ValueError) as exc:
        raise PolicyFileError(f"Policy file {path} is invalid: {exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()[:8]
    return LoadedPolicy(file=parsed, version=f"{parsed.policy_version}+{digest}")


def default_policy_path(policy_dir: str) -> Path:
    return Path(policy_dir) / DEFAULT_POLICY_FILENAME


# ---------------------------------------------------------------------- operand checks


def _check_operand(field: str, operator: str, operand: Any) -> None:
    where = f"{field}.{operator}"
    if operator in _ORDERING:
        if isinstance(operand, bool) or not isinstance(operand, int | float):
            raise ValueError(f"{where} needs a number, got {operand!r}")
    elif operator == "exists":
        if not isinstance(operand, bool):
            raise ValueError(f"{where} needs true or false, got {operand!r}")
    elif operator in _LISTS:
        if not isinstance(operand, list) or not operand:
            raise ValueError(f"{where} needs a non-empty list")
        wanted = str if operator == "glob" else (bool, int, float, str)
        if not all(isinstance(item, wanted) for item in operand):
            raise ValueError(f"{where} has an item of the wrong type: {operand!r}")
    elif not isinstance(operand, bool | int | float | str):
        raise ValueError(f"{where} needs a single value, got {operand!r}")
