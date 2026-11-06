"""Policy engine unit tests (Stage 3): file format, matching rules, rate limit, the real policy.

Covers AC-12 (decision shape), AC-13 (every matrix row), AC-14 (boundaries) and AC-21 (rate
limit). Nothing here starts a gateway; `tests/security/test_policy_enforcement.py` does that.
"""

from __future__ import annotations

import asyncio
import textwrap
from collections.abc import Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp.client import Client

from agents.business.scenarios import UNSAFE_CALLS
from core.config import Settings
from core.seed_generator import generate_all
from gateway.identity.registry import Identity
from gateway.mcp_gateway.downstream import Downstream, load_catalog
from gateway.mcp_gateway.tools import ToolRegistry
from gateway.policy.decision import POLICY_FILE_REASON_CODES, PolicyDecision
from gateway.policy.engine import RuleEngine
from gateway.policy.policy_file import (
    PolicyFileError,
    default_policy_path,
    load_policy,
)
from gateway.policy.rate_limit import TokenBucketRateLimiter
from mcp_servers.company_data.server import create_server as create_company_data
from mcp_servers.developer_tools.server import create_server as create_developer_tools
from mcp_servers.operations.server import create_server as create_operations

REAL_POLICY = default_policy_path("policies")
ROOMY = (6000.0, 1000)  # a limiter that never interferes


def identity(role: str = "finance", agent_id: str | None = None) -> Identity:
    return Identity(agent_id=agent_id or f"{role}-agent", role=role, key_version=1)  # type: ignore[arg-type]


def roomy_limiter() -> TokenBucketRateLimiter:
    return TokenBucketRateLimiter(*ROOMY)


def small_policy(tmp_path: Path, body: str, version: str = "t1") -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(
        f'version: 1\npolicy_version: "{version}"\ntools:\n' + textwrap.indent(body, "  "),
        encoding="utf-8",
    )
    return path


def small_engine(tmp_path: Path, body: str, **kwargs: Any) -> RuleEngine:
    return RuleEngine.from_file(
        small_policy(tmp_path, body),
        tool_arguments={"t": {"x", "y"}},
        limiter=kwargs.get("limiter") or roomy_limiter(),
    )


@pytest.fixture(scope="module")
def tool_arguments() -> dict[str, set[str]]:
    """The argument names every approved tool really declares, read from the real servers."""

    async def read() -> dict[str, set[str]]:
        company, operations, developer = generate_all()
        servers = {
            "company_data": create_company_data(company),
            "operations": create_operations(operations),
            "developer_tools": create_developer_tools(developer),
        }

        @asynccontextmanager
        async def connect(name: str):  # type: ignore[no-untyped-def]
            async with Client(servers[name]) as client:
                yield client

        catalog = await load_catalog(ToolRegistry.load(), Downstream(connect))
        return {n: set(t.input_schema.get("properties", {})) for n, t in catalog.items()}

    return asyncio.run(read())


@pytest.fixture
def engine(tool_arguments: dict[str, set[str]]) -> RuleEngine:
    return RuleEngine.from_file(REAL_POLICY, tool_arguments=tool_arguments, limiter=roomy_limiter())


# ------------------------------------------------------------------ policy file format


def test_the_shipped_policy_loads_and_covers_every_tool() -> None:
    loaded = load_policy(REAL_POLICY)
    assert set(loaded.file.tools) == ToolRegistry.load().names()
    assert len(loaded.file.tools) == 22


def test_the_version_names_the_policy_and_the_exact_file(tmp_path: Path) -> None:
    body = "t:\n  default: {decision: ALLOW}\n"
    one = load_policy(small_policy(tmp_path, body, "7.1")).version
    assert one == load_policy(small_policy(tmp_path, body, "7.1")).version  # stable
    assert one.startswith("7.1+") and len(one) == len("7.1+") + 8
    two = load_policy(small_policy(tmp_path, body + "\n# a comment\n", "7.1")).version
    assert two != one  # any change to the file changes the recorded version


def _with_when(when: str) -> str:
    return f"t:\n  rules: [{{when: {when}, decision: ALLOW}}]\n  default: {{decision: ALLOW}}\n"


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ("t:\n  default: {decision: ALLOW, reason: ARG_LIMIT_EXCEEDED}\n", "ALLOW with a reason"),
        ("t:\n  default: {decision: BLOCK}\n", "BLOCK without a reason"),
        ("t:\n  default: {decision: REQUIRE_APPROVAL}\n", "approval without a reason"),
        ("t:\n  default: {decision: BLOCK, reason: MADE_UP}\n", "unknown reason code"),
        (
            "t:\n  rules: [{when: {}, decision: ALLOW}]\n  default: {decision: ALLOW}\n",
            "empty when",
        ),
        (_with_when("{x: {}}"), "field without operator"),
        (_with_when("{x: {approx: 1}}"), "unknown operator"),
        (_with_when("{x: {lte: '5'}}"), "ordering operand is text"),
        (_with_when("{x: {lte: true}}"), "ordering operand is a bool"),
        (_with_when("{x: {in: []}}"), "empty list"),
        (_with_when("{x: {in: x}}"), "in needs a list"),
        (_with_when("{x: {exists: 1}}"), "exists needs a bool"),
        (_with_when("{x: {glob: [1]}}"), "glob needs text"),
        (
            "t:\n  rules: [{when: {x: {eq: 1}}, decision: ALLOW, bogus: 1}]\n"
            "  default: {decision: ALLOW}\n",
            "unknown key in rule",
        ),
    ],
)
def test_a_bad_policy_file_is_refused(tmp_path: Path, body: str, why: str) -> None:
    with pytest.raises(PolicyFileError):
        load_policy(small_policy(tmp_path, body))


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not: a policy",
        "version: 2\npolicy_version: '1'\ntools: {t: {default: {decision: ALLOW}}}\n",
        "version: 1\ntools: {t: {default: {decision: ALLOW}}}\n",  # no policy_version
        "version: 1\npolicy_version: 'has space'\ntools: {t: {default: {decision: ALLOW}}}\n",
        "version: 1\npolicy_version: '1'\ntools: {}\n",
        "version: [",
    ],
)
def test_a_malformed_policy_document_is_refused(tmp_path: Path, text: str) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyFileError):
        load_policy(path)


def test_a_missing_policy_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PolicyFileError, match="not found"):
        load_policy(tmp_path / "nope.yaml")


def test_the_reason_codes_a_file_may_use_are_all_in_the_catalogue() -> None:
    catalogue = (Path(__file__).parents[2] / "docs" / "permission-matrix.md").read_text("utf-8")
    for code in POLICY_FILE_REASON_CODES - {"ALLOWED_BY_POLICY", "DESTRUCTIVE_TOOL_DENIED"}:
        assert f"`{code}`" in catalogue, code


# ------------------------------------------------------------------ policy vs the tool registry


def test_every_approved_tool_must_have_a_policy_entry(tmp_path: Path) -> None:
    path = small_policy(tmp_path, "t:\n  default: {decision: ALLOW}\n")
    with pytest.raises(PolicyFileError, match="no policy entry"):
        RuleEngine.from_file(path, tool_arguments={"t": set(), "u": set()}, limiter=roomy_limiter())


def test_a_policy_entry_for_an_unapproved_tool_is_refused(tmp_path: Path) -> None:
    path = small_policy(
        tmp_path, "t:\n  default: {decision: ALLOW}\nu:\n  default: {decision: ALLOW}\n"
    )
    with pytest.raises(PolicyFileError, match="unapproved"):
        RuleEngine.from_file(path, tool_arguments={"t": set()}, limiter=roomy_limiter())


def test_a_rule_that_tests_an_undeclared_field_is_refused(tmp_path: Path) -> None:
    body = "t:\n  rules: [{when: {z: {eq: 1}}, decision: ALLOW}]\n  default: {decision: ALLOW}\n"
    with pytest.raises(PolicyFileError, match="undeclared"):
        small_engine(tmp_path, body)


def test_the_shipped_policy_matches_the_real_tool_schemas(
    tool_arguments: dict[str, set[str]],
) -> None:
    RuleEngine.from_file(REAL_POLICY, tool_arguments=tool_arguments, limiter=roomy_limiter())


def test_removing_a_tool_from_the_shipped_policy_stops_the_engine(
    tmp_path: Path, tool_arguments: dict[str, set[str]]
) -> None:
    text = REAL_POLICY.read_text("utf-8")
    cut = text.replace(
        "  read_env_secrets:\n    default: {decision: BLOCK, reason: SECRETS_ACCESS_DENIED}\n", ""
    )
    assert cut != text
    path = tmp_path / "policy.yaml"
    path.write_text(cut, encoding="utf-8")
    with pytest.raises(PolicyFileError, match="read_env_secrets"):
        RuleEngine.from_file(path, tool_arguments=tool_arguments, limiter=roomy_limiter())


# ------------------------------------------------------------------ matching semantics


def decide(engine: RuleEngine, args: dict[str, Any], role: str = "finance") -> PolicyDecision:
    return engine.evaluate(identity(role), "t", args)


def test_first_matching_rule_wins(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {lte: 10}}, decision: ALLOW}
    - {when: {x: {lte: 100}}, decision: REQUIRE_APPROVAL, reason: APPROVAL_REQUIRED}
  default: {decision: BLOCK, reason: ARG_LIMIT_EXCEEDED}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {"x": 10}).decision == "ALLOW"
    assert decide(e, {"x": 11}).decision == "REQUIRE_APPROVAL"
    assert decide(e, {"x": 100}).decision == "REQUIRE_APPROVAL"
    assert decide(e, {"x": 101}) == PolicyDecision("BLOCK", "ARG_LIMIT_EXCEEDED", e.version)


def test_all_fields_of_a_rule_must_match(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {eq: a}, y: {lte: 5}}, decision: ALLOW}
  default: {decision: BLOCK, reason: ARG_LIMIT_EXCEEDED}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {"x": "a", "y": 5}).decision == "ALLOW"
    assert decide(e, {"x": "a", "y": 6}).decision == "BLOCK"
    assert decide(e, {"x": "b", "y": 1}).decision == "BLOCK"


def test_an_absent_field_never_matches_an_allow_rule(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {lte: 50}}, decision: ALLOW}
  default: {decision: BLOCK, reason: ARG_LIMIT_EXCEEDED}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {}).decision == "BLOCK"
    assert decide(e, {"y": 1}).decision == "BLOCK"


def test_exists_false_matches_only_an_absent_field(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {exists: false}}, decision: ALLOW}
  default: {decision: BLOCK, reason: ARG_LIMIT_EXCEEDED}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {}).decision == "ALLOW"
    assert decide(e, {"x": None}).decision == "BLOCK"
    assert decide(e, {"x": 1}).decision == "BLOCK"


@pytest.mark.parametrize("value", ["50", "5", True, False, None, [50], {"n": 5}, "inf"])
def test_a_value_of_the_wrong_type_matches_no_ordering_rule(tmp_path: Path, value: Any) -> None:
    body = """\
t:
  rules:
    - {when: {x: {lte: 50}}, decision: ALLOW}
  default: {decision: BLOCK, reason: ARG_LIMIT_EXCEEDED}
"""
    assert decide(small_engine(tmp_path, body), {"x": value}).decision == "BLOCK"


def test_text_and_numbers_are_never_equal(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {eq: 1}}, decision: ALLOW}
  default: {decision: BLOCK, reason: ARG_LIMIT_EXCEEDED}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {"x": 1}).decision == "ALLOW"
    assert decide(e, {"x": 1.0}).decision == "ALLOW"
    assert decide(e, {"x": "1"}).decision == "BLOCK"
    assert decide(e, {"x": True}).decision == "BLOCK"


def test_eq_on_text_is_exact_and_case_sensitive(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {eq: prod}}, decision: BLOCK, reason: PROD_DESTRUCTIVE_DENIED}
  default: {decision: ALLOW}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {"x": "prod"}).decision == "BLOCK"
    # The gateway's schema check stops these first; the engine on its own must not match them.
    assert decide(e, {"x": "PROD"}).decision == "ALLOW"
    assert decide(e, {"x": "prod "}).decision == "ALLOW"


def test_ne_not_in_and_in(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {ne: a}}, decision: REQUIRE_APPROVAL, reason: APPROVAL_REQUIRED}
  default: {decision: ALLOW}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {"x": "a"}).decision == "ALLOW"
    assert decide(e, {"x": "b"}).decision == "REQUIRE_APPROVAL"
    assert decide(e, {"x": 1}).decision == "ALLOW"  # a different kind of value is not "not a"
    assert decide(e, {}).decision == "ALLOW"

    body = """\
t:
  rules:
    - {when: {x: {not_in: [a, b]}}, decision: BLOCK, reason: ARG_LIMIT_EXCEEDED}
  default: {decision: ALLOW}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {"x": "c"}).decision == "BLOCK"
    assert decide(e, {"x": "a"}).decision == "ALLOW"
    assert decide(e, {}).decision == "ALLOW"


def test_glob_matches_whole_values_only(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {x: {glob: [main, "release/*"]}}, decision: BLOCK, reason: PROTECTED_BRANCH}
  default: {decision: ALLOW}
"""
    e = small_engine(tmp_path, body)
    for protected in ("main", "release/1.0", "release/2.0-rc1", "release/x/y"):
        assert decide(e, {"x": protected}).decision == "BLOCK", protected
    for open_ in ("feature/main", "mainline", "main2", "Main", "xrelease/1.0", "release", ""):
        assert decide(e, {"x": open_}).decision == "ALLOW", open_
    assert decide(e, {"x": 5}).decision == "ALLOW"


def test_role_can_be_tested_and_comes_from_the_verified_identity(tmp_path: Path) -> None:
    body = """\
t:
  rules:
    - {when: {role: {eq: developer}}, decision: BLOCK, reason: TOOL_NOT_GRANTED}
  default: {decision: ALLOW}
"""
    e = small_engine(tmp_path, body)
    assert decide(e, {}, role="developer").decision == "BLOCK"
    assert decide(e, {}, role="finance").decision == "ALLOW"
    # An argument called "role" cannot override the verified one.
    assert decide(e, {"role": "finance"}, role="developer").decision == "BLOCK"
    assert decide(e, {"role": "developer"}, role="finance").decision == "ALLOW"


def test_every_decision_carries_a_reason_code_and_the_policy_version(
    engine: RuleEngine,
) -> None:
    allowed = engine.evaluate(identity("finance"), "get_invoice", {"invoice_id": "INV-0001"})
    assert allowed == PolicyDecision("ALLOW", "ALLOWED_BY_POLICY", engine.version)
    blocked = engine.evaluate(identity("developer"), "read_env_secrets", {"scope": "prod"})
    assert blocked == PolicyDecision("BLOCK", "SECRETS_ACCESS_DENIED", engine.version)
    assert engine.version.startswith("1.0+")


def test_an_unknown_tool_is_blocked_even_if_it_reaches_the_engine(engine: RuleEngine) -> None:
    got = engine.evaluate(identity(), "format_disk", {})
    assert (got.decision, got.reason_code) == ("BLOCK", "UNKNOWN_TOOL")


# ------------------------------------------------------------------ rate limit (AC-21)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_the_default_limit_is_30_per_minute_with_a_burst_of_10() -> None:
    settings = Settings(_env_file=None)
    assert settings.rate_limit_calls_per_minute == 30
    assert settings.rate_limit_burst == 10


def test_both_limits_are_configurable_and_validated() -> None:
    settings = Settings(_env_file=None, rate_limit_calls_per_minute=60, rate_limit_burst=3)
    assert (settings.rate_limit_calls_per_minute, settings.rate_limit_burst) == (60, 3)
    for bad in ({"rate_limit_calls_per_minute": 0}, {"rate_limit_burst": 0}):
        with pytest.raises(ValueError):
            Settings(_env_file=None, **bad)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(0, 10)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(30, 0)


def test_a_burst_of_10_then_the_11th_call_is_refused() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(30, 10, clock)
    assert [limiter.allow("a") for _ in range(10)] == [True] * 10
    assert limiter.allow("a") is False
    assert limiter.allow("a") is False  # a refused call takes nothing and does not queue


def test_the_bucket_refills_at_30_per_minute() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(30, 10, clock)
    for _ in range(10):
        limiter.allow("a")
    clock.now += 1.9  # 0.95 of a token: not yet
    assert limiter.allow("a") is False
    clock.now += 0.2  # now 1.0 token
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    clock.now += 600  # a long pause refills to the burst size and no further
    assert [limiter.allow("a") for _ in range(11)] == [True] * 10 + [False]


def test_sustained_use_is_capped_at_30_calls_per_minute() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(30, 10, clock)
    allowed = 0
    for _ in range(600):  # one call every 0.1 s for a minute: far above the limit
        allowed += limiter.allow("a")
        clock.now += 0.1
    assert allowed == 10 + 29  # the burst, plus what refilled in the 60 s


def test_agents_have_separate_buckets() -> None:
    limiter = TokenBucketRateLimiter(30, 2, Clock())
    assert limiter.allow("a") and limiter.allow("a")
    assert limiter.allow("a") is False
    assert limiter.allow("b") is True


def test_a_clock_that_goes_backwards_cannot_grant_extra_calls() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(30, 2, clock)
    assert limiter.allow("a") and limiter.allow("a")
    clock.now -= 500
    assert limiter.allow("a") is False


def test_the_engine_blocks_with_rate_limit_exceeded(tmp_path: Path) -> None:
    limiter = TokenBucketRateLimiter(30, 3, Clock())
    e = small_engine(tmp_path, "t:\n  default: {decision: ALLOW}\n", limiter=limiter)
    got = [decide(e, {}).decision for _ in range(5)]
    assert got == ["ALLOW"] * 3 + ["BLOCK"] * 2
    last = decide(e, {})
    assert (last.decision, last.reason_code) == ("BLOCK", "RATE_LIMIT_EXCEEDED")
    assert last.policy_version == e.version


# ------------------------------------------------------------------ matrix (AC-13, AC-14)

Case = tuple[str, str, dict[str, Any], str, str]  # role, tool, args, decision, reason

OK = "ALLOWED_BY_POLICY"
APPROVAL = "APPROVAL_REQUIRED"

MATRIX: list[Case] = [
    # Finance: plain reads and the always-approval tool
    ("finance", "get_invoice", {"invoice_id": "INV-0001"}, "ALLOW", OK),
    ("finance", "get_payment_status", {"invoice_id": "INV-0001"}, "ALLOW", OK),
    ("finance", "get_customer_record", {"customer_id": "CUS-001"}, "ALLOW", OK),
    (
        "finance",
        "update_beneficiary_bank_details",
        {"beneficiary_id": "BEN-001", "account_number": "99887766"},
        "REQUIRE_APPROVAL",
        APPROVAL,
    ),
    # list_invoices: limit <= 50 (boundary 50 / 51), default when absent
    ("finance", "list_invoices", {}, "ALLOW", OK),
    ("finance", "list_invoices", {"status": "approved"}, "ALLOW", OK),
    ("finance", "list_invoices", {"limit": 1}, "ALLOW", OK),
    ("finance", "list_invoices", {"limit": 49}, "ALLOW", OK),
    ("finance", "list_invoices", {"limit": 50}, "ALLOW", OK),
    ("finance", "list_invoices", {"limit": 51}, "BLOCK", "ARG_LIMIT_EXCEEDED"),
    ("finance", "list_invoices", {"limit": 100}, "BLOCK", "ARG_LIMIT_EXCEEDED"),
    # initiate_payment: amount <= 5,000 (boundary 5,000 / 5,000.01)
    ("finance", "initiate_payment", {"invoice_id": "I", "amount": 0.01}, "ALLOW", OK),
    ("finance", "initiate_payment", {"invoice_id": "I", "amount": 4999.99}, "ALLOW", OK),
    ("finance", "initiate_payment", {"invoice_id": "I", "amount": 5000}, "ALLOW", OK),
    ("finance", "initiate_payment", {"invoice_id": "I", "amount": 5000.0}, "ALLOW", OK),
    (
        "finance",
        "initiate_payment",
        {"invoice_id": "I", "amount": 5000.01},
        "REQUIRE_APPROVAL",
        APPROVAL,
    ),
    (
        "finance",
        "initiate_payment",
        {"invoice_id": "I", "amount": 12000},
        "REQUIRE_APPROVAL",
        APPROVAL,
    ),
    # export_records: invoices up to 100 rows allowed, above that approval, other tables blocked
    ("finance", "export_records", {"table": "invoices", "limit": 1}, "ALLOW", OK),
    ("finance", "export_records", {"table": "invoices", "limit": 100}, "ALLOW", OK),
    (
        "finance",
        "export_records",
        {"table": "invoices", "limit": 101},
        "REQUIRE_APPROVAL",
        APPROVAL,
    ),
    (
        "finance",
        "export_records",
        {"table": "invoices", "limit": 5000},
        "REQUIRE_APPROVAL",
        APPROVAL,
    ),
    *[
        ("finance", "export_records", {"table": t, "limit": n}, "BLOCK", "SENSITIVE_TABLE_EXPORT")
        for t in ("customers", "employees", "payroll")
        for n in (1, 100, 101, 5000)
    ],
    # Tools granted to nobody
    ("finance", "get_employee_record", {"employee_id": "E"}, "BLOCK", "TOOL_NOT_GRANTED"),
    ("finance", "read_payroll", {"employee_id": "E"}, "BLOCK", "TOOL_NOT_GRANTED"),
    # IT Ops
    ("it_ops", "get_service_status", {"service": "auth", "env": "prod"}, "ALLOW", OK),
    ("it_ops", "update_ticket", {"ticket_id": "T", "comment": "c"}, "ALLOW", OK),
    ("it_ops", "send_notification", {"channel": "ops", "message": "m"}, "ALLOW", OK),
    ("it_ops", "restart_service", {"service": "billing-api", "env": "dev"}, "ALLOW", OK),
    ("it_ops", "restart_service", {"service": "auth", "env": "dev"}, "ALLOW", OK),
    ("it_ops", "restart_service", {"service": "auth", "env": "staging"}, "ALLOW", OK),
    (
        "it_ops",
        "restart_service",
        {"service": "billing-api", "env": "prod"},
        "REQUIRE_APPROVAL",
        APPROVAL,
    ),
    (
        "it_ops",
        "restart_service",
        {"service": "auth", "env": "prod"},
        "BLOCK",
        "RESTRICTED_SERVICE",
    ),
    (
        "it_ops",
        "restart_service",
        {"service": "monitoring", "env": "prod"},
        "BLOCK",
        "RESTRICTED_SERVICE",
    ),
    (
        "it_ops",
        "delete_resource",
        {"resource_id": "RES-001", "env": "prod"},
        "BLOCK",
        "PROD_DESTRUCTIVE_DENIED",
    ),
    (
        "it_ops",
        "delete_resource",
        {"resource_id": "RES-002", "env": "dev"},
        "BLOCK",
        "DESTRUCTIVE_TOOL_DENIED",
    ),
    (
        "it_ops",
        "delete_resource",
        {"resource_id": "R", "env": "staging"},
        "BLOCK",
        "DESTRUCTIVE_TOOL_DENIED",
    ),
    (
        "it_ops",
        "disable_monitoring",
        {"service": "auth", "env": "prod"},
        "BLOCK",
        "PROD_DESTRUCTIVE_DENIED",
    ),
    (
        "it_ops",
        "disable_monitoring",
        {"service": "auth", "env": "dev"},
        "BLOCK",
        "DESTRUCTIVE_TOOL_DENIED",
    ),
    # Developer
    ("developer", "get_service_status", {"service": "search", "env": "dev"}, "ALLOW", OK),
    ("developer", "repo_get_metadata", {"repo": "web-portal"}, "ALLOW", OK),
    ("developer", "repo_get_build_status", {"repo": "web-portal", "branch": "main"}, "ALLOW", OK),
    ("developer", "repo_create_branch", {"repo": "r", "branch": "feature/x"}, "ALLOW", OK),
    (
        "developer",
        "repo_open_pull_request",
        {"repo": "r", "source": "a", "target": "main"},
        "ALLOW",
        OK,
    ),
    ("developer", "repo_push_commit", {"repo": "r", "branch": "feature/x"}, "ALLOW", OK),
    ("developer", "repo_push_commit", {"repo": "r", "branch": "release-notes"}, "ALLOW", OK),
    ("developer", "repo_push_commit", {"repo": "r", "branch": "main"}, "BLOCK", "PROTECTED_BRANCH"),
    (
        "developer",
        "repo_push_commit",
        {"repo": "r", "branch": "release/1.0"},
        "BLOCK",
        "PROTECTED_BRANCH",
    ),
    ("developer", "repo_delete_branch", {"repo": "r", "branch": "feature/x"}, "ALLOW", OK),
    (
        "developer",
        "repo_delete_branch",
        {"repo": "r", "branch": "main"},
        "BLOCK",
        "PROTECTED_BRANCH",
    ),
    (
        "developer",
        "repo_delete_branch",
        {"repo": "r", "branch": "release/1.0"},
        "BLOCK",
        "PROTECTED_BRANCH",
    ),
    ("developer", "read_env_secrets", {"scope": "prod"}, "BLOCK", "SECRETS_ACCESS_DENIED"),
    ("developer", "read_env_secrets", {"scope": "dev"}, "BLOCK", "SECRETS_ACCESS_DENIED"),
]


@pytest.mark.parametrize(
    ("role", "tool", "args", "decision", "reason"),
    MATRIX,
    ids=[f"{c[1]}-{c[2]}" for c in MATRIX],
)
def test_each_matrix_row_gives_its_documented_decision(
    engine: RuleEngine, role: str, tool: str, args: dict[str, Any], decision: str, reason: str
) -> None:
    got = engine.evaluate(identity(role), tool, args)
    assert (got.decision, got.reason_code) == (decision, reason)
    assert got.policy_version == engine.version


def test_the_matrix_table_touches_every_approved_tool(tool_arguments: Mapping[str, Any]) -> None:
    assert {case[1] for case in MATRIX} == set(tool_arguments)


@pytest.mark.parametrize("call", UNSAFE_CALLS, ids=[c.call_id for c in UNSAFE_CALLS])
def test_every_planned_unsafe_call_gets_its_planned_decision(engine: RuleEngine, call: Any) -> None:
    got = engine.evaluate(identity(call.agent), call.tool, dict(call.args))
    assert (got.decision, got.reason_code) == (call.decision, call.reason), call.call_id
