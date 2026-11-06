"""Policy enforcement tests (Stage 3): the rule engine running inside the real gateway.

AC-15 (Scenario B), AC-16 (Scenario C), AC-17 (Scenario D), AC-18 (a call that is not ALLOW
never reaches a downstream server), AC-19 (allowed calls reach the right server), AC-20 (fail
closed, no read-only exception) and AC-21 (rate limit). Scenario A is only *paused* here
(REQUIRE_APPROVAL); the approval flow itself is Stage 4.

Every denial test checks the downstream call counter in `GatewayHarness.downstream.calls`.
"""

from __future__ import annotations

from typing import Any

import pytest

from agents.business.scenarios import UNSAFE_CALLS, UnsafeCall
from gateway.identity.registry import Identity
from gateway.mcp_gateway.tools import ToolEntry, ToolRegistry
from gateway.policy.decision import PolicyDecision
from gateway.policy.engine import RuleEngine
from gateway.policy.policy_file import default_policy_path
from gateway.policy.rate_limit import TokenBucketRateLimiter
from tests.gateway_harness import GatewayHarness, running_gateway
from tests.unit.test_policy_engine import MATRIX, Clock


@pytest.fixture
async def pgw():  # type: ignore[no-untyped-def]
    """A gateway running the real policy file."""
    async with running_gateway(rules=True) as harness:
        yield harness


def verdict(result: Any) -> tuple[str, str]:
    assert result.is_error, "expected a denial"
    assert result.structured_content is not None
    return result.structured_content["decision"], result.structured_content["reason_code"]


def call_events(gw: GatewayHarness) -> list:  # type: ignore[type-arg]
    return [e for e in gw.audit.events if e.method == "tools/call"]


def demo_run_registry() -> ToolRegistry:
    """The Scenario C demo run: `read_env_secrets` is made visible to the Developer Agent so
    the attempt can be shown (docs/permission-matrix.md section 3)."""
    base = ToolRegistry.load()
    tools = {n: base.get(n) for n in base.names()}
    secrets = tools["read_env_secrets"]
    assert secrets is not None
    tools["read_env_secrets"] = ToolEntry(
        server=secrets.server,
        owner=secrets.owner,
        sensitivity=secrets.sensitivity,
        roles=("developer",),
    )
    return ToolRegistry({k: v for k, v in tools.items() if v is not None})


# ------------------------------------------------------------------ the planned unsafe calls


@pytest.mark.parametrize("call", UNSAFE_CALLS, ids=[c.call_id for c in UNSAFE_CALLS])
async def test_every_planned_unsafe_call_is_stopped_before_it_runs(call: UnsafeCall) -> None:
    """The deterministic baseline replay, now through the gateway. Same calls, same agents."""
    tools = demo_run_registry() if call.tool == "read_env_secrets" else None
    async with running_gateway(rules=True, tools=tools) as gw:
        async with gw.client(gw.keys[call.agent].key) as client:
            result = await client.call_tool(call.tool, dict(call.args))

        assert verdict(result) == (call.decision, call.reason), call.call_id
        assert gw.downstream.calls == [], f"{call.call_id} reached a downstream server"
        event = call_events(gw)[-1]
        assert (event.decision, event.reason_code) == (call.decision, call.reason)
        assert event.execution_status == "not_executed"


async def test_all_twelve_unsafe_calls_are_stopped_and_none_reaches_a_server() -> None:
    assert len(UNSAFE_CALLS) == 12
    stopped = 0
    async with running_gateway(rules=True, tools=demo_run_registry()) as gw:
        for call in UNSAFE_CALLS:
            async with gw.client(gw.keys[call.agent].key) as client:
                result = await client.call_tool(call.tool, dict(call.args))
            assert result.is_error
            stopped += 1
        assert stopped == 12
        assert gw.downstream.calls == []


# ------------------------------------------------------------------ scenarios B, C, D (AC-15..17)


async def test_scenario_b_delete_prod_resource_is_blocked(pgw: GatewayHarness) -> None:
    async with pgw.client(pgw.keys["it_ops"].key) as client:
        result = await client.call_tool(
            "delete_resource", {"resource_id": "RES-001", "env": "prod"}
        )
    assert verdict(result) == ("BLOCK", "PROD_DESTRUCTIVE_DENIED")
    assert pgw.downstream.calls == []


async def test_scenario_b_the_resource_still_exists_afterwards() -> None:
    """Prove it by effect, not only by counter: the prod database can still be read."""
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            await client.call_tool("delete_resource", {"resource_id": "RES-001", "env": "prod"})
            await client.call_tool("disable_monitoring", {"service": "auth", "env": "prod"})
            status = await client.call_tool(
                "get_service_status", {"service": "auth", "env": "prod"}
            )
        assert not status.is_error
        assert status.structured_content is not None
        assert status.structured_content.get("monitoring") == "enabled"
        assert [c.tool for c in gw.downstream.calls] == ["get_service_status"]


async def test_scenario_c_demo_run_secrets_are_blocked_by_policy() -> None:
    async with running_gateway(rules=True, tools=demo_run_registry()) as gw:
        async with gw.client(gw.keys["developer"].key) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            result = await client.call_tool("read_env_secrets", {"scope": "prod"})
        assert "read_env_secrets" in names
        assert verdict(result) == ("BLOCK", "SECRETS_ACCESS_DENIED")
        assert gw.downstream.calls == []


async def test_scenario_c_normal_run_secrets_are_not_granted(pgw: GatewayHarness) -> None:
    async with pgw.client(pgw.keys["developer"].key) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool("read_env_secrets", {"scope": "prod"})
    assert "read_env_secrets" not in names
    assert verdict(result) == ("BLOCK", "TOOL_NOT_GRANTED")
    assert pgw.downstream.calls == []


async def test_scenario_c_no_role_and_no_scope_can_read_secrets() -> None:
    """Even if every role were granted the tool, the policy has no allow condition for it."""
    base = ToolRegistry.load()
    everyone = {n: base.get(n) for n in base.names()}
    s = everyone["read_env_secrets"]
    assert s is not None
    everyone["read_env_secrets"] = ToolEntry(
        server=s.server,
        owner=s.owner,
        sensitivity=s.sensitivity,
        roles=("finance", "it_ops", "developer"),
    )
    registry = ToolRegistry({k: v for k, v in everyone.items() if v is not None})
    async with running_gateway(rules=True, tools=registry) as gw:
        for role in ("finance", "it_ops", "developer"):
            for scope in ("prod", "dev", "staging", "anything"):
                async with gw.client(gw.keys[role].key) as client:
                    result = await client.call_tool("read_env_secrets", {"scope": scope})
                assert verdict(result) == ("BLOCK", "SECRETS_ACCESS_DENIED"), (role, scope)
        assert gw.downstream.calls == []


async def test_scenario_d_large_export_needs_approval(pgw: GatewayHarness) -> None:
    async with pgw.client(pgw.keys["finance"].key) as client:
        result = await client.call_tool("export_records", {"table": "invoices", "limit": 5000})
    assert verdict(result) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
    assert pgw.downstream.calls == []


async def test_scenario_d_payroll_export_is_blocked(pgw: GatewayHarness) -> None:
    async with pgw.client(pgw.keys["finance"].key) as client:
        result = await client.call_tool("export_records", {"table": "payroll", "limit": 40})
    assert verdict(result) == ("BLOCK", "SENSITIVE_TABLE_EXPORT")
    assert pgw.downstream.calls == []


# ------------------------------------------------------------------ scenario A: paused


async def test_scenario_a_bank_detail_change_is_paused_and_not_executed() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool(
                "update_beneficiary_bank_details",
                {"beneficiary_id": "BEN-001", "account_number": "99887766"},
            )
            assert verdict(result) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
            assert result.structured_content is not None
            assert "99887766" not in str(result.structured_content)
            paid = await client.call_tool(
                "initiate_payment", {"invoice_id": "INV-0001", "amount": 12000}
            )
        assert verdict(paid) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
        assert gw.downstream.calls == []


# ------------------------------------------------------------------ boundaries (AC-14)


async def test_the_5000_boundary_through_the_gateway() -> None:
    """INV-0002 is exactly 5,000 and INV-0003 is 5,000.01 (planted by the seed generator)."""
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            at = await client.call_tool(
                "initiate_payment", {"invoice_id": "INV-0002", "amount": 5000}
            )
            over = await client.call_tool(
                "initiate_payment", {"invoice_id": "INV-0003", "amount": 5000.01}
            )
        assert not at.is_error, at
        assert verdict(over) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
        assert [(c.tool, c.args["invoice_id"]) for c in gw.downstream.calls] == [
            ("initiate_payment", "INV-0002")
        ]


async def test_the_list_and_export_boundaries_through_the_gateway() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            ok50 = await client.call_tool("list_invoices", {"limit": 50})
            over51 = await client.call_tool("list_invoices", {"limit": 51})
            default = await client.call_tool("list_invoices", {})
            ok100 = await client.call_tool("export_records", {"table": "invoices", "limit": 100})
            over101 = await client.call_tool("export_records", {"table": "invoices", "limit": 101})
        assert not ok50.is_error and not default.is_error and not ok100.is_error
        assert verdict(over51) == ("BLOCK", "ARG_LIMIT_EXCEEDED")
        assert verdict(over101) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
        assert len(gw.downstream.calls) == 3


async def test_the_restart_rules_through_the_gateway() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            dev = await client.call_tool("restart_service", {"service": "auth", "env": "dev"})
            prod_ok = await client.call_tool(
                "restart_service", {"service": "billing-api", "env": "prod"}
            )
            prod_restricted = await client.call_tool(
                "restart_service", {"service": "monitoring", "env": "prod"}
            )
        assert not dev.is_error, dev
        assert verdict(prod_ok) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
        assert verdict(prod_restricted) == ("BLOCK", "RESTRICTED_SERVICE")
        assert len(gw.downstream.calls) == 1


async def test_the_protected_branch_rules_through_the_gateway() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["developer"].key) as client:
            push_main = await client.call_tool(
                "repo_push_commit", {"repo": "billing-service", "branch": "main"}
            )
            delete_release = await client.call_tool(
                "repo_delete_branch", {"repo": "billing-service", "branch": "release/1.0"}
            )
            create = await client.call_tool(
                "repo_create_branch", {"repo": "billing-service", "branch": "feature/x"}
            )
            push_feature = await client.call_tool(
                "repo_push_commit", {"repo": "billing-service", "branch": "feature/x"}
            )
        assert verdict(push_main) == ("BLOCK", "PROTECTED_BRANCH")
        assert verdict(delete_release) == ("BLOCK", "PROTECTED_BRANCH")
        assert not create.is_error and not push_feature.is_error
        assert [c.tool for c in gw.downstream.calls] == ["repo_create_branch", "repo_push_commit"]


# ------------------------------------------------------------------ AC-18 across the whole matrix


@pytest.mark.parametrize("case", MATRIX, ids=[f"{c[1]}-{c[2]}" for c in MATRIX])
async def test_only_allowed_matrix_rows_reach_a_downstream_server(case: Any) -> None:
    role, tool, args, decision, reason = case
    registry = demo_run_registry()  # makes read_env_secrets reachable by the developer
    # Tools nobody is granted never reach the policy; the grant check stops them first.
    granted = registry.is_granted(tool, role)
    async with running_gateway(rules=True, tools=registry) as gw:
        async with gw.client(gw.keys[role].key) as client:
            result = await client.call_tool(tool, args)
        calls = call_events(gw)
        if not granted:
            assert verdict(result) == ("BLOCK", "TOOL_NOT_GRANTED")
            assert gw.downstream.calls == []
        elif decision == "ALLOW":
            # The mock servers may still refuse for business reasons (unknown id); what matters
            # is that the policy let it through to the right server.
            assert [c.tool for c in gw.downstream.calls] == [tool]
            assert (calls[-1].decision, calls[-1].reason_code) == ("ALLOW", reason)
        else:
            assert verdict(result) == (decision, reason)
            assert gw.downstream.calls == []
            assert calls[-1].execution_status == "not_executed"


async def test_allowed_calls_reach_the_right_server_and_return_its_result(
    pgw: GatewayHarness,
) -> None:
    async with pgw.client(pgw.keys["finance"].key) as client:
        invoice = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
    assert not invoice.is_error
    assert invoice.structured_content is not None
    assert invoice.structured_content["invoice_id"] == "INV-0005"
    assert [(c.server, c.tool) for c in pgw.downstream.calls] == [("company_data", "get_invoice")]
    assert call_events(pgw)[-1].policy_version is not None


# ------------------------------------------------------------------ audit carries the decision


async def test_the_policy_version_and_reason_are_recorded_on_every_decision(
    pgw: GatewayHarness,
) -> None:
    async with pgw.client(pgw.keys["finance"].key) as client:
        await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        await client.call_tool("list_invoices", {"limit": 99})
        await client.call_tool("export_records", {"table": "invoices", "limit": 500})
    events = call_events(pgw)
    assert [(e.decision, e.reason_code) for e in events] == [
        ("ALLOW", "ALLOWED_BY_POLICY"),
        ("BLOCK", "ARG_LIMIT_EXCEEDED"),
        ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED"),
    ]
    versions = {e.policy_version for e in events}
    assert len(versions) == 1
    (version,) = versions
    assert version is not None and version.startswith("1.0+")


async def test_agents_see_a_decision_a_reason_and_a_correlation_id_and_nothing_else(
    pgw: GatewayHarness,
) -> None:
    async with pgw.client(pgw.keys["finance"].key) as client:
        result = await client.call_tool("list_invoices", {"limit": 99})
    assert result.structured_content is not None
    assert set(result.structured_content) == {
        "decision",
        "reason_code",
        "correlation_id",
        "message",
    }
    shown = {k: v for k, v in result.structured_content.items() if k != "correlation_id"}
    text = str(shown) + result.content[0].text.replace(  # type: ignore[union-attr]
        result.structured_content["correlation_id"], ""
    )
    for leak in ("50", "policy.yaml", "lte", "rule", "1.0+"):
        assert leak not in text, leak


# ------------------------------------------------------------------ claims change nothing


async def test_a_claimed_role_or_agent_name_cannot_change_the_decision() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            result = await client.call_tool(
                "delete_resource",
                {"resource_id": "RES-001", "env": "prod", "role": "admin", "agent_name": "root"},
            )
        # Identity-like fields are stripped before the schema check, so the call is judged on
        # what it really is.
        assert verdict(result) == ("BLOCK", "PROD_DESTRUCTIVE_DENIED")
        assert gw.downstream.calls == []
        assert call_events(gw)[-1].spoof_attempt is True


@pytest.mark.parametrize("env", ["PROD", "Prod", " prod", "prod ", "production", "prod\n"])
async def test_spelling_tricks_cannot_turn_a_prod_call_into_a_dev_call(env: str) -> None:
    """The schema allows only dev / staging / prod, so a lookalike never reaches the rules."""
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            result = await client.call_tool("restart_service", {"service": "auth", "env": env})
        assert verdict(result) == ("BLOCK", "INVALID_ARGUMENTS")
        assert gw.downstream.calls == []


@pytest.mark.parametrize(
    "branch", ["main ", "Main", "MAIN", "release", "refs/heads/main", "main\n", "./main"]
)
async def test_branch_lookalikes_are_judged_by_the_exact_rule(branch: str) -> None:
    """These are not protected names, so the policy allows them; the mock server then says the
    branch does not exist. The rule is exact on purpose: protection is for the real names."""
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["developer"].key) as client:
            result = await client.call_tool(
                "repo_push_commit", {"repo": "billing-service", "branch": branch}
            )
        assert call_events(gw)[-1].reason_code == "ALLOWED_BY_POLICY"
        assert result.is_error  # the server has no such branch
        assert [c.tool for c in gw.downstream.calls] == ["repo_push_commit"]


# ------------------------------------------------------------------ rate limit (AC-21)


async def test_the_11th_call_in_a_burst_is_refused_and_never_forwarded() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(30, 10, clock)
    async with running_gateway(rules=True, limiter=limiter) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            results = [
                await client.call_tool("get_invoice", {"invoice_id": "INV-0005"}) for _ in range(12)
            ]
        assert [r.is_error for r in results] == [False] * 10 + [True, True]
        assert verdict(results[10]) == ("BLOCK", "RATE_LIMIT_EXCEEDED")
        assert len(gw.downstream.calls) == 10
        last = call_events(gw)[-1]
        assert (last.decision, last.reason_code) == ("BLOCK", "RATE_LIMIT_EXCEEDED")
        assert last.execution_status == "not_executed"

        clock.now += 2.0  # one token refills every 2 seconds at 30 per minute
        async with gw.client(gw.keys["finance"].key) as client:
            again = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        assert not again.is_error


async def test_the_rate_limit_is_per_agent_not_shared() -> None:
    limiter = TokenBucketRateLimiter(30, 2, Clock())
    async with running_gateway(rules=True, limiter=limiter) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            for _ in range(2):
                await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
            blocked = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        async with gw.client(gw.keys["it_ops"].key) as client:
            other = await client.call_tool("get_service_status", {"service": "auth", "env": "dev"})
        assert verdict(blocked) == ("BLOCK", "RATE_LIMIT_EXCEEDED")
        assert not other.is_error


async def test_the_rate_limit_also_stops_calls_that_policy_would_otherwise_block() -> None:
    """A flood of forbidden calls is throttled too; each is still audited."""
    limiter = TokenBucketRateLimiter(30, 2, Clock())
    async with running_gateway(rules=True, limiter=limiter) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            reasons = [
                verdict(
                    await client.call_tool(
                        "delete_resource", {"resource_id": "RES-001", "env": "prod"}
                    )
                )[1]
                for _ in range(4)
            ]
        assert reasons == ["PROD_DESTRUCTIVE_DENIED"] * 2 + ["RATE_LIMIT_EXCEEDED"] * 2
        assert len(call_events(gw)) == 4
        assert gw.downstream.calls == []


# ------------------------------------------------------------------ fail closed (AC-20)


class RaisingPolicy:
    def evaluate(self, identity: Identity, tool: str, args: dict[str, Any]) -> PolicyDecision:
        raise RuntimeError("policy engine exploded")


class NotADecisionPolicy:
    def evaluate(self, identity: Identity, tool: str, args: dict[str, Any]) -> Any:
        return None


class MadeUpDecisionPolicy:
    def evaluate(self, identity: Identity, tool: str, args: dict[str, Any]) -> Any:
        return PolicyDecision("allow", "ALLOWED_BY_POLICY", "x")  # type: ignore[arg-type]


class BrokenLimiter(TokenBucketRateLimiter):
    def allow(self, agent_id: str) -> bool:
        raise RuntimeError("limiter state lost")


READ_ONLY_CALLS = [
    ("finance", "get_invoice", {"invoice_id": "INV-0005"}),
    ("finance", "get_payment_status", {"invoice_id": "INV-0005"}),
    ("it_ops", "get_service_status", {"service": "auth", "env": "dev"}),
    ("developer", "repo_get_metadata", {"repo": "web-portal"}),
    ("developer", "get_service_status", {"service": "search", "env": "dev"}),
]


@pytest.mark.parametrize("policy_cls", [RaisingPolicy, NotADecisionPolicy, MadeUpDecisionPolicy])
@pytest.mark.parametrize(("role", "tool", "args"), READ_ONLY_CALLS)
async def test_a_policy_fault_blocks_even_read_only_calls(
    policy_cls: type, role: str, tool: str, args: dict[str, Any]
) -> None:
    """There is no emergency exception: a read-only tool fails closed like any other."""
    async with running_gateway(policy=policy_cls()) as gw:
        async with gw.client(gw.keys[role].key) as client:
            result = await client.call_tool(tool, args)
        assert verdict(result) == ("BLOCK", "POLICY_UNAVAILABLE")
        assert gw.downstream.calls == []
        assert "exploded" not in result.content[0].text  # type: ignore[union-attr]


async def test_a_broken_rate_limiter_fails_closed_for_read_only_calls() -> None:
    async with running_gateway(rules=True, limiter=BrokenLimiter(30, 10)) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        assert verdict(result) == ("BLOCK", "POLICY_UNAVAILABLE")
        assert gw.downstream.calls == []
        assert call_events(gw)[-1].reason_code == "POLICY_UNAVAILABLE"


async def test_a_policy_fault_does_not_stop_the_gateway_answering_the_next_call() -> None:
    flaky = {"fail": True}
    real: dict[str, RuleEngine] = {}

    class Flaky:
        def evaluate(self, identity: Identity, tool: str, args: dict[str, Any]) -> PolicyDecision:
            if flaky["fail"]:
                raise RuntimeError("temporary")
            return real["engine"].evaluate(identity, tool, args)

    async with running_gateway(policy=Flaky()) as gw:
        # Build the real engine against the same catalog the gateway loaded.
        real["engine"] = RuleEngine.from_file(
            default_policy_path("policies"),
            tool_arguments={
                n: set(t.input_schema.get("properties", {})) for n, t in gw.catalog.items()
            },
            limiter=TokenBucketRateLimiter(6000, 1000),
        )
        async with gw.client(gw.keys["finance"].key) as client:
            down = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
            flaky["fail"] = False
            up = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        assert verdict(down) == ("BLOCK", "POLICY_UNAVAILABLE")
        assert not up.is_error
        assert len(gw.downstream.calls) == 1


# ------------------------------------------------------------------ start-up fails closed


async def test_the_gateway_does_not_start_on_a_bad_policy_file(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from contextlib import asynccontextmanager

    from mcp.client import Client

    from core.config import Settings
    from core.seed_generator import generate_all
    from gateway.mcp_gateway.__main__ import build_gateway
    from gateway.policy.policy_file import PolicyFileError
    from mcp_servers.company_data.server import create_server as company
    from mcp_servers.developer_tools.server import create_server as developer
    from mcp_servers.operations.server import create_server as operations

    c, o, d = generate_all()
    servers = {
        "company_data": company(c),
        "operations": operations(o),
        "developer_tools": developer(d),
    }

    @asynccontextmanager
    async def connect(name: str):  # type: ignore[no-untyped-def]
        async with Client(servers[name]) as client:
            yield client

    settings = Settings(_env_file=None, postgres_password="x")  # secret-scan: ignore
    bad = tmp_path / "policy.yaml"
    bad.write_text("version: 1\npolicy_version: '1'\ntools:\n  get_invoice: {}\n", encoding="utf-8")
    with pytest.raises(PolicyFileError):
        await build_gateway(settings, database_url="sqlite://", connector=connect, policy_path=bad)
    with pytest.raises(PolicyFileError, match="not found"):
        await build_gateway(
            settings,
            database_url="sqlite://",
            connector=connect,
            policy_path=tmp_path / "gone.yaml",
        )
    app = await build_gateway(settings, database_url="sqlite://", connector=connect)
    assert app is not None
