"""Gateway integration tests (Stage 2): identity, tool list, pass-through, errors, audit.

Covers AC-01, AC-02, AC-04, AC-07, AC-08, AC-09, AC-10. A standard, unmodified MCP SDK client
talks to the real gateway app; the three real mock servers sit behind it.
"""

from __future__ import annotations

import json

import pytest
from mcp.shared.exceptions import MCPError

from agents.business.developer import DEVELOPER_TOOLS
from agents.business.finance import FINANCE_TOOLS
from agents.business.it_ops import IT_OPS_TOOLS
from tests.gateway_harness import GatewayHarness, running_gateway


def call_events(gw: GatewayHarness) -> list:  # type: ignore[type-arg]
    """Audit events for tools/call only. The SDK client also sends its own tools/list."""
    return [e for e in gw.audit.events if e.method == "tools/call"]


# ------------------------------------------------------------------ AC-08: MCP semantics


async def test_a_standard_mcp_client_lists_and_calls_through_the_gateway(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        tools = (await client.list_tools()).tools
        assert {t.name for t in tools} == set(FINANCE_TOOLS)
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})

    assert not result.is_error
    assert result.structured_content is not None
    assert result.structured_content["invoice_id"] == "INV-0001"


async def test_tool_definitions_pass_through_unchanged(gw: GatewayHarness) -> None:
    """Names, descriptions and argument schemas are the downstream server's own."""
    async with gw.client(gw.keys["it_ops"].key) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    restart = tools["restart_service"]
    assert restart.description == "Restart a service in one environment (mock)."
    assert restart.input_schema["required"] == ["service", "env"]
    assert restart.input_schema["properties"]["env"]["enum"] == ["dev", "staging", "prod"]


async def test_pass_through_returns_what_the_downstream_server_returns(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["it_ops"].key) as client:
        result = await client.call_tool("restart_service", {"service": "auth", "env": "dev"})
    assert not result.is_error
    assert result.structured_content is not None
    assert result.structured_content["action"] == "restarted"
    assert [c.tool for c in gw.downstream.calls] == ["restart_service"]


async def test_a_tool_error_from_the_downstream_server_is_passed_back_as_an_error(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-9999"})
    assert result.is_error
    assert "INV-9999" in result.content[0].text
    assert call_events(gw)[-1].execution_status == "tool_error"


async def test_each_agent_uses_tools_on_different_servers_through_one_gateway(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["developer"].key) as client:
        repo = await client.call_tool("repo_get_metadata", {"repo": "web-portal"})
        status = await client.call_tool("get_service_status", {"service": "search", "env": "dev"})
    assert not repo.is_error
    assert not status.is_error
    assert [c.server for c in gw.downstream.calls] == ["developer_tools", "operations"]


# ------------------------------------------------------------------ AC-01: identity from key


async def test_valid_key_sets_identity_and_role_from_the_credential(gw: GatewayHarness) -> None:
    async with gw.client(gw.keys["it_ops"].key) as client:
        await client.list_tools()
    event = gw.audit.events[-1]
    assert (event.agent_id, event.role, event.key_version) == ("it-ops-agent", "it_ops", 1)
    assert event.decision == "ALLOW"


# ------------------------------------------------------------------ AC-02: bad credentials


def _denial(exc: MCPError) -> dict[str, str]:
    assert isinstance(exc.data, dict)
    return exc.data


@pytest.mark.parametrize("key", [None, "", "afk_" + "A" * 43, "garbage"])
async def test_missing_or_unknown_key_cannot_list_tools(
    gw: GatewayHarness, key: str | None
) -> None:
    async with gw.client(key) as client:
        with pytest.raises(MCPError) as caught:
            await client.list_tools()
    assert _denial(caught.value)["reason_code"] == "UNREGISTERED_AGENT"
    assert gw.audit.events[-1].reason_code == "UNREGISTERED_AGENT"
    assert gw.audit.events[-1].agent_id is None


@pytest.mark.parametrize("key", [None, "afk_" + "A" * 43])
async def test_missing_or_unknown_key_cannot_call_tools(
    gw: GatewayHarness, key: str | None
) -> None:
    async with gw.client(key) as client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "UNREGISTERED_AGENT"
    assert gw.downstream.calls == []
    assert call_events(gw)[-1].auth_failure in {"missing", "unknown"}


async def test_disabled_agent_is_denied_on_the_next_request(gw: GatewayHarness) -> None:
    key = gw.keys["finance"].key
    async with gw.client(key) as client:
        assert not (await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})).is_error
    gw.registry.set_status("finance-agent", "disabled")

    async with gw.client(key) as client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})

    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "UNREGISTERED_AGENT"
    assert call_events(gw)[-1].auth_failure == "disabled"
    assert len(gw.downstream.calls) == 1  # only the first, allowed call


async def test_expired_key_is_denied() -> None:
    from core.db import make_engine
    from gateway.identity.registry import AgentRegistry

    clock = {"now": 1_800_000_000.0}
    registry = AgentRegistry(make_engine("sqlite://"), clock=lambda: clock["now"])
    registry.create_tables()
    issued = registry.register_agent("finance-agent", "finance", ttl_days=1)
    clock["now"] += 86_400
    assert registry.authenticate(issued.key).failure == "expired"


async def test_a_rotated_key_replaces_the_old_one(gw: GatewayHarness) -> None:
    old = gw.keys["finance"].key
    new = gw.registry.rotate_key("finance-agent")

    async with gw.client(old) as client:
        denied = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
    async with gw.client(new.key) as client:
        allowed = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})

    assert denied.is_error
    assert not allowed.is_error
    assert call_events(gw)[-1].key_version == 2


async def test_a_second_authorization_header_cannot_override_the_first(
    gw: GatewayHarness,
) -> None:
    import httpx

    from gateway.identity.middleware import bearer_token

    scope = {
        "headers": [
            (b"authorization", f"Bearer {gw.keys['finance'].key}".encode()),
            (b"authorization", b"Bearer afk_other"),
        ]
    }
    assert bearer_token(scope) is None  # ambiguous: treated as no credential
    assert httpx is not None


# ------------------------------------------------------------------ AC-04: tools/list filter


@pytest.mark.parametrize(
    ("agent", "expected"),
    [("finance", FINANCE_TOOLS), ("it_ops", IT_OPS_TOOLS), ("developer", DEVELOPER_TOOLS)],
)
async def test_tools_list_returns_only_the_tools_granted_to_the_caller(
    gw: GatewayHarness, agent: str, expected: tuple[str, ...]
) -> None:
    async with gw.client(gw.keys[agent].key) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert names == set(expected)


async def test_no_agent_ever_sees_the_hidden_tools(gw: GatewayHarness) -> None:
    for agent in ("finance", "it_ops", "developer"):
        async with gw.client(gw.keys[agent].key) as client:
            names = {t.name for t in (await client.list_tools()).tools}
        assert not names & {"read_env_secrets", "read_payroll", "get_employee_record"}, agent


# ------------------------------------------------------------------ AC-07: schema validation


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("get_invoice", {}),
        ("get_invoice", {"invoice_id": 123}),
        ("get_invoice", {"invoice_id": "INV-0001", "surprise": True}),
        ("list_invoices", {"limit": "many"}),
        ("initiate_payment", {"invoice_id": "INV-0005"}),
    ],
)
async def test_invalid_arguments_are_denied_and_never_reach_downstream(
    gw: GatewayHarness, tool: str, args: dict[str, object]
) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        result = await client.call_tool(tool, args)
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "INVALID_ARGUMENTS"
    assert gw.downstream.calls == []
    assert call_events(gw)[-1].reason_code == "INVALID_ARGUMENTS"


async def test_a_bad_enum_value_is_denied(gw: GatewayHarness) -> None:
    async with gw.client(gw.keys["it_ops"].key) as client:
        result = await client.call_tool("restart_service", {"service": "auth", "env": "mars"})
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "INVALID_ARGUMENTS"
    assert gw.downstream.calls == []


# ------------------------------------------------------------------ AC-09: correlation ID


async def test_correlation_id_is_in_the_audit_event_the_downstream_call_and_the_reply(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})

    forwarded = gw.downstream.calls[0]
    event = call_events(gw)[-1]
    assert result.meta is not None
    assert result.meta["correlation_id"] == forwarded.correlation_id == event.correlation_id
    assert len(event.correlation_id) == 32


async def test_every_request_gets_its_own_correlation_id(gw: GatewayHarness) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        for _ in range(3):
            await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
    ids = [e.correlation_id for e in gw.audit.events]
    assert len(ids) == len(set(ids))
    assert len(call_events(gw)) == 3


# ------------------------------------------------------------------ AC-10: safe errors


async def test_denials_contain_only_decision_reason_code_and_correlation_id(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        result = await client.call_tool("read_payroll", {"employee_id": "EMP-001"})

    assert result.is_error
    assert result.structured_content is not None
    assert set(result.structured_content) == {
        "decision",
        "reason_code",
        "correlation_id",
        "message",
    }
    body = json.loads(result.content[0].text)
    assert body == result.structured_content
    text = result.content[0].text
    for leak in ("Traceback", 'File "', "policy", "sqlalchemy", "registry.yaml"):
        assert leak not in text


async def test_a_downstream_crash_is_reported_safely(gw: GatewayHarness) -> None:
    async def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("secret internal detail: db password is hunter2")

    gw.downstream.call_tool = boom  # type: ignore[method-assign]
    async with gw.client(gw.keys["finance"].key) as client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})

    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "DOWNSTREAM_ERROR"
    assert "hunter2" not in result.content[0].text
    assert "RuntimeError" not in result.content[0].text
    assert call_events(gw)[-1].execution_status == "error"


async def test_a_slow_downstream_call_times_out_safely() -> None:
    async with running_gateway(call_timeout=0.3) as gw:
        gw.delay["seconds"] = 3.0
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
        gw.delay["seconds"] = 0.0

        assert result.is_error
        assert result.structured_content is not None
        assert result.structured_content["reason_code"] == "DOWNSTREAM_TIMEOUT"
        assert call_events(gw)[-1].execution_status == "timeout"


async def test_a_pipeline_fault_fails_closed_and_forwards_nothing() -> None:
    from gateway.policy.decision import PolicyDecision

    class BrokenPolicy:
        def evaluate(self, identity: object, tool: str, args: dict[str, object]) -> PolicyDecision:
            raise RuntimeError("policy engine exploded")

    async with running_gateway(policy=BrokenPolicy()) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})

        assert result.is_error
        assert result.structured_content is not None
        assert result.structured_content["reason_code"] == "POLICY_UNAVAILABLE"
        assert "exploded" not in result.content[0].text
        assert gw.downstream.calls == []


# ------------------------------------------------------------------ audit content


async def test_audit_events_never_contain_keys_or_secret_argument_values(
    gw: GatewayHarness,
) -> None:
    """Stage 5 keeps sanitized arguments (IDs, limits) because detections need them; keys and
    account numbers must still never appear (`tests/security/test_audit.py` goes further)."""
    key = gw.keys["finance"].key
    async with gw.client(key) as client:
        await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
        await client.call_tool(
            "update_beneficiary_bank_details",
            {
                "beneficiary_id": "BEN-001",
                "account_number": "99887766",
            },
        )

    dump = " ".join(repr(e) for e in gw.audit.events)
    assert key not in dump
    assert "99887766" not in dump
    event = call_events(gw)[-1]
    assert event.arg_names == ("account_number", "beneficiary_id")
    assert event.sanitized_args == {"account_number": "****7766", "beneficiary_id": "BEN-001"}
    assert event.args_hash is not None
    assert len(event.args_hash) == 64


async def test_every_gateway_request_writes_exactly_one_audit_event(gw: GatewayHarness) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        await client.list_tools()
        await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
        await client.call_tool("nope", {})
    calls = [(e.decision, e.reason_code) for e in call_events(gw)]
    assert calls == [("ALLOW", "ALLOW_ALL"), ("BLOCK", "UNKNOWN_TOOL")]
    assert all(e.method == "tools/list" for e in gw.audit.events if e not in call_events(gw))
