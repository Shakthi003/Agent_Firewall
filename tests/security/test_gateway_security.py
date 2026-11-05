"""Gateway security tests (Stage 2): scenarios E, F and G.

AC-03 (spoofed identity), AC-05 (unknown tool), AC-06 (tool not granted). In every denied case
the downstream call counter must stay at zero.
"""

from __future__ import annotations

import pytest

from gateway.mcp_gateway.tools import ToolRegistry
from tests.gateway_harness import GatewayHarness, running_gateway


def calls(gw: GatewayHarness) -> list:  # type: ignore[type-arg]
    return [e for e in gw.audit.events if e.method == "tools/call"]


# ------------------------------------------------------------------ G: unknown tool (AC-05)


@pytest.mark.parametrize("agent", ["finance", "it_ops", "developer"])
@pytest.mark.parametrize(
    "tool", ["format_disk", "", "GET_INVOICE", "get_invoice ", "../etc/passwd"]
)
async def test_scenario_g_unknown_tool_is_denied(gw: GatewayHarness, agent: str, tool: str) -> None:
    async with gw.client(gw.keys[agent].key) as client:
        result = await client.call_tool(tool, {})

    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "UNKNOWN_TOOL"
    assert result.structured_content["decision"] == "BLOCK"
    assert gw.downstream.calls == []
    assert calls(gw)[-1].reason_code == "UNKNOWN_TOOL"
    assert calls(gw)[-1].tool is None  # an unregistered name is not echoed into the audit field


async def test_a_tool_the_server_offers_but_the_registry_omits_is_unreachable() -> None:
    """`delete_resource` really exists on the Operations server. Leave it out of the registry
    and the gateway neither lists it nor forwards a call to it."""
    full = ToolRegistry.load()
    kept = {name: full.get(name) for name in full.names() if name != "delete_resource"}
    async with running_gateway(tools=ToolRegistry({k: v for k, v in kept.items() if v})) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            result = await client.call_tool("delete_resource", {"resource_id": "R", "env": "dev"})

        assert "delete_resource" not in names
        assert "restart_service" in names
        assert result.structured_content is not None
        assert result.structured_content["reason_code"] == "UNKNOWN_TOOL"
        assert gw.downstream.calls == []


async def test_the_gateway_refuses_to_start_if_an_approved_tool_is_missing_downstream() -> None:
    from contextlib import asynccontextmanager

    from mcp.client import Client

    from core.seed_generator import generate_all
    from gateway.mcp_gateway.downstream import Downstream, GatewayStartupError, load_catalog
    from mcp_servers.operations.server import create_server

    _, operations, _ = generate_all()
    server = create_server(operations)

    @asynccontextmanager
    async def connect(name: str):  # type: ignore[no-untyped-def]
        if name != "operations":
            raise ConnectionError(f"{name} is down")
        async with Client(server) as client:
            yield client

    with pytest.raises(GatewayStartupError):
        await load_catalog(ToolRegistry.load(), Downstream(connect))


# ------------------------------------------------------------------ E: not granted (AC-06)


@pytest.mark.parametrize(
    ("agent", "tool", "args"),
    [
        ("developer", "read_payroll", {"employee_id": "EMP-001"}),  # scenario E
        ("developer", "get_employee_record", {"employee_id": "EMP-001"}),
        ("developer", "read_env_secrets", {"scope": "prod"}),  # scenario C2 (normal run)
        ("finance", "read_env_secrets", {"scope": "prod"}),
        ("finance", "delete_resource", {"resource_id": "RES-001", "env": "dev"}),
        ("finance", "repo_delete_branch", {"repo": "web-portal", "branch": "x"}),
        ("it_ops", "get_invoice", {"invoice_id": "INV-0001"}),
        ("it_ops", "read_payroll", {"employee_id": "EMP-001"}),
        ("it_ops", "repo_push_commit", {"repo": "web-portal", "branch": "x"}),
        ("developer", "delete_resource", {"resource_id": "RES-001", "env": "dev"}),
        ("developer", "restart_service", {"service": "auth", "env": "dev"}),
        ("developer", "initiate_payment", {"invoice_id": "INV-0005", "amount": 1}),
    ],
)
async def test_scenario_e_a_registered_tool_not_granted_to_the_role_is_denied(
    gw: GatewayHarness, agent: str, tool: str, args: dict[str, object]
) -> None:
    async with gw.client(gw.keys[agent].key) as client:
        result = await client.call_tool(tool, args)

    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "TOOL_NOT_GRANTED"
    assert gw.downstream.calls == []
    event = calls(gw)[-1]
    assert event.tool == tool  # registered, so it is safe to record
    assert event.agent_id == gw.keys[agent].agent_id


async def test_grant_is_checked_before_arguments_so_nothing_leaks_about_the_schema(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["developer"].key) as client:
        result = await client.call_tool("read_payroll", {"completely": "wrong"})
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "TOOL_NOT_GRANTED"


# ------------------------------------------------------------------ F: spoofed identity (AC-03)


async def test_scenario_f_a_wrong_agent_name_never_changes_the_identity(
    gw: GatewayHarness,
) -> None:
    """The finance key claims to be the IT agent. The call is still judged as finance."""
    async with gw.client(gw.keys["finance"].key) as client:
        result = await client.call_tool(
            "get_invoice", {"invoice_id": "INV-0001", "agent_name": "it-ops-agent"}
        )
        denied = await client.call_tool(
            "restart_service", {"service": "auth", "env": "dev", "agent_name": "it-ops-agent"}
        )

    assert not result.is_error  # finance may call get_invoice
    assert denied.is_error  # the claimed IT role did not help
    assert denied.structured_content is not None
    assert denied.structured_content["reason_code"] == "TOOL_NOT_GRANTED"
    for event in calls(gw):
        assert (event.agent_id, event.role) == ("finance-agent", "finance")


async def test_a_conflicting_identity_claim_is_logged_as_a_spoofing_attempt(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        await client.call_tool(
            "get_invoice", {"invoice_id": "INV-0001", "agent_name": "it-ops-agent"}
        )
    event = calls(gw)[-1]
    assert event.spoof_attempt is True
    assert event.spoofed_fields == ("agent_name",)
    assert event.agent_id == "finance-agent"
    assert "it-ops-agent" not in repr(event)  # the claimed value is not stored


@pytest.mark.parametrize(
    "field", ["agent_name", "agent_id", "role", "identity", "user", "requested_by", "AGENT_NAME"]
)
async def test_identity_fields_are_not_forwarded_downstream(gw: GatewayHarness, field: str) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001", field: "root"})

    assert not result.is_error
    assert gw.downstream.calls[0].args == {"invoice_id": "INV-0001"}
    assert calls(gw)[-1].spoof_attempt is True


async def test_a_matching_claim_is_removed_but_not_called_spoofing(gw: GatewayHarness) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        await client.call_tool(
            "get_invoice", {"invoice_id": "INV-0001", "agent_name": "finance-agent"}
        )
    event = calls(gw)[-1]
    assert event.spoofed_fields == ("agent_name",)
    assert event.spoof_attempt is False
    assert gw.downstream.calls[0].args == {"invoice_id": "INV-0001"}


async def test_an_identity_claim_in_request_meta_is_ignored_and_logged(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        await client.call_tool(
            "get_invoice", {"invoice_id": "INV-0001"}, meta={"agent_name": "it-ops-agent"}
        )
    event = calls(gw)[-1]
    assert event.agent_id == "finance-agent"
    assert event.spoof_attempt is True


async def test_a_claim_without_a_credential_is_a_denied_spoofing_attempt(
    gw: GatewayHarness,
) -> None:
    async with gw.client(None) as client:
        result = await client.call_tool(
            "get_invoice", {"invoice_id": "INV-0001", "agent_name": "finance-agent"}
        )
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "UNREGISTERED_AGENT"
    event = calls(gw)[-1]
    assert event.agent_id is None
    assert event.spoof_attempt is True
    assert gw.downstream.calls == []


async def test_a_valid_key_for_one_agent_cannot_be_used_to_act_as_another(
    gw: GatewayHarness,
) -> None:
    async with gw.client(gw.keys["developer"].key) as client:
        result = await client.call_tool(
            "update_beneficiary_bank_details",
            {"beneficiary_id": "BEN-001", "account_number": "1", "agent_name": "finance-agent"},
        )
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "TOOL_NOT_GRANTED"
    assert gw.downstream.calls == []


# ------------------------------------------------------------------ session / reuse


async def test_each_request_is_authenticated_on_its_own(gw: GatewayHarness) -> None:
    """A connection opened with a good key does not stay trusted after the agent is disabled."""
    async with gw.client(gw.keys["finance"].key) as client:
        first = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
        gw.registry.set_status("finance-agent", "disabled")
        second = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})

    assert not first.is_error
    assert second.is_error
    assert second.structured_content is not None
    assert second.structured_content["reason_code"] == "UNREGISTERED_AGENT"
    assert len(gw.downstream.calls) == 1
