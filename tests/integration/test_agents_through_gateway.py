"""The real business agents working through the gateway (Stage 2).

Each agent runs its normal loop with a scripted model, but its MCP client is a gateway client
with the agent's own API key. Also covers gateway start-up and the registration script.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import asynccontextmanager

import httpx
import pytest
from mcp.client import Client
from pydantic import SecretStr

from agents.business.developer import run_developer_agent
from agents.business.finance import run_finance_agent
from agents.business.gateway_client import agent_key, gateway_client
from agents.business.it_ops import run_it_ops_agent
from agents.business.runtime import run_agent
from core.config import Settings
from core.db import make_engine
from core.llm import Message, ToolCall, ToolSpec
from gateway.identity.registry import AgentRegistry
from gateway.mcp_gateway.__main__ import build_gateway
from gateway.mcp_gateway.downstream import GatewayStartupError
from scripts.register_agents import AGENTS, register_all
from tests.gateway_harness import BASE_URL, GatewayHarness, running_gateway


class ScriptedModel:
    def __init__(self, script: list[Message]) -> None:
        self._script = list(script)
        self.offered: list[str] = []

    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message:
        self.offered = [t.name for t in tools]
        return self._script.pop(0)


def calls(*items: tuple[str, dict[str, object]]) -> Message:
    return Message(role="model", tool_calls=tuple(ToolCall(name=n, args=a) for n, a in items))


def final(text: str) -> Message:
    return Message(role="model", text=text)


def agent_client(gw: GatewayHarness, role: str) -> Client:
    """A gateway client for one agent, wired to the in-process gateway app."""
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gw.app),
        headers={"Authorization": f"Bearer {gw.keys[role].key}"},
    )
    return gateway_client(BASE_URL, gw.keys[role].key, http=http)


# ------------------------------------------------------------------ agents through the gateway


async def test_finance_agent_works_through_the_gateway(gw: GatewayHarness) -> None:
    model = ScriptedModel(
        [
            calls(("get_invoice", {"invoice_id": "INV-0005"})),
            calls(("get_payment_status", {"invoice_id": "INV-0005"})),
            final("checked"),
        ]
    )
    async with agent_client(gw, "finance") as client:
        run = await run_finance_agent(model=model, client=client, task="check INV-0005")

    assert [c.name for c in run.calls] == ["get_invoice", "get_payment_status"]
    assert not any(c.is_error for c in run.calls)
    assert [c.tool for c in gw.downstream.calls] == ["get_invoice", "get_payment_status"]
    assert {e.agent_id for e in gw.audit.events} == {"finance-agent"}


async def test_it_ops_agent_works_through_the_gateway(gw: GatewayHarness) -> None:
    model = ScriptedModel(
        [
            calls(("get_service_status", {"service": "billing-api", "env": "staging"})),
            calls(("update_ticket", {"ticket_id": "TCK-001", "comment": "checked"})),
            final("done"),
        ]
    )
    async with agent_client(gw, "it_ops") as client:
        run = await run_it_ops_agent(model=model, client=client, task="check")

    assert not any(c.is_error for c in run.calls)
    assert [c.server for c in gw.downstream.calls] == ["operations", "operations"]


async def test_developer_agent_reaches_two_servers_through_one_gateway_connection(
    gw: GatewayHarness,
) -> None:
    model = ScriptedModel(
        [
            calls(
                ("repo_get_metadata", {"repo": "web-portal"}),
                ("get_service_status", {"service": "search", "env": "dev"}),
            ),
            final("reviewed"),
        ]
    )
    async with agent_client(gw, "developer") as client:
        run = await run_developer_agent(
            model=model, developer_tools_client=client, operations_client=client, task="review"
        )

    assert not any(c.is_error for c in run.calls)
    assert {c.server for c in gw.downstream.calls} == {"developer_tools", "operations"}
    assert "read_env_secrets" not in model.offered


async def test_a_hidden_tool_is_not_even_offered_to_the_model(gw: GatewayHarness) -> None:
    model = ScriptedModel([final("nothing")])
    async with agent_client(gw, "finance") as client:
        await run_agent(
            model=model,
            system_prompt="x",
            clients=[client],
            allowed_tools=("get_invoice", "read_payroll", "delete_resource"),
            task="x",
        )
    assert model.offered == ["get_invoice"]


async def test_a_tool_the_gateway_does_not_grant_never_reaches_the_model_or_downstream(
    gw: GatewayHarness,
) -> None:
    """Defence in depth. The model asks for `restart_service` (not a finance tool). The loop
    cannot route it because the gateway never listed it, so it reports the tool as unavailable.
    Nothing reaches a downstream server."""
    model = ScriptedModel(
        [calls(("restart_service", {"service": "auth", "env": "dev"})), final("could not")]
    )
    async with agent_client(gw, "finance") as client:
        run = await run_agent(
            model=model,
            system_prompt="x",
            clients=[client],
            allowed_tools=("get_invoice", "restart_service"),
            task="x",
        )
    assert model.offered == ["get_invoice"]
    assert run.calls[0].is_error
    assert "not available" in str(run.calls[0].result)
    assert gw.downstream.calls == []


async def test_a_direct_call_to_a_tool_the_role_lacks_is_a_safe_denial(
    gw: GatewayHarness,
) -> None:
    """Bypassing the loop entirely: the gateway itself still says no."""
    async with agent_client(gw, "finance") as client:
        result = await client.call_tool("restart_service", {"service": "auth", "env": "dev"})
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "TOOL_NOT_GRANTED"
    assert gw.downstream.calls == []


async def test_an_agent_with_the_wrong_key_gets_nothing(gw: GatewayHarness) -> None:
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gw.app),
        headers={"Authorization": "Bearer afk_" + "Z" * 43},
    )
    async with gateway_client(BASE_URL, "unused", http=http) as client:
        result = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["reason_code"] == "UNREGISTERED_AGENT"
    assert gw.downstream.calls == []


# ------------------------------------------------------------------ keys from settings


def test_agent_key_reads_the_secret_from_settings() -> None:
    settings = Settings(_env_file=None, finance_agent_key=SecretStr("afk_example"))
    assert agent_key("finance", settings) == "afk_example"


@pytest.mark.parametrize("agent", ["finance", "it_ops", "developer"])
def test_a_missing_agent_key_is_an_error_not_a_fallback(agent: str) -> None:
    with pytest.raises(RuntimeError, match="_AGENT_KEY is not set"):
        agent_key(agent, Settings(_env_file=None))


# ------------------------------------------------------------------ registration script


def test_register_all_creates_the_three_agents_with_working_keys() -> None:
    registry = AgentRegistry(make_engine("sqlite://"))
    registry.create_tables()

    issued = register_all(registry, rotate=False, ttl_days=30)

    assert set(issued) == {"FINANCE_AGENT_KEY", "IT_OPS_AGENT_KEY", "DEVELOPER_AGENT_KEY"}
    for agent_id, role, env_name in AGENTS:
        result = registry.authenticate(issued[env_name].key)
        assert result.identity is not None
        assert (result.identity.agent_id, result.identity.role) == (agent_id, role)


def test_register_all_does_not_re_key_existing_agents_unless_asked() -> None:
    registry = AgentRegistry(make_engine("sqlite://"))
    registry.create_tables()
    first = register_all(registry, rotate=False, ttl_days=30)

    assert register_all(registry, rotate=False, ttl_days=30) == {}
    assert registry.authenticate(first["FINANCE_AGENT_KEY"].key).identity is not None

    rotated = register_all(registry, rotate=True, ttl_days=30)
    assert registry.authenticate(first["FINANCE_AGENT_KEY"].key).failure == "unknown"
    assert registry.authenticate(rotated["FINANCE_AGENT_KEY"].key).identity is not None


# ------------------------------------------------------------------ start-up fails closed


async def test_build_gateway_starts_when_every_approved_tool_is_offered() -> None:
    from core.seed_generator import generate_all
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

    app = await build_gateway(Settings(_env_file=None), database_url="sqlite://", connector=connect)
    assert app is not None


async def test_build_gateway_refuses_to_start_if_a_server_is_unreachable() -> None:
    @asynccontextmanager
    async def connect(name: str):  # type: ignore[no-untyped-def]
        raise ConnectionError("nothing listening")
        yield  # pragma: no cover

    with pytest.raises(GatewayStartupError):
        await build_gateway(Settings(_env_file=None), database_url="sqlite://", connector=connect)


async def test_running_gateway_helper_cleans_up() -> None:
    async with running_gateway() as gw:
        assert len(gw.registry.list_agents()) == 3
