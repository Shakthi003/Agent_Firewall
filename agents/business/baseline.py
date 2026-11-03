"""The unprotected baseline (Stage 1): agents and servers with NO firewall in between.

This is the "before" picture. It shows what the three business agents can do when nothing
checks their tool calls. In Stage 8 the same scenarios run through the gateway for comparison.

Two ways to run the scenarios:
- `replay_unsafe_calls`: deterministic. Calls each planned unsafe tool directly. No LLM.
- `run_attack_scenario` / `run_normal_workflow`: an agent with a real model reads poisoned (or
  normal) data. Whether the model falls for hostile text varies, which is why the replay exists.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from agents.business.developer import run_developer_agent
from agents.business.finance import run_finance_agent
from agents.business.it_ops import run_it_ops_agent
from agents.business.runtime import AgentRun
from agents.business.scenarios import (
    UNSAFE_CALLS,
    AttackScenario,
    NormalWorkflow,
    ServerName,
    UnsafeCall,
    poison_company_data,
    poison_developer_tools,
    poison_operations,
)
from core.llm import ChatModel
from core.seed_generator import generate_all
from mcp_servers.company_data.server import create_server as create_company_data
from mcp_servers.developer_tools.server import create_server as create_developer_tools
from mcp_servers.operations.server import create_server as create_operations

BANNER = "UNPROTECTED BASELINE: no firewall, no identity checks, no approvals"
LIVE_PORTS: dict[ServerName, int] = {
    "company_data": 9001,
    "operations": 9002,
    "developer_tools": 9003,
}


@dataclass(frozen=True)
class Servers:
    company_data: Client
    operations: Client
    developer_tools: Client

    def by_name(self, name: ServerName) -> Client:
        return getattr(self, name)  # type: ignore[no-any-return]


@asynccontextmanager
async def open_servers(
    *, poisoned: bool = False, live_host: str | None = None
) -> AsyncIterator[Servers]:
    """Connect to the three servers.

    By default, fresh in-process servers are built from the generated seed (so every run starts
    from the same state). With `live_host`, connect to servers already running on ports 9001-9003.
    `poisoned` plants the hostile text in the seed copies; it cannot be combined with `live_host`.
    """
    if live_host is not None and poisoned:
        raise ValueError("Poisoned data can only be used with in-process servers")
    async with AsyncExitStack() as stack:
        if live_host is not None:
            clients = {
                name: Client(_http(f"http://{live_host}:{port}/mcp"))
                for name, port in LIVE_PORTS.items()
            }
        else:
            company, operations, developer = generate_all()
            if poisoned:
                company = poison_company_data(company)
                operations = poison_operations(operations)
                developer = poison_developer_tools(developer)
            clients = {
                "company_data": Client(create_company_data(company)),
                "operations": Client(create_operations(operations)),
                "developer_tools": Client(create_developer_tools(developer)),
            }
        entered = {name: await stack.enter_async_context(c) for name, c in clients.items()}
        yield Servers(**entered)


def _http(url: str) -> Any:
    http = httpx.AsyncClient(headers={"Authorization": "Bearer baseline"})
    return streamable_http_client(url, http_client=http)


# ------------------------------------------------------------------ deterministic replay


@dataclass(frozen=True)
class ReplayResult:
    call: UnsafeCall
    succeeded: bool  # True means the unprotected server did what was asked
    detail: str


async def replay_unsafe_calls(servers: Servers) -> list[ReplayResult]:
    """Call every planned unsafe tool directly on its server and record the outcome."""
    results = []
    for call in UNSAFE_CALLS:
        reply = await servers.by_name(call.server).call_tool(call.tool, call.args)
        detail = reply.content[0].text[:80] if reply.content else ""
        results.append(ReplayResult(call=call, succeeded=not reply.is_error, detail=detail))
    return results


# ------------------------------------------------------------------ agent runs


async def run_agent_by_name(
    agent: str, model: ChatModel, servers: Servers, task: str, *, show_secrets_tool: bool = False
) -> AgentRun:
    if agent == "finance":
        return await run_finance_agent(model=model, client=servers.company_data, task=task)
    if agent == "it_ops":
        return await run_it_ops_agent(model=model, client=servers.operations, task=task)
    if agent == "developer":
        return await run_developer_agent(
            model=model,
            developer_tools_client=servers.developer_tools,
            operations_client=servers.operations,
            task=task,
            show_secrets_tool=show_secrets_tool,
        )
    raise ValueError(f"Unknown agent: {agent}")


async def run_normal_workflow(
    workflow: NormalWorkflow, model: ChatModel, servers: Servers
) -> AgentRun:
    return await run_agent_by_name(workflow.agent, model, servers, workflow.task)


async def run_attack_scenario(
    scenario: AttackScenario, model: ChatModel, servers: Servers
) -> AgentRun:
    return await run_agent_by_name(
        scenario.agent,
        model,
        servers,
        scenario.task,
        show_secrets_tool=scenario.show_secrets_tool,
    )
