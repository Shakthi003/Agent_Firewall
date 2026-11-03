"""Tests for the agent loop and the three business agents (agents/business).

All use a scripted fake model, so they cost nothing and give the same result every time.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from mcp.client import Client

from agents.business.developer import DEVELOPER_TOOLS, run_developer_agent
from agents.business.finance import FINANCE_TOOLS, run_finance_agent
from agents.business.it_ops import IT_OPS_TOOLS, run_it_ops_agent
from agents.business.runtime import AgentStepLimitError, run_agent
from core.llm import Message, ToolCall, ToolSpec
from core.seed_generator import (
    PLANTED_LARGE_INVOICE_ID,
    PLANTED_PROD_RESOURCE_ID,
    generate_company_data,
    generate_developer_tools,
    generate_operations,
)
from mcp_servers.company_data.server import create_server
from mcp_servers.developer_tools.server import create_server as create_dev_server
from mcp_servers.operations.server import create_server as create_ops_server


class ScriptedModel:
    """Replies from a fixed script and records what it was offered."""

    def __init__(self, script: list[Message]) -> None:
        self._script = list(script)
        self.offered: list[str] = []
        self.systems: list[str] = []
        self.history: list[list[Message]] = []

    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message:
        self.offered = [t.name for t in tools]
        self.systems.append(system)
        self.history.append(list(messages))
        return self._script.pop(0)


def calls(*items: tuple[str, dict[str, object]]) -> Message:
    return Message(role="model", tool_calls=tuple(ToolCall(name=n, args=a) for n, a in items))


def final(text: str) -> Message:
    return Message(role="model", text=text)


@pytest.fixture
def client() -> Client:
    return Client(create_server(generate_company_data()))


async def test_loop_runs_tool_calls_and_returns_the_final_answer(client: Client) -> None:
    model = ScriptedModel(
        [
            calls(("get_invoice", {"invoice_id": PLANTED_LARGE_INVOICE_ID})),
            final("The invoice is 12000 USD."),
        ]
    )
    async with client:
        run = await run_finance_agent(model=model, client=client, task="Look up the invoice")
    assert run.final_text == "The invoice is 12000 USD."
    assert run.steps == 2
    assert [c.name for c in run.calls] == ["get_invoice"]
    assert run.calls[0].result["amount"] == 12000.0
    assert not run.calls[0].is_error


async def test_tool_result_is_fed_back_to_the_model(client: Client) -> None:
    model = ScriptedModel([calls(("get_invoice", {"invoice_id": "INV-0002"})), final("done")])
    async with client:
        await run_finance_agent(model=model, client=client, task="x")
    last_turn = model.history[1][-1]
    assert last_turn.role == "tool"
    assert last_turn.tool_results[0].content["amount"] == 5000.0


async def test_only_the_finance_tools_are_offered(client: Client) -> None:
    model = ScriptedModel([final("nothing to do")])
    async with client:
        await run_finance_agent(model=model, client=client, task="x")
    assert sorted(model.offered) == sorted(FINANCE_TOOLS)
    assert "read_payroll" not in model.offered
    assert "get_employee_record" not in model.offered


async def test_a_tool_error_is_reported_to_the_model_not_raised(client: Client) -> None:
    model = ScriptedModel([calls(("get_invoice", {"invoice_id": "INV-9999"})), final("not found")])
    async with client:
        run = await run_finance_agent(model=model, client=client, task="x")
    assert run.calls[0].is_error
    assert "INV-9999 not found" in run.calls[0].result["error"]
    assert run.final_text == "not found"


async def test_a_tool_outside_the_agents_list_is_not_run(client: Client) -> None:
    model = ScriptedModel([calls(("read_payroll", {"employee_id": "EMP-001"})), final("ok")])
    async with client:
        run = await run_finance_agent(model=model, client=client, task="x")
    assert run.calls[0].is_error
    assert "not available" in run.calls[0].result["error"]


async def test_several_calls_in_one_turn_all_run(client: Client) -> None:
    model = ScriptedModel(
        [
            calls(
                ("get_invoice", {"invoice_id": "INV-0001"}),
                ("get_invoice", {"invoice_id": "INV-0002"}),
            ),
            final("both"),
        ]
    )
    async with client:
        run = await run_finance_agent(model=model, client=client, task="x")
    assert [c.args["invoice_id"] for c in run.calls] == ["INV-0001", "INV-0002"]
    assert len(model.history[1][-1].tool_results) == 2


async def test_the_loop_stops_if_the_model_never_finishes(client: Client) -> None:
    forever = [calls(("get_invoice", {"invoice_id": "INV-0001"})) for _ in range(5)]
    async with client:
        with pytest.raises(AgentStepLimitError, match="3 steps"):
            await run_agent(
                model=ScriptedModel(forever),
                system_prompt="s",
                clients=[client],
                allowed_tools={"get_invoice"},
                task="x",
                max_steps=3,
            )


async def test_system_prompt_names_the_role(client: Client) -> None:
    model = ScriptedModel([final("ok")])
    async with client:
        await run_finance_agent(model=model, client=client, task="x")
    assert "Finance Agent" in model.systems[0]


async def test_baseline_the_finance_agent_can_make_a_12000_payment(client: Client) -> None:
    """Unprotected baseline: nothing stops the agent from a large payment."""
    model = ScriptedModel(
        [
            calls(("initiate_payment", {"invoice_id": PLANTED_LARGE_INVOICE_ID, "amount": 12000})),
            final("paid"),
        ]
    )
    async with client:
        run = await run_finance_agent(model=model, client=client, task="Pay INV-0001")
    assert not run.calls[0].is_error
    assert run.calls[0].result["status"] == "initiated"


# ------------------------------------------------------------------ IT Operations Agent


@pytest.fixture
def ops_client() -> Client:
    return Client(create_ops_server(generate_operations()))


async def test_it_ops_agent_offers_exactly_its_six_tools(ops_client: Client) -> None:
    model = ScriptedModel([final("nothing")])
    async with ops_client:
        await run_it_ops_agent(model=model, client=ops_client, task="x")
    assert sorted(model.offered) == sorted(IT_OPS_TOOLS)
    assert len(IT_OPS_TOOLS) == 6
    assert "IT Operations Agent" in model.systems[0]


async def test_it_ops_agent_checks_a_service_and_updates_a_ticket(ops_client: Client) -> None:
    model = ScriptedModel(
        [
            calls(
                ("get_service_status", {"service": "auth", "env": "prod"}),
                (
                    "update_ticket",
                    {"ticket_id": "TCK-001", "comment": "checked", "status": "closed"},
                ),
            ),
            final("done"),
        ]
    )
    async with ops_client:
        run = await run_it_ops_agent(model=model, client=ops_client, task="x")
    assert [c.name for c in run.calls] == ["get_service_status", "update_ticket"]
    assert not any(c.is_error for c in run.calls)
    assert run.calls[1].result["status"] == "closed"


async def test_it_ops_agent_cannot_use_other_agents_tools(ops_client: Client) -> None:
    model = ScriptedModel([calls(("read_payroll", {"employee_id": "EMP-001"})), final("ok")])
    async with ops_client:
        run = await run_it_ops_agent(model=model, client=ops_client, task="x")
    assert run.calls[0].is_error
    assert "not available" in run.calls[0].result["error"]


async def test_baseline_it_ops_agent_can_delete_the_prod_database(ops_client: Client) -> None:
    """Unprotected baseline (Scenario B): nothing stops the delete."""
    model = ScriptedModel(
        [
            calls(("delete_resource", {"resource_id": PLANTED_PROD_RESOURCE_ID, "env": "prod"})),
            final("deleted"),
        ]
    )
    async with ops_client:
        run = await run_it_ops_agent(model=model, client=ops_client, task="x")
    assert not run.calls[0].is_error
    assert run.calls[0].result["status"] == "deleted"


# ------------------------------------------------------------------ Developer Agent


@pytest.fixture
def dev_client() -> Client:
    return Client(create_dev_server(generate_developer_tools()))


async def test_developer_agent_offers_its_seven_tools_but_not_secrets(
    dev_client: Client, ops_client: Client
) -> None:
    model = ScriptedModel([final("nothing")])
    async with dev_client, ops_client:
        await run_developer_agent(
            model=model, developer_tools_client=dev_client, operations_client=ops_client, task="x"
        )
    assert sorted(model.offered) == sorted(DEVELOPER_TOOLS)
    assert len(DEVELOPER_TOOLS) == 7
    assert "read_env_secrets" not in model.offered
    assert "restart_service" not in model.offered  # on the Operations server, not granted
    assert "Developer Agent" in model.systems[0]


async def test_developer_agent_calls_are_routed_to_the_right_server(
    dev_client: Client, ops_client: Client
) -> None:
    model = ScriptedModel(
        [
            calls(
                ("repo_get_build_status", {"repo": "billing-service", "branch": "main"}),
                ("get_service_status", {"service": "billing-api", "env": "dev"}),
            ),
            final("both ok"),
        ]
    )
    async with dev_client, ops_client:
        run = await run_developer_agent(
            model=model, developer_tools_client=dev_client, operations_client=ops_client, task="x"
        )
    assert not any(c.is_error for c in run.calls)
    assert run.calls[0].result["build_status"] == "passing"
    assert run.calls[1].result["name"] == "billing-api"


async def test_developer_agent_cannot_read_secrets_even_if_it_asks(
    dev_client: Client, ops_client: Client
) -> None:
    model = ScriptedModel([calls(("read_env_secrets", {"scope": "prod"})), final("ok")])
    async with dev_client, ops_client:
        run = await run_developer_agent(
            model=model, developer_tools_client=dev_client, operations_client=ops_client, task="x"
        )
    assert run.calls[0].is_error
    assert "not available" in run.calls[0].result["error"]


async def test_baseline_developer_agent_can_push_to_main_and_delete_a_release_branch(
    dev_client: Client, ops_client: Client
) -> None:
    """Unprotected baseline: protected branches are not protected without the gateway."""
    model = ScriptedModel(
        [
            calls(
                ("repo_push_commit", {"repo": "billing-service", "branch": "main"}),
                ("repo_delete_branch", {"repo": "billing-service", "branch": "release/1.0"}),
            ),
            final("done"),
        ]
    )
    async with dev_client, ops_client:
        run = await run_developer_agent(
            model=model, developer_tools_client=dev_client, operations_client=ops_client, task="x"
        )
    assert not any(c.is_error for c in run.calls)


async def test_the_loop_routes_a_tool_to_the_first_client_that_lists_it() -> None:
    """With two clients, each tool is served by the server that has it."""
    finance = Client(create_server(generate_company_data()))
    ops = Client(create_ops_server(generate_operations()))
    model = ScriptedModel(
        [
            calls(
                ("get_invoice", {"invoice_id": "INV-0001"}),
                ("get_service_status", {"service": "auth", "env": "prod"}),
            ),
            final("ok"),
        ]
    )
    async with finance, ops:
        run = await run_agent(
            model=model,
            system_prompt="s",
            clients=[finance, ops],
            allowed_tools={"get_invoice", "get_service_status"},
            task="x",
        )
    assert [c.is_error for c in run.calls] == [False, False]
