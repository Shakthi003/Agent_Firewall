"""Tests for the agent loop and the Finance Agent (agents/business), using a scripted fake model."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from mcp.client import Client

from agents.business.finance import FINANCE_TOOLS, run_finance_agent
from agents.business.runtime import AgentStepLimitError, run_agent
from core.llm import Message, ToolCall, ToolSpec
from core.seed_generator import PLANTED_LARGE_INVOICE_ID, generate_company_data
from mcp_servers.company_data.server import create_server


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
                client=client,
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
