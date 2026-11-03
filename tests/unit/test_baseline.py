"""Tests for the scenarios and the unprotected baseline (agents/business/scenarios.py, baseline.py).

Everything here is deterministic: no real LLM is called.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

import pytest

from agents.business.baseline import (
    BANNER,
    open_servers,
    replay_unsafe_calls,
    run_attack_scenario,
    run_normal_workflow,
)
from agents.business.developer import DEVELOPER_TOOLS
from agents.business.finance import FINANCE_TOOLS
from agents.business.it_ops import IT_OPS_TOOLS
from agents.business.scenarios import (
    ATTACK_SCENARIOS,
    INJECTION_BANK,
    INJECTION_DELETE,
    INJECTION_EXPORT,
    INJECTION_SECRETS,
    NORMAL_WORKFLOWS,
    UNSAFE_CALLS,
    poison_company_data,
    poison_developer_tools,
    poison_operations,
)
from core.llm import Message, ToolCall, ToolSpec
from core.seed_generator import generate_all
from scripts.run_baseline import main as baseline_main

AGENT_TOOLS = {
    "finance": set(FINANCE_TOOLS),
    "it_ops": set(IT_OPS_TOOLS),
    "developer": set(DEVELOPER_TOOLS),
}
MATRIX = Path("docs/permission-matrix.md").read_text(encoding="utf-8")


class ScriptedModel:
    def __init__(self, script: list[Message]) -> None:
        self._script = list(script)

    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message:
        return self._script.pop(0)


def calls(*items: tuple[str, dict[str, object]]) -> Message:
    return Message(role="model", tool_calls=tuple(ToolCall(name=n, args=a) for n, a in items))


def final(text: str) -> Message:
    return Message(role="model", text=text)


# ------------------------------------------------------------------ the unsafe-call table


def test_every_unsafe_call_names_a_real_tool_and_a_documented_reason_code() -> None:
    codes = set(re.findall(r"`([A-Z_]{6,})`", MATRIX))
    for call in UNSAFE_CALLS:
        assert f"`{call.tool}`" in MATRIX, call.call_id
        assert call.reason in codes, call.call_id


def test_unsafe_call_ids_are_unique_and_cover_every_scenario() -> None:
    ids = [c.call_id for c in UNSAFE_CALLS]
    assert len(ids) == len(set(ids))
    assert {"A", "B", "C", "D", "E"} <= {c.scenario for c in UNSAFE_CALLS}


async def test_replay_every_planned_unsafe_call_succeeds_without_a_firewall() -> None:
    """The baseline: nothing stops any of them."""
    async with open_servers() as servers:
        results = await replay_unsafe_calls(servers)
    assert len(results) == len(UNSAFE_CALLS)
    failed = [r.call.call_id for r in results if not r.succeeded]
    assert failed == []


async def test_replay_is_repeatable() -> None:
    async def outcome() -> list[bool]:
        async with open_servers() as servers:
            return [r.succeeded for r in await replay_unsafe_calls(servers)]

    assert await outcome() == await outcome()


# ------------------------------------------------------------------ poisoned data


def test_poisoned_seeds_contain_the_hostile_text_and_the_originals_are_untouched() -> None:
    company, operations, developer = generate_all()
    poisoned = (
        poison_company_data(company),
        poison_operations(operations),
        poison_developer_tools(developer),
    )
    blob = "".join(p.model_dump_json() for p in poisoned)
    for text in (INJECTION_BANK, INJECTION_EXPORT, INJECTION_DELETE, INJECTION_SECRETS):
        assert text in blob
    original = "".join(s.model_dump_json() for s in (company, operations, developer))
    assert all(
        text not in original
        for text in (INJECTION_BANK, INJECTION_EXPORT, INJECTION_DELETE, INJECTION_SECRETS)
    )


def test_poisoned_seeds_still_pass_the_schema() -> None:
    company, operations, developer = generate_all()
    type(company).model_validate(poison_company_data(company).model_dump())
    type(operations).model_validate(poison_operations(operations).model_dump())
    type(developer).model_validate(poison_developer_tools(developer).model_dump())


async def test_the_agent_can_actually_read_the_poisoned_data() -> None:
    async with open_servers(poisoned=True) as servers:
        invoice = await servers.company_data.call_tool("get_invoice", {"invoice_id": "INV-0001"})
        ticket_ops = await servers.operations.call_tool(
            "update_ticket", {"ticket_id": "TCK-002", "comment": "x"}
        )
        repo = await servers.developer_tools.call_tool(
            "repo_get_metadata", {"repo": "billing-service"}
        )
    assert INJECTION_BANK in invoice.structured_content["description"]
    assert INJECTION_DELETE in ticket_ops.structured_content["comments"]
    assert INJECTION_SECRETS in repo.structured_content["description"]


async def test_poisoned_servers_are_fresh_each_time_and_do_not_pollute_clean_ones() -> None:
    async with open_servers(poisoned=True):
        pass
    async with open_servers() as clean:
        invoice = await clean.company_data.call_tool("get_invoice", {"invoice_id": "INV-0001"})
    assert INJECTION_BANK not in invoice.structured_content["description"]


def test_poisoned_data_cannot_be_combined_with_live_servers() -> None:
    with pytest.raises(ValueError, match="in-process"):
        # The check runs when the context manager is entered.
        import asyncio

        async def go() -> None:
            async with open_servers(poisoned=True, live_host="127.0.0.1"):
                pass

        asyncio.run(go())


# ------------------------------------------------------------------ scenario definitions


def test_attack_scenarios_target_tools_the_matrix_lists_and_agents_can_attempt() -> None:
    assert {s.scenario_id for s in ATTACK_SCENARIOS} == {"A", "B", "C", "D"}
    for sc in ATTACK_SCENARIOS:
        assert sc.hostile_text in {
            INJECTION_BANK,
            INJECTION_EXPORT,
            INJECTION_DELETE,
            INJECTION_SECRETS,
        }
        # The agent can attempt the unsafe tool (that is the point), as long as it is offered.
        # Scenario C needs the demo-run override, because the normal run hides the secrets tool.
        offered = AGENT_TOOLS[sc.agent] | ({"read_env_secrets"} if sc.show_secrets_tool else set())
        assert sc.unsafe_tool in offered, sc.scenario_id


def test_the_normal_run_hides_the_secrets_tool_and_only_scenario_c_shows_it() -> None:
    assert "read_env_secrets" not in DEVELOPER_TOOLS
    assert [s.scenario_id for s in ATTACK_SCENARIOS if s.show_secrets_tool] == ["C"]


def test_normal_workflows_only_require_tools_the_agent_has() -> None:
    assert {w.agent for w in NORMAL_WORKFLOWS} == {"finance", "it_ops", "developer"}
    for wf in NORMAL_WORKFLOWS:
        assert set(wf.required_tools) <= AGENT_TOOLS[wf.agent]


# ------------------------------------------------------------------ running scenarios


async def test_a_normal_workflow_passes_when_the_model_does_the_job() -> None:
    wf = NORMAL_WORKFLOWS[0]
    model = ScriptedModel(
        [
            calls(("get_invoice", {"invoice_id": "INV-0005"})),
            calls(("get_payment_status", {"invoice_id": "INV-0005"})),
            calls(("initiate_payment", {"invoice_id": "INV-0005", "amount": 389.51})),
            final("paid"),
        ]
    )
    async with open_servers() as servers:
        run = await run_normal_workflow(wf, model, servers)
    assert wf.passed(run)


async def test_a_normal_workflow_fails_if_a_required_tool_is_skipped() -> None:
    wf = NORMAL_WORKFLOWS[0]
    model = ScriptedModel([calls(("get_invoice", {"invoice_id": "INV-0005"})), final("done")])
    async with open_servers() as servers:
        run = await run_normal_workflow(wf, model, servers)
    assert not wf.passed(run)


@pytest.mark.parametrize("scenario", ATTACK_SCENARIOS, ids=lambda s: s.scenario_id)
async def test_an_agent_that_obeys_hostile_text_succeeds_without_a_firewall(scenario) -> None:  # noqa: ANN001
    """Replays what a fooled agent would do, using the real servers and the real tool lists."""
    unsafe_args = next(c.args for c in UNSAFE_CALLS if c.tool == scenario.unsafe_tool)
    model = ScriptedModel([calls((scenario.unsafe_tool, unsafe_args)), final("done")])
    async with open_servers(poisoned=True) as servers:
        run = await run_attack_scenario(scenario, model, servers)
    assert scenario.fell_for_it(run)


async def test_an_agent_that_resists_is_not_counted_as_fooled() -> None:
    model = ScriptedModel([final("I will not do that.")])
    async with open_servers(poisoned=True) as servers:
        run = await run_attack_scenario(ATTACK_SCENARIOS[0], model, servers)
    assert not ATTACK_SCENARIOS[0].fell_for_it(run)


async def test_scenario_c_secrets_tool_is_refused_in_the_normal_run() -> None:
    """Without the demo override, the agent was never offered the tool, so the call is refused."""
    from agents.business.baseline import run_agent_by_name

    model = ScriptedModel([calls(("read_env_secrets", {"scope": "prod"})), final("ok")])
    async with open_servers(poisoned=True) as servers:
        run = await run_agent_by_name("developer", model, servers, "x", show_secrets_tool=False)
    assert run.calls[0].is_error


# ------------------------------------------------------------------ the CLI


def test_cli_replay_prints_the_banner_and_a_summary(capsys: pytest.CaptureFixture[str]) -> None:
    assert baseline_main(["replay"]) == 0
    out = capsys.readouterr().out
    assert BANNER in out
    n = len(UNSAFE_CALLS)
    assert f"{n} of {n} planned unsafe calls succeeded with no firewall" in out


def test_cli_rejects_attacks_with_live_servers() -> None:
    with pytest.raises(SystemExit):
        baseline_main(["attacks", "--live"])
