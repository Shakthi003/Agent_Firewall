"""Attack simulation for the dashboard (Stage 7, AC-47).

Runs one of the documented attack scenarios (A-D) through a REAL gateway with the REAL policy,
but in a throw-away in-memory sandbox: its own database, audit chain and alerts. Nothing it does
touches the live audit log, the approval store or any agent key. The investigation workflow then
reads the sandbox trail, so a reviewer sees decision, evidence and investigation in one place.

The sandbox reuses the test harness (`tests.gateway_harness`), the same way
`scripts/run_investigation.py samples` does. That package is not part of the Docker image, so
`SimulationUnavailable` is raised there and the API answers 503 instead of crashing.
"""

import time
from collections.abc import Sequence
from dataclasses import asdict
from typing import Any

from agents.business.scenarios import ATTACK_SCENARIOS, UNSAFE_CALLS
from core.llm import ChatModel, GeminiModel, Message, ModelError, ToolSpec
from monitoring.audit.store import StoredEvent
from workflows.investigation.evidence import AuditEvidence
from workflows.investigation.graph import InvestigationWorkflow

SCENARIO_IDS = tuple(s.scenario_id for s in ATTACK_SCENARIOS)


class SimulationUnavailable(RuntimeError):
    """The sandbox cannot be built in this deployment."""


class OfflineModel:
    """Always fails, so the investigation uses its deterministic fallback (no network, no key)."""

    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message:
        raise ModelError("offline mode: no LLM was called")


def default_model_factory(use_llm: bool) -> ChatModel:
    if not use_llm:
        return OfflineModel()
    try:
        return GeminiModel.from_settings()
    except RuntimeError:  # no GEMINI_API_KEY: say so plainly instead of a stack trace
        raise SimulationUnavailable("GEMINI_API_KEY is not set; use offline mode") from None


def scenario_catalog() -> list[dict[str, Any]]:
    return [
        {
            "id": s.scenario_id,
            "name": s.name,
            "agent": s.agent,
            "task": s.task,
            "hostile_text": s.hostile_text,
            "unsafe_tool": s.unsafe_tool,
            "planned_calls": [
                {"call_id": c.call_id, "tool": c.tool, "args": dict(c.args)}
                for c in UNSAFE_CALLS
                if c.scenario == s.scenario_id
            ],
        }
        for s in ATTACK_SCENARIOS
    ]


def event_view(stored: StoredEvent) -> dict[str, Any]:
    """One audit event as JSON: the event itself plus its place in the hash chain."""
    view = asdict(stored.event)
    view["seq"] = stored.seq
    view["prev_hash"] = stored.prev_hash
    view["record_hash"] = stored.record_hash
    return view


async def run_scenario(scenario_id: str, model: ChatModel) -> dict[str, Any]:
    try:
        from scripts.run_investigation import AGENT_NAME, NORMAL_CALL
        from tests.gateway_harness import running_gateway
        from tests.security.test_policy_enforcement import demo_run_registry
    except ImportError as err:  # the image ships without tests/
        raise SimulationUnavailable("the simulation sandbox is not part of this build") from err

    calls = [c for c in UNSAFE_CALLS if c.scenario == scenario_id]
    if not calls:
        raise KeyError(scenario_id)
    agent = calls[0].agent
    tools = demo_run_registry() if any(c.tool == "read_env_secrets" for c in calls) else None
    planned = [("NORMAL", *NORMAL_CALL[agent], None, None)] + [
        (c.call_id, c.tool, dict(c.args), c.decision, c.reason) for c in calls
    ]
    started = time.perf_counter()
    async with running_gateway(rules=True, tools=tools) as gw:
        assert gw.audit_store is not None and gw.alerts is not None
        async with gw.client(gw.keys[agent].key) as client:
            for _, tool, args, _, _ in planned:
                await client.call_tool(tool, args)
        stored = gw.audit_store.events()
        verify = gw.audit_store.verify()
        alerts = gw.alerts.list_recent()
        workflow = InvestigationWorkflow(AuditEvidence(gw.audit_store, gw.alerts), model)
        report = await workflow.run(agent_id=AGENT_NAME[agent])

    # Match each planned call to the tools/call event it produced (same tool, in order).
    decided = [s for s in stored if s.event.method == "tools/call"]
    cursor = 0
    results: list[dict[str, Any]] = []
    for call_id, tool, args, expected, expected_reason in planned:
        match = next((s for s in decided[cursor:] if s.event.tool == tool), None)
        if match is not None:
            cursor = decided.index(match) + 1
        results.append(
            {
                "call_id": call_id,
                "tool": tool,
                "args": args,
                "expected_decision": expected,
                "expected_reason": expected_reason,
                "decision": match.event.decision if match else None,
                "reason_code": match.event.reason_code if match else None,
                "enforcement_action": match.event.enforcement_action if match else None,
                "seq": match.seq if match else None,
            }
        )
    scenario = next(s for s in ATTACK_SCENARIOS if s.scenario_id == scenario_id)
    return {
        "scenario": {"id": scenario.scenario_id, "name": scenario.name, "agent": scenario.agent},
        "sandbox": True,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "calls": results,
        "events": [event_view(s) for s in stored],
        "chain": {"ok": verify.ok, "checked": verify.checked, "reason": verify.reason},
        "alerts": alerts,
        "report": report.model_dump(),
        "markdown": report.to_markdown(),
    }
