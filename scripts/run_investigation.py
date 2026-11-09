"""Run the security investigation workflow (Stage 6).

    uv run python -m scripts.run_investigation samples [--offline]  reports for Scenarios A-D
    uv run python -m scripts.run_investigation audit [--agent ID]   investigate the audit store

`samples` replays each scenario's planned unsafe calls (agents/business/scenarios.py) through
the real in-process gateway with the real policy, then investigates the audit trail they left.
It needs no business-agent LLM, so the evidence is deterministic. The investigation uses Gemini
unless `--offline` is given, which forces the deterministic fallback (no network, no key).
Reports are written to docs/incident-reports/. The workflow is advisory: it only reads.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

from agents.business.scenarios import UNSAFE_CALLS
from core.config import get_settings
from core.db import make_engine
from core.llm import ChatModel, GeminiModel, Message, ModelError, ToolSpec
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore
from tests.gateway_harness import running_gateway
from tests.security.test_policy_enforcement import demo_run_registry
from workflows.investigation.evidence import AuditEvidence
from workflows.investigation.graph import InvestigationWorkflow

OUT_DIR = Path("docs") / "incident-reports"
# One ordinary, allowed read per agent, so each trail starts with normal behaviour.
NORMAL_CALL = {
    "finance": ("get_invoice", {"invoice_id": "INV-0005"}),
    "it_ops": ("get_service_status", {"service": "billing-api", "env": "dev"}),
    "developer": ("repo_get_metadata", {"repo": "web-portal"}),
}
AGENT_NAME = {"finance": "finance-agent", "it_ops": "it-ops-agent", "developer": "developer-agent"}
SCENARIOS = ("A", "B", "C", "D")


class OfflineModel:
    """Always fails, so the workflow uses its deterministic fallback."""

    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message:
        raise ModelError("offline mode: no LLM was called")


async def sample(scenario: str, model: ChatModel) -> str:
    calls = [c for c in UNSAFE_CALLS if c.scenario == scenario]
    agent = calls[0].agent
    tools = demo_run_registry() if any(c.tool == "read_env_secrets" for c in calls) else None
    async with running_gateway(rules=True, tools=tools) as gw:
        assert gw.audit_store is not None
        async with gw.client(gw.keys[agent].key) as client:
            await client.call_tool(*NORMAL_CALL[agent])
            for call in calls:
                await client.call_tool(call.tool, dict(call.args))
        workflow = InvestigationWorkflow(AuditEvidence(gw.audit_store, gw.alerts), model)
        report = await workflow.run(agent_id=AGENT_NAME[agent])
    return report.to_markdown()


async def samples(offline: bool) -> int:
    model: ChatModel = OfflineModel() if offline else GeminiModel.from_settings()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for scenario in SCENARIOS:
        text = await sample(scenario, model)
        path = OUT_DIR / f"scenario-{scenario}.md"
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


async def audit(agent: str | None, database_url: str | None, offline: bool) -> int:
    engine = make_engine(database_url or get_settings().database_url)
    model: ChatModel = OfflineModel() if offline else GeminiModel.from_settings()
    evidence = AuditEvidence(AuditStore(engine), AlertStore(engine))
    report = await InvestigationWorkflow(evidence, model).run(agent_id=agent)
    print(report.to_markdown())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["samples", "audit"])
    parser.add_argument("--agent", default=None, help="agent ID to investigate (audit mode)")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--offline", action="store_true", help="skip the LLM; use the fallback")
    args = parser.parse_args(argv)
    if args.mode == "samples":
        return asyncio.run(samples(args.offline))
    return asyncio.run(audit(args.agent, args.database_url, args.offline))


if __name__ == "__main__":
    sys.exit(main())
