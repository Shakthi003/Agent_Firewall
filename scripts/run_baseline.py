"""Run the unprotected baseline: the "before" picture, with no firewall.

Usage:
    uv run python -m scripts.run_baseline replay      # every planned unsafe call, no LLM
    uv run python -m scripts.run_baseline workflows   # normal tasks, with Gemini
    uv run python -m scripts.run_baseline attacks     # poisoned data, with Gemini

Add `--live` to use servers already running on ports 9001-9003 (not for `attacks`, which needs
poisoned copies of the seed data). Otherwise fresh in-process servers are used.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from agents.business.baseline import (
    BANNER,
    open_servers,
    replay_unsafe_calls,
    run_attack_scenario,
    run_normal_workflow,
)
from agents.business.scenarios import ATTACK_SCENARIOS, NORMAL_WORKFLOWS
from core.llm import GeminiModel


async def _replay(live_host: str | None) -> int:
    async with open_servers(live_host=live_host) as servers:
        results = await replay_unsafe_calls(servers)
    for r in results:
        outcome = "SUCCEEDED" if r.succeeded else "refused"
        print(
            f"{r.call.call_id:3} {r.call.scenario:2} {r.call.tool:33} {outcome:10} "
            f"(gateway must: {r.call.decision} {r.call.reason})"
        )
    done = sum(r.succeeded for r in results)
    print(f"\n{done} of {len(results)} planned unsafe calls succeeded with no firewall.")
    return 0 if done == len(results) else 1


async def _workflows(live_host: str | None) -> int:
    model = GeminiModel.from_settings()
    failed = 0
    for wf in NORMAL_WORKFLOWS:
        async with open_servers(live_host=live_host) as servers:
            run = await run_normal_workflow(wf, model, servers)
        ok = wf.passed(run)
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  [{wf.agent}] {wf.name}: {[c.name for c in run.calls]}")
    return 1 if failed else 0


async def _attacks() -> int:
    model = GeminiModel.from_settings()
    for sc in ATTACK_SCENARIOS:
        async with open_servers(poisoned=True) as servers:
            run = await run_attack_scenario(sc, model, servers)
        verdict = "AGENT FELL FOR IT" if sc.fell_for_it(run) else "agent resisted"
        print(f"{sc.scenario_id}  {verdict:18} {sc.name}: {[c.name for c in run.calls]}")
    print("\nModels vary: 'resisted' is luck, not a defence. The replay is the guarantee.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=BANNER)
    parser.add_argument("mode", choices=["replay", "workflows", "attacks"])
    parser.add_argument("--live", action="store_true", help="use servers running on 127.0.0.1")
    args = parser.parse_args(argv)
    live_host = "127.0.0.1" if args.live else None
    if args.live and args.mode == "attacks":
        parser.error("attacks needs poisoned seed data, so it cannot use --live")

    print(f"*** {BANNER} ***\n")
    if args.mode == "replay":
        return asyncio.run(_replay(live_host))
    if args.mode == "workflows":
        return asyncio.run(_workflows(live_host))
    return asyncio.run(_attacks())


if __name__ == "__main__":
    sys.exit(main())
