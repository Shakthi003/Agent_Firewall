"""Stage 8 evaluation: the same scenario suite with and without the firewall, plus the metrics.

    uv run python -m scripts.run_evaluation                          # print the report
    uv run python -m scripts.run_evaluation --write docs/evaluation-report.md

Everything runs in-process on the real gateway, the real policy file, the real approval store and
the real hash-chained audit store (SQLite), with the three mock MCP servers behind it. No model is
used, so the run is repeatable. Sample sizes are printed next to every number.

Read the numbers with these limits in mind (they are repeated in the report):
- Latency is measured in-process, without network hops or PostgreSQL.
- The anomaly figures come from simulated traffic that this project also wrote, scored on a seed
  that was never used for tuning.
"""

from __future__ import annotations

import argparse
import asyncio
import platform
import statistics
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_types import CallToolResult

from agents.business.baseline import open_servers, replay_unsafe_calls
from agents.business.gateway_client import APPROVAL_META_KEY
from agents.business.scenarios import UNSAFE_CALLS
from monitoring.detection.evaluate import evaluate
from tests.gateway_harness import GatewayHarness, running_gateway
from tests.security.test_policy_enforcement import demo_run_registry
from tests.unit.test_policy_engine import MATRIX

FRESH_SEED = 4004  # never looked at while tuning (tuning used 2002 and 3003)
LATENCY_ROUNDS = 20  # times 12 unsafe calls
APPROVAL_ROUNDS = 20
BANK_TOOL = "update_beneficiary_bank_details"


def correlation_of(result: CallToolResult) -> str | None:
    data = result.structured_content
    if result.is_error and isinstance(data, dict):
        value = data.get("correlation_id")
    else:
        value = (result.meta or {}).get("correlation_id")
    return value if isinstance(value, str) else None


class Probe:
    """Makes calls through the gateway, remembering every correlation ID it was given."""

    def __init__(self, gw: GatewayHarness) -> None:
        self.gw = gw
        self.ids: list[str | None] = []

    async def call(
        self, agent: str, tool: str, args: dict[str, Any], *, approval: str | None = None
    ) -> CallToolResult:
        meta = {APPROVAL_META_KEY: approval} if approval else None
        async with self.gw.client(self.gw.keys[agent].key) as client:
            result = await client.call_tool(tool, args, meta=meta)  # type: ignore[arg-type]
        self.ids.append(correlation_of(result))
        return result

    def reached(self) -> int:
        """How many calls have been forwarded to a downstream server so far."""
        return len(self.gw.downstream.calls)

    def decisions(self) -> list[Any]:
        return [e for e in self.gw.audit.events if e.method == "tools/call"]


# ------------------------------------------------------------------ AC-49: the scenario suite


async def run_baseline() -> dict[str, Any]:
    async with open_servers() as servers:
        results = await replay_unsafe_calls(servers)
    return {"total": len(results), "succeeded": sum(r.succeeded for r in results)}


async def run_protected(p: Probe) -> dict[str, Any]:
    rows = []
    for call in UNSAFE_CALLS:
        before = p.reached()
        result = await p.call(call.agent, call.tool, dict(call.args))
        data = result.structured_content or {}
        rows.append(
            {
                "id": call.call_id,
                "expected": (call.decision, call.reason),
                "got": (str(data.get("decision", "ALLOW")), str(data.get("reason_code", ""))),
                "reached": p.reached() > before,
            }
        )
    return {
        "rows": rows,
        "total": len(rows),
        "stopped": sum(not r["reached"] for r in rows),
        "blocked": sum(r["got"][0] == "BLOCK" for r in rows),
        "paused": sum(r["got"][0] == "REQUIRE_APPROVAL" for r in rows),
        "as_expected": sum(r["got"] == r["expected"] for r in rows),
    }


# ------------------------------------------------------------------ AC-50: the metrics


async def run_false_positives(p: Probe) -> dict[str, Any]:
    """Legitimate calls (every ALLOW row of the policy matrix) must be let through."""
    registry = demo_run_registry()
    legit = [
        (role, tool, args)
        for role, tool, args, decision, _ in MATRIX
        if decision == "ALLOW" and registry.is_granted(tool, role)
    ]
    wrongly_denied = []
    for role, tool, args in legit:
        await p.call(role, tool, args)
        event = p.decisions()[-1]
        if event.decision != "ALLOW":
            wrongly_denied.append(f"{role}/{tool}: {event.reason_code}")
    return {"total": len(legit), "false_positives": len(wrongly_denied), "which": wrongly_denied}


async def run_latency(p: Probe) -> dict[str, Any]:
    """Gateway decision time (`latency_ms` in the audit event) for calls that are stopped."""
    start = len(p.decisions())
    for _ in range(LATENCY_ROUNDS):
        for call in UNSAFE_CALLS:
            await p.call(call.agent, call.tool, dict(call.args))
    samples = sorted(e.latency_ms for e in p.decisions()[start:])
    return {
        "n": len(samples),
        "p50": statistics.median(samples),
        "p95": samples[int(0.95 * (len(samples) - 1))],
        "max": samples[-1],
    }


async def run_approval_integrity(p: Probe) -> dict[str, Any]:
    """An approved request runs once, exactly as stored; nothing else ever runs."""
    api = p.gw.approver_api()
    checks = violations = 0

    def check(ok: bool) -> None:
        nonlocal checks, violations
        checks += 1
        violations += not ok

    for n in range(APPROVAL_ROUNDS):
        args = {"beneficiary_id": "BEN-001", "account_number": f"1000{n:04d}"}
        first = await p.call("finance", BANK_TOOL, args)
        approval_id = (first.structured_content or {})["approval_id"]
        before = p.reached()
        await p.call("finance", BANK_TOOL, args, approval=approval_id)  # not decided yet
        check(p.reached() == before)
        check(api.post(f"/approvals/{approval_id}/approve").status_code == 200)
        changed = {**args, "account_number": f"9999{n:04d}"}
        await p.call("finance", BANK_TOOL, changed, approval=approval_id)  # changed arguments
        check(p.reached() == before)
        await p.call("finance", BANK_TOOL, args, approval=approval_id)  # the genuine retry
        check(p.reached() == before + 1 and p.gw.downstream.calls[-1].args == args)
        await p.call("finance", BANK_TOOL, args, approval=approval_id)  # replay
        check(p.reached() == before + 1)

        other = {"beneficiary_id": "BEN-001", "account_number": f"2000{n:04d}"}
        asked = await p.call("finance", BANK_TOOL, other)
        rejected_id = (asked.structured_content or {})["approval_id"]
        check(api.post(f"/approvals/{rejected_id}/reject").status_code == 200)
        await p.call("finance", BANK_TOOL, other, approval=rejected_id)  # rejected
        check(p.reached() == before + 1)
    return {"rounds": APPROVAL_ROUNDS, "checks": checks, "violations": violations}


def run_audit_completeness(p: Probe) -> dict[str, Any]:
    store = p.gw.audit_store
    assert store is not None
    asked = len(p.ids)
    found = sum(1 for i in p.ids if i and store.get_by_correlation(i))
    rows = sum(1 for s in store.events() if s.event.method == "tools/call")
    verdict = store.verify()
    return {
        "requests": asked,
        "recorded": found,
        "call_rows": rows,
        "chain_ok": verdict.ok,
        "chain_checked": verdict.checked,
    }


# ------------------------------------------------------------------ anomaly detection (fresh seed)


def run_anomaly() -> dict[str, Any]:
    """Re-test the rules and the model on a seed that was never used while tuning."""
    report = evaluate(test_seed=FRESH_SEED)
    return {
        "seed": report.seed_test,
        "normal_episodes": report.normal_episodes,
        "attack_episodes": report.attack_episodes,
        "normal_windows": report.normal_windows,
        "attack_windows": report.attack_windows,
        "text": report.as_text(),
        "rules": report.rules,
        "model": report.model,
        "combined": report.combined,
    }


# ------------------------------------------------------------------ the run


async def run_all() -> dict[str, Any]:
    out: dict[str, Any] = {"baseline": await run_baseline()}
    async with running_gateway(rules=True, tools=demo_run_registry()) as gw:
        p = Probe(gw)
        out["protected"] = await run_protected(p)
        out["false_positives"] = await run_false_positives(p)
        out["latency"] = await run_latency(p)
        out["approvals"] = await run_approval_integrity(p)
        out["audit"] = run_audit_completeness(p)
    out["anomaly"] = run_anomaly()
    return out


def _git_commit() -> str:
    try:
        done = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _pct(part: int, whole: int) -> str:
    return f"{part}/{whole} ({100 * part / whole:.1f}%)" if whole else "0/0"


def render(r: dict[str, Any]) -> str:
    b, p, fp, lat = r["baseline"], r["protected"], r["false_positives"], r["latency"]
    ap, au, an = r["approvals"], r["audit"], r["anomaly"]
    lines = [
        "# Evaluation report (Stage 8)",
        "",
        f"Recorded {datetime.now(UTC):%Y-%m-%d %H:%M} UTC, commit `{_git_commit()}`, "
        f"Python {platform.python_version()} on {platform.system()}. "
        "Reproduce with "
        "`uv run python -m scripts.run_evaluation --write docs/evaluation-report.md`.",
        "",
        "Everything ran in one process: the real gateway, policy file, approval store and "
        "hash-chained audit store (SQLite), with the three mock MCP servers behind it. "
        "No language model was used, so the run is repeatable. Sample sizes are in every row.",
        "",
        "## 1. Same scenario suite, with and without the firewall (AC-49)",
        "",
        f"The {b['total']} planned unsafe calls from scenarios A to E and the protected-branch "
        "cases, sent to the same mock servers.",
        "",
        "| | Unsafe calls that ran | Stopped before running |",
        "| -- | -- | -- |",
        f"| Unprotected baseline (no gateway) | {_pct(b['succeeded'], b['total'])} | "
        f"{b['total'] - b['succeeded']}/{b['total']} |",
        f"| Protected (through the gateway) | {_pct(p['total'] - p['stopped'], p['total'])} | "
        f"{_pct(p['stopped'], p['total'])} |",
        "",
        f"Of the {p['total']} protected calls, {p['blocked']} were blocked outright and "
        f"{p['paused']} were paused for a human. {p['as_expected']}/{p['total']} returned exactly "
        "the decision and reason code written down in advance in `agents/business/scenarios.py`.",
        "",
        "| Call | Expected | Got | Reached a server |",
        "| -- | -- | -- | -- |",
    ]
    for row in p["rows"]:
        lines.append(
            f"| {row['id']} | {' '.join(row['expected'])} | {' '.join(row['got'])} | "
            f"{'yes' if row['reached'] else 'no'} |"
        )
    lines += [
        "",
        "## 2. Metrics (AC-50)",
        "",
        "| Metric | Result | Sample |",
        "| -- | -- | -- |",
        f"| Blocking rate (unsafe calls stopped) | {_pct(p['stopped'], p['total'])} | "
        f"{p['total']} unsafe calls |",
        f"| False positives (legitimate calls wrongly denied) | "
        f"{_pct(fp['false_positives'], fp['total'])} | {fp['total']} legitimate calls |",
        f"| Authorization latency, median / 95th percentile / max | "
        f"{lat['p50']:.2f} / {lat['p95']:.2f} / {lat['max']:.2f} ms | {lat['n']} decisions |",
        f"| Audit completeness (requests with a stored record) | "
        f"{_pct(au['recorded'], au['requests'])} | {au['requests']} requests |",
        f"| Audit chain verifies | {'yes' if au['chain_ok'] else 'NO'} | "
        f"{au['chain_checked']} records |",
        f"| Approval integrity (violations) | {ap['violations']} | {ap['checks']} checks over "
        f"{ap['rounds']} approvals |",
        f"| Anomaly rules: precision / recall / false-positive rate | "
        f"{an['rules'].precision:.3f} / {an['rules'].recall:.3f} / "
        f"{an['rules'].false_positive_rate:.3f} | {an['normal_windows']} normal + "
        f"{an['attack_windows']} attack windows |",
        f"| Anomaly model: precision / recall / false-positive rate | "
        f"{an['model'].precision:.3f} / {an['model'].recall:.3f} / "
        f"{an['model'].false_positive_rate:.3f} | same windows |",
        f"| Rules + model: precision / recall / false-positive rate | "
        f"{an['combined'].precision:.3f} / {an['combined'].recall:.3f} / "
        f"{an['combined'].false_positive_rate:.3f} | same windows |",
        "",
        "Approval integrity counts, for each approval: a retry before the decision does not run; "
        "a retry with changed arguments does not run; the genuine retry runs once with exactly "
        "the stored arguments; a replay does not run; a rejected approval does not run.",
        "",
        "### Anomaly detail",
        "",
        f"Scored on seed {an['seed']} ({an['normal_episodes']} normal and "
        f"{an['attack_episodes']} attack episodes). The earlier tuning used seeds 2002 and 3003, "
        "so this seed was never looked at.",
        "",
        "```text",
        an["text"],
        "```",
        "",
        "## 3. Read these numbers with care",
        "",
        "- **The unsafe calls are the ones the policy was written for.** A 100% blocking rate on "
        "them shows the rules do what they say. It does not estimate how many unknown attacks "
        "would be stopped.",
        f"- **The {fp['total']} legitimate calls come from the policy test matrix**, which the "
        "policy was also written against. A zero false-positive rate here is a floor, not a "
        "measure of real traffic.",
        "- **Latency is in-process.** There is no network hop and no PostgreSQL. It is the cost "
        "of the checks and of writing the audit record to SQLite, not an end-to-end figure. It "
        "covers stopped calls only; a forwarded call also waits for the downstream server.",
        "- **Anomaly traffic is simulated by this project.** The numbers show that the pipeline "
        "works and where it is blind (see the per-kind table, including the slow scrape). They "
        "make no claim about real-world accuracy.",
        "- **The baseline is the replay.** It shows what the mock servers do when asked directly. "
        "It says nothing about whether a real model would have made those calls.",
    ]
    if fp["which"]:
        lines += ["", "Wrongly denied: " + "; ".join(fp["which"])]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Stage 8 evaluation.")
    parser.add_argument("--write", metavar="FILE", help="also write the report to this file")
    args = parser.parse_args(argv)

    results = asyncio.run(run_all())
    report = render(results)
    print(report)
    if args.write:
        Path(args.write).write_text(report, encoding="utf-8")
        print(f"report written to {args.write}")
    p, ap, au = results["protected"], results["approvals"], results["audit"]
    healthy = (
        p["stopped"] == p["total"]
        and p["as_expected"] == p["total"]
        and ap["violations"] == 0
        and au["recorded"] == au["requests"]
        and au["chain_ok"]
    )
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
