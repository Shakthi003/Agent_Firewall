"""Stage 8 robustness tests (AC-51): concurrency, timeout, downstream error, retry, duplicates.

Test matrix (what each group proves, and where the older tests cover the rest):

| Case               | Proved here                                                              |
| ------------------ | ------------------------------------------------------------------------ |
| concurrency        | parallel denied calls never reach a server; parallel allowed calls each  |
|                    | get one audit record; an approval spent in parallel runs once; the rate  |
|                    | limiter hands out exactly its burst to competing threads                 |
| timeout            | a timed-out approved call is spent (no second run) and the gateway keeps |
|                    | serving. Plain timeout: tests/integration/test_gateway.py                |
| downstream error   | a crashed approved call is spent (no second run). Plain crash:           |
|                    | tests/integration/test_gateway.py                                        |
| retry              | a retry after a transient failure is a new, audited call; the agent      |
|                    | helper waits for approval and runs the request once                      |
| duplicate requests | the same allowed call twice is two audited calls; the same paused call   |
|                    | twice is one approval; paying an invoice twice is refused by the server  |
|                    | (approval replay: tests/security/test_approval.py)                       |
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

from mcp_types import CallToolResult

from agents.business.gateway_client import APPROVAL_META_KEY, call_tool_with_approval
from gateway.policy.rate_limit import TokenBucketRateLimiter
from tests.gateway_harness import GatewayHarness, running_gateway
from tests.security.test_policy_enforcement import demo_run_registry
from tests.unit.test_policy_engine import MATRIX

BANK_TOOL = "update_beneficiary_bank_details"
BANK_ARGS = {"beneficiary_id": "BEN-001", "account_number": "99887766"}
PARALLEL = 24


def on_disk(tmp_path: Path) -> str:
    """A database file, so parallel calls get a connection each (as they would on PostgreSQL)."""
    return f"sqlite:///{(tmp_path / 'gateway.db').as_posix()}"


def body(result: CallToolResult) -> dict[str, Any]:
    assert result.structured_content is not None
    return dict(result.structured_content)


def call_events(gw: GatewayHarness) -> list[Any]:
    return [e for e in gw.audit.events if e.method == "tools/call"]


async def one_call(
    gw: GatewayHarness, agent: str, tool: str, args: dict[str, Any], approval: str | None = None
) -> CallToolResult:
    """A call on its own connection, so many of these really run side by side."""
    meta = {APPROVAL_META_KEY: approval} if approval else None
    async with gw.client(gw.keys[agent].key) as client:
        return await client.call_tool(tool, args, meta=meta)  # type: ignore[arg-type]


async def approved_bank_change(gw: GatewayHarness) -> str:
    """Ask for the bank-detail change and approve it. Returns the approval id."""
    first = await one_call(gw, "finance", BANK_TOOL, BANK_ARGS)
    approval_id = str(body(first)["approval_id"])
    assert gw.approver_api().post(f"/approvals/{approval_id}/approve").status_code == 200
    return approval_id


# ------------------------------------------------------------------ concurrency


async def test_many_denied_calls_at_once_never_reach_a_server(tmp_path: Path) -> None:
    denied = [
        (agent, tool, args)
        for agent, tool, args, decision, _ in MATRIX
        if decision == "BLOCK" and tool != "read_env_secrets"
    ]
    async with running_gateway(
        rules=True, tools=demo_run_registry(), database_url=on_disk(tmp_path)
    ) as gw:
        results = await asyncio.gather(*(one_call(gw, *call) for call in denied))
        assert all(r.is_error for r in results)
        assert gw.downstream.calls == []
        events = call_events(gw)
        assert len(events) == len(denied)
        assert {e.decision for e in events} == {"BLOCK"}


async def test_parallel_allowed_calls_each_get_one_audit_record_and_one_answer(
    tmp_path: Path,
) -> None:
    async with running_gateway(rules=True, database_url=on_disk(tmp_path)) as gw:
        ids = [f"INV-{n:04d}" for n in range(1, PARALLEL + 1)]
        results = await asyncio.gather(
            *(one_call(gw, "finance", "get_invoice", {"invoice_id": i}) for i in ids)
        )
        # every caller got the answer for ITS invoice, not a neighbour's
        for invoice_id, result in zip(ids, results, strict=True):
            assert not result.is_error
            assert result.structured_content is not None
            assert result.structured_content["invoice_id"] == invoice_id
        events = call_events(gw)
        assert len(events) == PARALLEL
        assert len({e.correlation_id for e in events}) == PARALLEL
        assert len(gw.downstream.calls) == PARALLEL
        assert gw.audit_store is not None and gw.audit_store.verify().ok  # chain intact


async def test_a_mixed_burst_is_decided_per_call(tmp_path: Path) -> None:
    """Allowed and denied calls arriving together do not leak into each other."""
    async with running_gateway(rules=True, database_url=on_disk(tmp_path)) as gw:
        jobs = []
        for n in range(PARALLEL):
            if n % 2:
                jobs.append(one_call(gw, "finance", "list_invoices", {"limit": 500}))
            else:
                jobs.append(one_call(gw, "finance", "list_invoices", {"limit": 5}))
        results = await asyncio.gather(*jobs)
        assert [r.is_error for r in results] == [bool(n % 2) for n in range(PARALLEL)]
        assert len(gw.downstream.calls) == PARALLEL // 2


async def test_an_approval_spent_by_many_callers_at_once_runs_exactly_once(tmp_path: Path) -> None:
    async with running_gateway(rules=True, database_url=on_disk(tmp_path)) as gw:
        approval_id = await approved_bank_change(gw)
        results = await asyncio.gather(
            *(one_call(gw, "finance", BANK_TOOL, BANK_ARGS, approval_id) for _ in range(10))
        )
        winners = [r for r in results if not r.is_error]
        losers = [body(r)["reason_code"] for r in results if r.is_error]
        assert len(winners) == 1
        assert losers == ["APPROVAL_ALREADY_USED"] * 9
        assert [(c.tool, c.args) for c in gw.downstream.calls] == [(BANK_TOOL, BANK_ARGS)]


async def test_asking_for_the_same_approval_at_once_creates_one_request(tmp_path: Path) -> None:
    async with running_gateway(rules=True, database_url=on_disk(tmp_path)) as gw:
        results = await asyncio.gather(
            *(one_call(gw, "finance", BANK_TOOL, BANK_ARGS) for _ in range(10))
        )
        assert len({body(r)["approval_id"] for r in results}) == 1
        assert gw.approvals is not None and len(gw.approvals.list_pending()) == 1
        assert gw.downstream.calls == []


def test_the_rate_limiter_gives_competing_threads_exactly_the_burst() -> None:
    limiter = TokenBucketRateLimiter(30, 10, clock=lambda: 1000.0)  # time frozen: no refill
    start = threading.Barrier(50)
    granted: list[bool] = []

    def compete() -> None:
        start.wait()
        granted.append(limiter.allow("finance-agent"))

    threads = [threading.Thread(target=compete) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert (granted.count(True), granted.count(False)) == (10, 40)


# ------------------------------------------------------------------ timeout


async def test_an_approved_call_that_times_out_is_spent_and_cannot_run_twice() -> None:
    async with running_gateway(rules=True, call_timeout=0.3) as gw:
        approval_id = await approved_bank_change(gw)
        gw.delay["seconds"] = 3.0
        timed_out = await one_call(gw, "finance", BANK_TOOL, BANK_ARGS, approval_id)
        gw.delay["seconds"] = 0.0
        assert body(timed_out)["reason_code"] == "DOWNSTREAM_TIMEOUT"

        assert gw.approvals is not None
        record = gw.approvals.get(approval_id)
        assert record is not None
        assert (record.status, record.execution_status) == ("used", "timeout")
        assert call_events(gw)[-1].execution_status == "timeout"

        retry = await one_call(gw, "finance", BANK_TOOL, BANK_ARGS, approval_id)
        assert body(retry)["reason_code"] == "APPROVAL_ALREADY_USED"
        assert len(gw.downstream.calls) == 1  # the timed-out attempt only


async def test_the_gateway_keeps_serving_after_a_timeout() -> None:
    async with running_gateway(rules=True, call_timeout=0.3) as gw:
        gw.delay["seconds"] = 3.0
        slow = await one_call(gw, "finance", "get_invoice", {"invoice_id": "INV-0005"})
        gw.delay["seconds"] = 0.0
        fast = await one_call(gw, "finance", "get_invoice", {"invoice_id": "INV-0005"})
        assert slow.is_error and not fast.is_error


# ------------------------------------------------------------------ downstream error


async def test_an_approved_call_whose_server_crashes_is_spent_and_cannot_run_twice() -> None:
    async with running_gateway(rules=True) as gw:
        approval_id = await approved_bank_change(gw)
        attempts = 0

        async def boom(*args: object, **kwargs: object) -> None:
            nonlocal attempts
            attempts += 1
            raise RuntimeError("internal detail that must not leak")

        gw.downstream.call_tool = boom  # type: ignore[method-assign]
        crashed = await one_call(gw, "finance", BANK_TOOL, BANK_ARGS, approval_id)
        assert body(crashed)["reason_code"] == "DOWNSTREAM_ERROR"
        assert "internal detail" not in crashed.content[0].text  # type: ignore[union-attr]

        assert gw.approvals is not None
        record = gw.approvals.get(approval_id)
        assert record is not None
        assert (record.status, record.execution_status) == ("used", "error")

        retry = await one_call(gw, "finance", BANK_TOOL, BANK_ARGS, approval_id)
        assert body(retry)["reason_code"] == "APPROVAL_ALREADY_USED"
        assert attempts == 1


async def test_a_downstream_error_is_audited_and_the_chain_stays_intact(tmp_path: Path) -> None:
    async with running_gateway(rules=True, database_url=on_disk(tmp_path)) as gw:

        async def boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("down")

        gw.downstream.call_tool = boom  # type: ignore[method-assign]
        await asyncio.gather(
            *(one_call(gw, "finance", "get_invoice", {"invoice_id": "INV-0005"}) for _ in range(8))
        )
        events = call_events(gw)
        assert [e.execution_status for e in events] == ["error"] * 8
        assert gw.audit_store is not None and gw.audit_store.verify().ok


# ------------------------------------------------------------------ retry


async def test_a_retry_after_a_transient_failure_is_a_new_audited_call() -> None:
    async with running_gateway(rules=True, call_timeout=0.3) as gw:
        args = {"invoice_id": "INV-0005"}
        gw.delay["seconds"] = 3.0
        first = await one_call(gw, "finance", "get_invoice", args)
        gw.delay["seconds"] = 0.0
        second = await one_call(gw, "finance", "get_invoice", args)

        assert first.is_error and not second.is_error
        events = call_events(gw)
        assert [e.execution_status for e in events] == ["timeout", "ok"]
        assert events[0].correlation_id != events[1].correlation_id
        assert events[0].args_hash == events[1].args_hash  # recognisably the same request


async def test_the_agent_helper_waits_for_approval_then_runs_the_request_once() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        polls = 0

        async def approver_acts(_: float) -> None:
            nonlocal polls
            polls += 1
            if polls == 2:  # the human decides on the second wait
                assert gw.approvals is not None
                (pending,) = gw.approvals.list_pending()
                assert api.post(f"/approvals/{pending.approval_id}/approve").status_code == 200

        async with gw.client(gw.keys["finance"].key) as client:
            result = await call_tool_with_approval(
                client, BANK_TOOL, BANK_ARGS, wait_seconds=5, poll_seconds=0, sleep=approver_acts
            )
        assert not result.is_error
        assert polls == 2
        assert [(c.tool, c.args) for c in gw.downstream.calls] == [(BANK_TOOL, BANK_ARGS)]


async def test_the_agent_helper_gives_up_cleanly_if_nobody_decides() -> None:
    async with running_gateway(rules=True) as gw:
        ticks = iter(range(100))

        async def no_wait(_: float) -> None:
            return None

        async with gw.client(gw.keys["finance"].key) as client:
            result = await call_tool_with_approval(
                client,
                BANK_TOOL,
                BANK_ARGS,
                wait_seconds=3,
                poll_seconds=0,
                sleep=no_wait,
                clock=lambda: float(next(ticks)),
            )
        assert body(result)["reason_code"] == "APPROVAL_PENDING"
        assert gw.downstream.calls == []


# ------------------------------------------------------------------ duplicate requests


async def test_the_same_allowed_call_twice_is_two_audited_calls() -> None:
    """The gateway does not silently merge or drop repeats: each is decided and recorded."""
    async with running_gateway(rules=True) as gw:
        args = {"invoice_id": "INV-0005"}
        await one_call(gw, "finance", "get_invoice", args)
        await one_call(gw, "finance", "get_invoice", args)
        events = call_events(gw)
        assert len(events) == 2
        assert events[0].correlation_id != events[1].correlation_id
        assert len(gw.downstream.calls) == 2


async def test_paying_the_same_invoice_twice_is_refused_by_the_server() -> None:
    async with running_gateway(rules=True) as gw:
        args = {"invoice_id": "INV-0005", "amount": 389.51}
        first = await one_call(gw, "finance", "initiate_payment", args)
        second = await one_call(gw, "finance", "initiate_payment", args)
        assert not first.is_error
        assert second.is_error  # the mock server: "already has a payment"
        assert [e.execution_status for e in call_events(gw)] == ["ok", "tool_error"]


async def test_a_duplicate_paused_request_is_the_same_approval_not_a_second_one() -> None:
    async with running_gateway(rules=True) as gw:
        first = body(await one_call(gw, "finance", BANK_TOOL, BANK_ARGS))
        second = body(await one_call(gw, "finance", BANK_TOOL, BANK_ARGS))
        assert first["approval_id"] == second["approval_id"]
        assert gw.approvals is not None and len(gw.approvals.list_pending()) == 1


async def test_a_duplicate_request_with_different_values_is_a_separate_approval() -> None:
    async with running_gateway(rules=True) as gw:
        other = {**BANK_ARGS, "account_number": "11112222"}
        first = body(await one_call(gw, "finance", BANK_TOOL, BANK_ARGS))
        second = body(await one_call(gw, "finance", BANK_TOOL, other))
        assert first["approval_id"] != second["approval_id"]
