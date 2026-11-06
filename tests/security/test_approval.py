"""Stage 4 security tests: human-in-the-loop approval (AC-22 .. AC-30).

Each test runs the real gateway with the real rules from `policies/policy.yaml`, the real approval
store and the real approver API. The common claim: an approval-required action never reaches a
downstream server until a valid approval exists, and an approval is spent exactly once.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.client import Client
from mcp_types import CallToolResult

from agents.business.gateway_client import APPROVAL_META_KEY, call_tool_with_approval
from tests.gateway_harness import GatewayHarness, running_gateway

BANK_ARGS = {"beneficiary_id": "BEN-001", "account_number": "99887766"}
BANK_TOOL = "update_beneficiary_bank_details"


def body(result: CallToolResult) -> dict[str, Any]:
    assert result.structured_content is not None
    return dict(result.structured_content)


async def ask(client: Client, args: dict[str, Any] | None = None) -> CallToolResult:
    return await client.call_tool(BANK_TOOL, args or BANK_ARGS)


async def retry(
    client: Client, approval_id: str, args: dict[str, Any] | None = None
) -> CallToolResult:
    return await client.call_tool(
        BANK_TOOL,
        args or BANK_ARGS,
        meta={APPROVAL_META_KEY: approval_id},  # type: ignore[typeddict-unknown-key]
    )


def server_calls(gw: GatewayHarness) -> list[str]:
    return [c.tool for c in gw.downstream.calls]


def audit_for(gw: GatewayHarness, approval_id: str) -> list[Any]:
    return [e for e in gw.audit.events if e.approval_id == approval_id]


# ------------------------------------------------------------------ AC-22: pending, not executed


async def test_a_paused_call_returns_pending_with_an_approval_id_and_does_not_run() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await ask(client)
        data = body(result)
        assert result.is_error
        assert (data["decision"], data["reason_code"]) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
        assert len(data["approval_id"]) == 32
        assert data["expires_at"] > 0
        assert "99887766" not in str(data)
        assert server_calls(gw) == []


async def test_asking_twice_while_pending_gives_the_same_approval() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            first, second = body(await ask(client)), body(await ask(client))
        assert first["approval_id"] == second["approval_id"]
        assert len(gw.approvals.list_pending()) == 1  # type: ignore[union-attr]


async def test_the_stored_request_is_the_exact_request() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        stored = gw.approvals.get(approval_id)  # type: ignore[union-attr]
        assert stored is not None
        assert stored.args == BANK_ARGS
        assert (stored.tool, stored.requester_agent_id) == (BANK_TOOL, "finance-agent")
        assert stored.status == "pending"


# ------------------------------------------------------------------ AC-23: approve, then run once


async def test_after_approval_the_retry_runs_exactly_the_stored_request() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            assert api.post(f"/approvals/{approval_id}/approve").status_code == 200
            result = await retry(client, approval_id)
        assert not result.is_error
        assert [(c.tool, c.args) for c in gw.downstream.calls] == [(BANK_TOOL, BANK_ARGS)]
        assert gw.approvals.get(approval_id).status == "used"  # type: ignore[union-attr]


async def test_the_approver_sees_the_pending_request_to_judge_it() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        pending = api.get("/approvals/pending").json()
        assert [p["approval_id"] for p in pending] == [approval_id]
        assert pending[0]["args"] == BANK_ARGS
        assert pending[0]["requester_agent_id"] == "finance-agent"


async def test_before_the_decision_the_retry_is_still_pending_and_does_not_run() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            result = await retry(client, approval_id)
        data = body(result)
        assert (data["decision"], data["reason_code"]) == ("REQUIRE_APPROVAL", "APPROVAL_PENDING")
        assert server_calls(gw) == []


# ------------------------------------------------------------------ AC-24: changed arguments


async def test_a_retry_with_changed_arguments_is_rejected_and_never_runs() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            changed = await retry(client, approval_id, {**BANK_ARGS, "account_number": "11112222"})
            assert body(changed)["reason_code"] == "APPROVAL_MISMATCH"
            assert server_calls(gw) == []
            # the genuine request is still approved and unspent
            assert not (await retry(client, approval_id)).is_error
        assert [c.args for c in gw.downstream.calls] == [BANK_ARGS]


async def test_an_approval_for_one_tool_cannot_run_another() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            result = await client.call_tool(
                "initiate_payment",
                {"invoice_id": "INV-0001", "amount": 12000},
                meta={APPROVAL_META_KEY: approval_id},  # type: ignore[typeddict-unknown-key]
            )
        assert body(result)["reason_code"] == "APPROVAL_MISMATCH"
        assert server_calls(gw) == []


# ------------------------------------------------------------------ AC-25: replay


async def test_a_second_use_of_the_same_approval_is_rejected() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            assert not (await retry(client, approval_id)).is_error
            replay = await retry(client, approval_id)
        assert body(replay)["reason_code"] == "APPROVAL_ALREADY_USED"
        assert server_calls(gw) == [BANK_TOOL]  # once, not twice


async def test_the_store_lets_an_approval_be_spent_only_once() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
        spent = []
        for _ in range(3):
            try:
                gw.approvals.consume(  # type: ignore[union-attr]
                    approval_id,
                    agent_id="finance-agent",
                    tool=BANK_TOOL,
                    args_hash=gw.approvals.get(approval_id).args_hash,  # type: ignore[union-attr]
                )
                spent.append(True)
            except Exception:  # noqa: S110
                pass
        assert spent == [True]


async def test_a_decision_cannot_be_replayed() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        assert api.post(f"/approvals/{approval_id}/approve").status_code == 200
        assert api.post(f"/approvals/{approval_id}/approve").status_code == 409
        assert api.post(f"/approvals/{approval_id}/reject").status_code == 409  # cannot flip it
        assert gw.approvals.get(approval_id).status == "approved"  # type: ignore[union-attr]


# ------------------------------------------------------------------ AC-26: expiry


async def test_an_expired_approval_is_rejected() -> None:
    async with running_gateway(rules=True, expiry_seconds=900) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            gw.now["t"] += 901
            result = await retry(client, approval_id)
        assert body(result)["reason_code"] == "APPROVAL_EXPIRED"
        assert server_calls(gw) == []


async def test_a_request_that_expired_before_a_decision_cannot_be_approved() -> None:
    async with running_gateway(rules=True, expiry_seconds=900) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        gw.now["t"] += 901
        assert api.get("/approvals/pending").json() == []
        assert api.post(f"/approvals/{approval_id}/approve").status_code == 409
        assert gw.approvals.get(approval_id).status == "expired"  # type: ignore[union-attr]


async def test_the_expiry_follows_the_setting() -> None:
    async with running_gateway(rules=True, expiry_seconds=60) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            gw.now["t"] += 59
            assert not (await retry(client, approval_id)).is_error


# ------------------------------------------------------------------ AC-27: rejected


async def test_a_rejected_request_never_runs() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            assert api.post(f"/approvals/{approval_id}/reject").status_code == 200
            result = await retry(client, approval_id)
        data = body(result)
        assert (data["decision"], data["reason_code"]) == ("BLOCK", "APPROVAL_REJECTED")
        assert server_calls(gw) == []


# ------------------------------------------------------------------ AC-28: who may decide


async def test_the_approver_api_needs_the_approver_login() -> None:
    async with running_gateway(rules=True) as gw:
        from fastapi.testclient import TestClient

        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        anonymous = TestClient(api.app)
        wrong = TestClient(api.app)
        wrong.auth = ("approver", "not-the-password")
        agent_key = TestClient(
            api.app, headers={"Authorization": f"Bearer {gw.keys['finance'].key}"}
        )
        for who in (anonymous, wrong, agent_key):
            assert who.get("/approvals/pending").status_code == 401
            assert who.post(f"/approvals/{approval_id}/approve").status_code == 401
        assert gw.approvals.get(approval_id).status == "pending"  # type: ignore[union-attr]
        assert any(e.reason_code == "APPROVER_AUTH_FAILED" for e in gw.audit.events)


async def test_an_agent_cannot_approve_its_own_request_through_the_gateway() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            # holding the approval ID alone does nothing: only a human decision counts
            fake = await retry(client, approval_id)
        assert body(fake)["reason_code"] == "APPROVAL_PENDING"
        assert server_calls(gw) == []
        tools = {t.name for t in (await _list(gw)).tools}
        assert not any("approv" in t for t in tools)


async def _list(gw: GatewayHarness) -> Any:
    async with gw.client(gw.keys["finance"].key) as client:
        return await client.list_tools()


async def test_the_store_refuses_a_requester_deciding_its_own_request() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        from gateway.approvals.store import ApprovalError

        with pytest.raises(ApprovalError) as err:
            gw.approvals.decide(approval_id, "finance-agent", approve=True)  # type: ignore[union-attr]
        assert err.value.code == "SELF_APPROVAL"
        assert gw.approvals.get(approval_id).status == "pending"  # type: ignore[union-attr]


async def test_another_agent_cannot_spend_an_approval() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        api.post(f"/approvals/{approval_id}/approve")
        # same role, different agent: the approval belongs to finance-agent only
        other = gw.registry.register_agent("finance-agent-2", "finance")
        async with gw.client(other.key) as client:
            result = await retry(client, approval_id)
        assert body(result)["reason_code"] == "APPROVAL_INVALID"
        assert server_calls(gw) == []


@pytest.mark.parametrize("bad", ["", "nope", "A" * 32, "0" * 31, "0" * 33, "../../etc", 5, ["x"]])
async def test_a_malformed_approval_id_is_refused(bad: Any) -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool(
                BANK_TOOL,
                BANK_ARGS,
                meta={APPROVAL_META_KEY: bad},  # type: ignore[typeddict-unknown-key]
            )
        assert body(result)["reason_code"] == "APPROVAL_INVALID"
        assert server_calls(gw) == []


async def test_an_unknown_approval_id_is_refused() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await retry(client, "0" * 32)
        assert body(result)["reason_code"] == "APPROVAL_INVALID"
        assert server_calls(gw) == []


# ------------------------------------------------------------------ AC-29: policy re-checked


async def test_an_approval_does_not_override_a_block() -> None:
    """An approval for a call that policy would now BLOCK (here: payroll export) cannot run."""
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            first = await client.call_tool("export_records", {"table": "invoices", "limit": 5000})
            approval_id = body(first)["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            # an approved export of invoices cannot be redirected to payroll
            swapped = await client.call_tool(
                "export_records",
                {"table": "payroll", "limit": 5000},
                meta={APPROVAL_META_KEY: approval_id},  # type: ignore[typeddict-unknown-key]
            )
        assert body(swapped)["decision"] == "BLOCK"
        assert server_calls(gw) == []


async def test_policy_is_evaluated_again_at_execution() -> None:
    from gateway.policy.decision import PolicyDecision

    class Switchable:
        mode = "REQUIRE_APPROVAL"
        calls = 0

        def evaluate(self, identity: Any, tool: str, args: dict[str, Any]) -> PolicyDecision:
            Switchable.calls += 1
            reason = (
                "APPROVAL_REQUIRED" if self.mode == "REQUIRE_APPROVAL" else "SECRETS_ACCESS_DENIED"
            )
            return PolicyDecision(self.mode, reason, "test-1")  # type: ignore[arg-type]

    policy = Switchable()
    async with running_gateway(policy=policy) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            policy.mode = "BLOCK"  # the rules changed after the approval
            result = await retry(client, approval_id)
        data = body(result)
        assert (data["decision"], data["reason_code"]) == ("BLOCK", "SECRETS_ACCESS_DENIED")
        assert server_calls(gw) == []
        assert gw.approvals.get(approval_id).status == "approved"  # type: ignore[union-attr]
        assert Switchable.calls == 2  # once to pause the call, once more on the retry


# ------------------------------------------------------------------ AC-30: audit


async def test_approver_identity_time_decision_and_result_are_audited() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            await retry(client, approval_id)
        events = audit_for(gw, approval_id)
        assert [(e.method, e.decision, e.reason_code) for e in events] == [
            ("tools/call", "REQUIRE_APPROVAL", "APPROVAL_REQUIRED"),
            ("approval/decide", "APPROVED", "APPROVER_DECISION"),
            ("tools/call", "ALLOW", "APPROVAL_GRANTED"),
        ]
        decision = events[1]
        assert decision.approver_id == "approver"
        assert decision.timestamp == pytest.approx(gw.now["t"], abs=5)
        assert decision.agent_id == "finance-agent"  # whose request it was
        executed = events[2]
        assert executed.execution_status == "ok"
        stored = gw.approvals.get(approval_id)  # type: ignore[union-attr]
        assert stored is not None
        assert (stored.decided_by, stored.execution_status) == ("approver", "ok")
        assert stored.decided_at is not None and stored.used_at is not None


async def test_a_rejection_and_a_refused_decision_are_audited() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
        api.post(f"/approvals/{approval_id}/reject")
        api.post(f"/approvals/{approval_id}/approve")  # refused: already decided
        decisions = [e for e in audit_for(gw, approval_id) if e.method == "approval/decide"]
        assert [(e.decision, e.reason_code, e.approver_id) for e in decisions] == [
            ("REJECTED", "APPROVER_DECISION", "approver"),
            ("BLOCK", "APPROVER_REFUSED", "approver"),
        ]


async def test_the_audit_log_holds_no_argument_values() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            approval_id = body(await ask(client))["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            await retry(client, approval_id)
        assert "99887766" not in str(gw.audit.events)


# ------------------------------------------------------------------ the agent helper


async def test_the_agent_helper_waits_for_the_approval_and_resumes() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            decided: list[str] = []

            async def approver_acts(_: float) -> None:
                if not decided:
                    pending = api.get("/approvals/pending").json()
                    decided.append(pending[0]["approval_id"])
                    api.post(f"/approvals/{decided[0]}/approve")

            result = await call_tool_with_approval(
                client, BANK_TOOL, BANK_ARGS, wait_seconds=30, poll_seconds=0, sleep=approver_acts
            )
        assert not result.is_error
        assert server_calls(gw) == [BANK_TOOL]


async def test_the_agent_helper_returns_the_final_denial_when_rejected() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:

            async def approver_rejects(_: float) -> None:
                for p in api.get("/approvals/pending").json():
                    api.post(f"/approvals/{p['approval_id']}/reject")

            result = await call_tool_with_approval(
                client,
                BANK_TOOL,
                BANK_ARGS,
                wait_seconds=30,
                poll_seconds=0,
                sleep=approver_rejects,
            )
        assert body(result)["reason_code"] == "APPROVAL_REJECTED"
        assert server_calls(gw) == []


async def test_the_agent_helper_gives_up_when_nobody_decides() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            ticks = iter(range(100))

            async def no_sleep(_: float) -> None:
                return None

            result = await call_tool_with_approval(
                client,
                BANK_TOOL,
                BANK_ARGS,
                wait_seconds=3,
                poll_seconds=0,
                sleep=no_sleep,
                clock=lambda: float(next(ticks)),
            )
        assert body(result)["decision"] == "REQUIRE_APPROVAL"
        assert server_calls(gw) == []


async def test_without_waiting_the_helper_returns_pending_at_once() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await call_tool_with_approval(client, BANK_TOOL, BANK_ARGS, wait_seconds=0)
        assert body(result)["reason_code"] == "APPROVAL_REQUIRED"
        assert "approval_id" in body(result)


# ------------------------------------------------------------------ nothing else changed


async def test_blocks_and_allows_are_unchanged_by_approvals() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            blocked = await client.call_tool("read_payroll", {})
            allowed = await client.call_tool("get_invoice", {"invoice_id": "INV-0001"})
        assert body(blocked)["decision"] == "BLOCK"
        assert "approval_id" not in body(blocked)
        assert not allowed.is_error
        assert gw.approvals.list_pending() == []  # type: ignore[union-attr]


async def test_an_approval_id_on_a_call_that_needs_none_changes_nothing() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool(
                "get_invoice",
                {"invoice_id": "INV-0001"},
                meta={APPROVAL_META_KEY: "0" * 32},  # type: ignore[typeddict-unknown-key]
            )
        assert not result.is_error
