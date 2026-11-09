"""Stage 5 security tests: the audit trail through the real gateway (AC-31, AC-32, AC-33, AC-34).

The real gateway, the real rules, the real hash-chained store (SQLite in memory), with the
real approver API writing to the same chain.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import text

from agents.business.gateway_client import APPROVAL_META_KEY
from agents.business.scenarios import UNSAFE_CALLS
from gateway.mcp_gateway.audit import AuditEvent
from monitoring.audit.store import AuditStore
from tests.gateway_harness import GatewayHarness, running_gateway
from tests.security.test_policy_enforcement import demo_run_registry

BANK = {"beneficiary_id": "BEN-001", "account_number": "99887766"}

REQUIRED_FIELDS = (
    "timestamp",
    "correlation_id",
    "method",
    "decision",
    "reason_code",
    "enforcement_action",
    "execution_status",
    "latency_ms",
    "anomaly_score",
    "sanitized_args",
    "args_hash",
    "policy_version",
)


def chain(gw: GatewayHarness) -> AuditStore:
    assert gw.audit_store is not None
    return gw.audit_store


def stored_calls(gw: GatewayHarness) -> list[AuditEvent]:
    return [s.event for s in chain(gw).events() if s.event.method == "tools/call"]


# ------------------------------------------------------------------ AC-31: completeness


async def test_every_protected_call_in_the_scenario_suite_has_one_complete_stored_event() -> None:
    """All 12 planned unsafe calls, the normal workflows' tools, and the failure paths."""
    async with running_gateway(rules=True, tools=demo_run_registry()) as gw:
        sent = 0
        for call in UNSAFE_CALLS:
            async with gw.client(gw.keys[call.agent].key) as client:
                await client.call_tool(call.tool, dict(call.args))
            sent += 1
        async with gw.client(gw.keys["finance"].key) as client:
            await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})  # allowed
            await client.call_tool("get_invoice", {"invoice_id": "INV-0005", "extra": 1})  # schema
            await client.call_tool("no_such_tool", {})  # unknown
            await client.call_tool("read_payroll", {"employee_id": "EMP-001"})  # not granted
            sent += 4
        async with gw.client("afk_not-a-real-key") as client:  # bad credential
            await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
            sent += 1

        events = stored_calls(gw)
        assert len(events) == sent
        correlation_ids = {e.correlation_id for e in events}
        assert len(correlation_ids) == sent  # one event per call, none merged or lost
        for e in events:
            assert e.timestamp > 0
            assert e.decision in ("ALLOW", "BLOCK", "REQUIRE_APPROVAL")
            assert e.reason_code
            assert e.enforcement_action in ("forwarded", "blocked", "paused")
            assert e.args_hash is not None and len(e.args_hash) == 64
            assert e.latency_ms >= 0
        # An authenticated call carries identity and tool; the policy version is present on every
        # call the policy engine decided. Calls refused earlier (not granted, bad schema, bad
        # credential) never reached it, so they have none.
        planned = events[: len(UNSAFE_CALLS)]
        for e, call in zip(planned, UNSAFE_CALLS, strict=True):
            assert e.agent_id is not None and e.role is not None
            assert e.tool == call.tool
            assert (e.decision, e.reason_code) == (call.decision, call.reason)
            if call.reason != "TOOL_NOT_GRANTED":
                assert e.policy_version and e.policy_version != "pass-through-0"
        refused_early = {
            "UNREGISTERED_AGENT",
            "UNKNOWN_TOOL",
            "TOOL_NOT_GRANTED",
            "INVALID_ARGUMENTS",
        }
        for e in events:
            assert (e.policy_version is None) == (e.reason_code in refused_early), e.reason_code
        assert chain(gw).verify().ok


async def test_the_stored_events_match_the_in_memory_ones_exactly_except_for_the_score() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            await client.list_tools()
            await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
            await client.call_tool("export_records", {"table": "invoices", "limit": 5000})
        stored = [s.event for s in chain(gw).events()]
        assert len(stored) == len(gw.audit.events)
        assert [e.method for e in stored].count("tools/call") == 2
        for kept, db in zip(gw.audit.events, stored, strict=True):
            assert db.correlation_id == kept.correlation_id
            assert (db.decision, db.reason_code) == (kept.decision, kept.reason_code)
            assert db.anomaly_score is not None  # stamped by the monitor on the way in


async def test_a_denied_call_is_stored_with_enforcement_blocked() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            await client.call_tool("delete_resource", {"resource_id": "RES-001", "env": "prod"})
        event = stored_calls(gw)[0]
        assert (event.decision, event.enforcement_action) == ("BLOCK", "blocked")
        assert event.execution_status == "not_executed"
        assert gw.downstream.calls == []


async def test_the_approval_flow_is_in_the_same_verified_chain() -> None:
    async with running_gateway(rules=True) as gw:
        api = gw.approver_api()
        async with gw.client(gw.keys["finance"].key) as client:
            paused = await client.call_tool("update_beneficiary_bank_details", BANK)
            approval_id = (paused.structured_content or {})["approval_id"]
            api.post(f"/approvals/{approval_id}/approve")
            await client.call_tool(
                "update_beneficiary_bank_details",
                BANK,
                meta={APPROVAL_META_KEY: approval_id},  # type: ignore[typeddict-unknown-key]
            )
        methods = [
            (s.event.method, s.event.decision)
            for s in chain(gw).events()
            if s.event.method != "tools/list"  # the MCP client lists tools before each call
        ]
        assert methods == [
            ("tools/call", "REQUIRE_APPROVAL"),
            ("approval/decide", "APPROVED"),
            ("tools/call", "ALLOW"),
        ]
        decide = next(s.event for s in chain(gw).events() if s.event.method == "approval/decide")
        assert decide.approver_id == "approver"
        assert decide.enforcement_action == "recorded"
        assert chain(gw).verify().ok


# ------------------------------------------------------------------ AC-32: no secrets, canaries


async def test_no_canary_value_reaches_the_stored_log() -> None:
    """Seeded canaries go in through every channel an agent controls. None may be stored."""
    canary_key = "afk_CANARYAGENTKEY0123456789abcdefghijkl"
    canary_account = "5550123456789012"
    canary_note = "CANARY-FREE-TEXT-" + "x" * 80
    async with running_gateway(rules=True) as gw:
        real_key = gw.keys["finance"].key
        async with gw.client(real_key) as client:
            # account number as an argument, on a tool that takes one
            await client.call_tool(
                "update_beneficiary_bank_details",
                {"beneficiary_id": "BEN-001", "account_number": canary_account},
            )
            # a key-like value and long text inside an argument the schema rejects
            await client.call_tool("get_invoice", {"invoice_id": canary_key, "note": canary_note})
            # an identity claim carrying a key-like value
            await client.call_tool(
                "get_invoice", {"invoice_id": "INV-0005", "agent_name": canary_key}
            )
            # a secret-looking field name the schema rejects
            await client.call_tool("get_invoice", {"invoice_id": "INV-0005", "password": "p455"})
        async with gw.client(canary_key) as client:  # an unknown credential
            await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})

        rows = " ".join(r[0] for r in _all(chain(gw), "SELECT event_json FROM audit_events"))
        everything = rows + str(gw.audit.events)
        for canary in (real_key, canary_key, canary_account, canary_note, "p455"):
            assert canary not in rows, f"{canary[:12]}... was stored in the audit log"
            assert canary not in everything, f"{canary[:12]}... leaked into an event"
        assert "****9012" in rows  # the last four digits are what is kept


async def test_tool_results_are_not_stored_in_the_log() -> None:
    """`read_env_secrets` returns fake secret values; they must never appear in the log."""
    async with running_gateway(tools=demo_run_registry()) as gw:  # pass-through policy
        async with gw.client(gw.keys["developer"].key) as client:
            result = await client.call_tool("read_env_secrets", {"scope": "prod"})
        assert not result.is_error
        assert "FAKE-NOT-A-SECRET" in result.content[0].text  # the agent did get them
        rows = " ".join(r[0] for r in _all(chain(gw), "SELECT event_json FROM audit_events"))
        assert "FAKE-NOT-A-SECRET" not in rows
        assert "DB_PASSWORD" not in rows


async def test_identity_claims_are_not_stored_only_their_field_names() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            await client.call_tool(
                "get_invoice", {"invoice_id": "INV-0005", "agent_name": "it-ops-agent"}
            )
        event = stored_calls(gw)[0]
        assert event.spoofed_fields == ("agent_name",)
        assert event.spoof_attempt is True
        assert "it-ops-agent" not in json.dumps(event.sanitized_args)


# ------------------------------------------------------------------ AC-33 / AC-34 on a real run


async def test_a_real_run_verifies_and_any_later_edit_or_delete_is_detected() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            for i in range(1, 8):
                await client.call_tool("get_invoice", {"invoice_id": f"INV-{i:04d}"})
        store = chain(gw)
        assert store.verify().ok
        assert store.verify().checked == store.count() >= 7

        _run(store, "UPDATE audit_events SET reason_code = 'X' WHERE seq = 3")
        assert not store.verify().ok

    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            for i in range(1, 8):
                await client.call_tool("get_invoice", {"invoice_id": f"INV-{i:04d}"})
        store = chain(gw)
        _run(store, "DELETE FROM audit_events WHERE seq = 4")  # an early record
        assert not store.verify().ok


# ------------------------------------------------------------------ fail closed on the audit store


async def test_a_call_is_not_forwarded_when_the_audit_store_is_unavailable() -> None:
    class BrokenAudit:
        def record(self, event: AuditEvent) -> None:
            raise RuntimeError("database down")

        def check(self) -> None:
            raise RuntimeError("database down")

    async with running_gateway(rules=True, audit_override=BrokenAudit()) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        assert result.is_error
        assert (result.structured_content or {})["reason_code"] == "POLICY_UNAVAILABLE"
        assert "database down" not in result.content[0].text
        assert gw.downstream.calls == []  # nothing ran without being able to record it


async def test_an_audit_write_failure_after_the_decision_does_not_hide_the_outcome() -> None:
    """If the store dies between `check()` and `record()`, the call still answers the agent."""

    class FlakyAudit:
        def record(self, event: AuditEvent) -> None:
            raise RuntimeError("write failed")

        def check(self) -> None:
            return None

    async with running_gateway(rules=True, audit_override=FlakyAudit()) as gw:
        async with gw.client(gw.keys["it_ops"].key) as client:
            result = await client.call_tool(
                "delete_resource", {"resource_id": "RES-001", "env": "prod"}
            )
        assert (result.structured_content or {})["reason_code"] == "PROD_DESTRUCTIVE_DENIED"
        assert gw.downstream.calls == []


# ------------------------------------------------------------------ helpers


def _all(store: AuditStore, sql: str) -> list[Any]:
    with store._engine.connect() as conn:  # noqa: SLF001
        return list(conn.execute(text(sql)))


def _run(store: AuditStore, sql: str) -> None:
    with store._engine.begin() as conn:  # noqa: SLF001
        conn.execute(text(sql))


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_the_event_schema_has_every_required_field(field: str) -> None:
    assert field in AuditEvent.__dataclass_fields__
