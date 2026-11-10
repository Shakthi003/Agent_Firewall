"""Stage 7 tests: the dashboard API (AC-44 to AC-48).

AC-44  decisions, reason codes, policy versions and audit event details are served
AC-45  pending approvals can be approved or rejected through the API the dashboard uses
AC-46  the audit chain verification result (intact or broken) is served
AC-47  an attack simulation returns decision, evidence and investigation in one response
AC-48  inputs are validated and unhandled errors return a request ID, not a stack trace
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text

from apps.api.main import create_app
from gateway.mcp_gateway.audit import FanOutAuditSink
from tests.gateway_harness import (
    APPROVER_PASSWORD,
    APPROVER_USER,
    GatewayHarness,
    running_gateway,
)
from tests.security.test_approval import BANK_ARGS, BANK_TOOL, ask, body, retry

NORMAL = ("get_invoice", {"invoice_id": "INV-0005"})
DENIED = ("read_payroll", {"employee_id": "EMP-001"})  # finance agent is not granted this
PAUSED = ("export_records", {"table": "invoices", "limit": 5000})


def api_for(gw: GatewayHarness, *, dist: Path | None = None, **kwargs: Any) -> TestClient:
    assert gw.approvals is not None and gw.audit_store is not None
    app = create_app(
        gw.approvals,
        FanOutAuditSink([gw.audit, gw.audit_store]),
        username=APPROVER_USER,
        password=APPROVER_PASSWORD,  # secret-scan: ignore
        clock=lambda: gw.now["t"],
        audit_store=gw.audit_store,
        alerts=gw.alerts,
        dashboard_dir=dist,
        **kwargs,
    )
    client = TestClient(app, raise_server_exceptions=False)
    client.auth = (APPROVER_USER, APPROVER_PASSWORD)
    return client


async def populate(gw: GatewayHarness) -> None:
    async with gw.client(gw.keys["finance"].key) as client:
        await client.call_tool(*NORMAL)
        await client.call_tool(*DENIED)
        await client.call_tool(*PAUSED)


# ---------------------------------------------------------------- AC-44: what is shown


async def test_overview_counts_decisions_and_reasons() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        body = api_for(gw).get("/api/overview").json()
    assert body["totals"]["allowed"] == 1
    assert body["totals"]["blocked"] == 1
    assert body["totals"]["needs_approval"] == 1
    assert body["pending_approvals"] == 1
    assert {r["reason"] for r in body["top_reasons"]} >= {"TOOL_NOT_GRANTED", "APPROVAL_REQUIRED"}
    assert body["agents"][0]["agent_id"] == "finance-agent"
    assert len(body["timeline"]) == 24
    assert body["head"]["count"] == gw.audit_store.count()  # type: ignore[union-attr]


async def test_audit_events_show_decision_reason_and_policy_version() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        events = api_for(gw).get("/api/audit/events", params={"method": "tools/call"}).json()
    by_tool = {e["tool"]: e for e in events["events"]}
    assert by_tool["read_payroll"]["decision"] == "BLOCK"
    assert by_tool["read_payroll"]["reason_code"] == "TOOL_NOT_GRANTED"
    assert by_tool["export_records"]["decision"] == "REQUIRE_APPROVAL"
    assert by_tool["get_invoice"]["policy_version"]
    assert by_tool["get_invoice"]["record_hash"] and by_tool["get_invoice"]["prev_hash"]
    seqs = [e["seq"] for e in events["events"]]
    assert seqs == sorted(seqs, reverse=True)  # newest first


async def test_audit_events_filter_and_page() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        api = api_for(gw)
        blocked = api.get("/api/audit/events", params={"decision": "BLOCK"}).json()["events"]
        assert blocked and all(e["decision"] == "BLOCK" for e in blocked)
        found = api.get("/api/audit/events", params={"search": "payroll"}).json()["events"]
        assert found and all(e["tool"] == "read_payroll" for e in found)
        first = api.get("/api/audit/events", params={"limit": 2}).json()
        assert len(first["events"]) == 2 and first["next_before_seq"] is not None
        second = api.get(
            "/api/audit/events", params={"limit": 2, "before_seq": first["next_before_seq"]}
        ).json()
        assert {e["seq"] for e in second["events"]}.isdisjoint({e["seq"] for e in first["events"]})


async def test_search_treats_wildcards_literally() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        found = api_for(gw).get("/api/audit/events", params={"search": "%"}).json()
    assert found["events"] == []  # '%' is not a wildcard that matches everything


async def test_one_event_with_its_siblings() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        api = api_for(gw)
        target = api.get("/api/audit/events", params={"search": "payroll"}).json()["events"][0]
        detail = api.get(f"/api/audit/events/{target['seq']}").json()
        missing = api.get("/api/audit/events/99999")
    assert detail["event"]["seq"] == target["seq"]
    assert all(e["correlation_id"] == target["correlation_id"] for e in detail["same_call"])
    assert missing.status_code == 404


async def test_events_never_expose_raw_secrets() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        raw = api_for(gw).get("/api/audit/events", params={"limit": 200}).text
        key = gw.keys["finance"].key
    assert key not in raw


# ---------------------------------------------------------------- AC-45: approvals


async def test_approvals_list_includes_decided_and_the_dashboard_can_decide() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        api = api_for(gw)
        pending = api.get("/api/approvals").json()
        assert [a["status"] for a in pending] == ["pending"]
        approval_id = pending[0]["approval_id"]
        assert pending[0]["args"]["limit"] == 5000  # the approver sees the full request
        done = api.post(f"/approvals/{approval_id}/reject")
        assert done.status_code == 200
        after = api.get("/api/approvals").json()
        again = api.post(f"/approvals/{approval_id}/approve")
    assert after[0]["status"] == "rejected" and after[0]["decided_by"] == APPROVER_USER
    assert again.status_code == 409  # a decided approval cannot be decided again


# ---------------------------------------------------------------- AC-46: chain verification


async def test_verify_reports_intact_then_broken() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        api = api_for(gw)
        intact = api.get("/api/audit/verify").json()
        assert intact["ok"] is True and intact["checked"] == gw.audit_store.count()  # type: ignore[union-attr]
        # Flip the first BLOCK in the database to ALLOW, as an attacker hiding a denial would.
        engine = gw.audit_store._engine  # type: ignore[union-attr]
        with engine.begin() as conn:
            target = conn.execute(
                text("SELECT MIN(seq) FROM audit_events WHERE decision = 'BLOCK'")
            ).scalar_one()
            conn.execute(
                text("UPDATE audit_events SET decision = 'ALLOW' WHERE seq = :seq"),
                {"seq": target},
            )
        broken = api.get("/api/audit/verify").json()
    assert broken["ok"] is False
    assert broken["first_bad_seq"] == target
    assert broken["reason"]


# ---------------------------------------------------------------- AC-47: simulation


def test_simulation_returns_decision_evidence_and_investigation() -> None:
    import asyncio

    async def go() -> dict[str, Any]:
        async with running_gateway(rules=True) as gw:
            api = api_for(gw)
            catalog = api.get("/api/simulations/scenarios").json()
            assert [s["id"] for s in catalog] == ["A", "B", "C", "D"]
            live_before = gw.audit_store.count()  # type: ignore[union-attr]
            response = api.post("/api/simulations/run", json={"scenario": "B"})
            assert response.status_code == 200, response.text
            assert gw.audit_store.count() == live_before  # type: ignore[union-attr]
            return response.json()

    result = asyncio.run(go())
    assert result["sandbox"] is True
    calls = {c["call_id"]: c for c in result["calls"]}
    assert calls["B1"]["decision"] == "BLOCK"
    assert calls["B1"]["reason_code"] == "PROD_DESTRUCTIVE_DENIED"
    assert all(
        c["decision"] == c["expected_decision"] for c in result["calls"] if c["expected_decision"]
    )
    assert result["chain"]["ok"] is True
    assert result["events"] and result["report"]["severity"] in {"low", "medium", "high"}
    assert result["report"]["advisory_only"] is True
    assert result["report"]["degraded"] is True  # offline mode used the deterministic fallback
    cited = result["report"]["summary_event_ids"]
    assert cited and set(cited) <= {e["seq"] for e in result["events"]}  # AC-40 holds here too


def test_simulation_rejects_unknown_scenarios_and_extra_fields() -> None:
    import asyncio

    async def go() -> list[int]:
        async with running_gateway(rules=True) as gw:
            api = api_for(gw)
            return [
                api.post("/api/simulations/run", json={"scenario": "Z"}).status_code,
                api.post("/api/simulations/run", json={"scenario": "A", "x": 1}).status_code,
                api.post("/api/simulations/run", json={}).status_code,
            ]

    assert asyncio.run(go()) == [422, 422, 422]


# ---------------------------------------------------------------- AC-48: validation and errors


async def test_invalid_input_is_a_422_with_a_request_id_and_no_internals() -> None:
    async with running_gateway(rules=True) as gw:
        api = api_for(gw)
        responses = [
            api.get("/api/audit/events", params={"limit": 0}),
            api.get("/api/audit/events", params={"limit": 100000}),
            api.get("/api/audit/events", params={"decision": "x; DROP TABLE"}),
            api.get("/api/audit/events", params={"before_seq": "abc"}),
            api.post("/api/investigations", json={"agent_id": "Bad Agent!"}),
        ]
    for response in responses:
        assert response.status_code == 422
        body = response.json()
        assert body["request_id"] == response.headers["X-Request-ID"]
        assert "Traceback" not in response.text and "sqlalchemy" not in response.text.lower()


async def test_unhandled_error_returns_request_id_not_a_stack_trace() -> None:
    async with running_gateway(rules=True) as gw:
        api = api_for(gw)
        assert gw.audit_store is not None

        def boom(**_: Any) -> None:
            raise RuntimeError("secret internal detail: postgresql://user:pw@host/db")

        gw.audit_store.list_events = boom  # type: ignore[method-assign]
        response = api.get("/api/audit/events")
    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "Something went wrong."
    assert body["request_id"] == response.headers["X-Request-ID"]
    assert "secret internal detail" not in response.text and "Traceback" not in response.text


async def test_every_response_has_a_distinct_request_id() -> None:
    async with running_gateway(rules=True) as gw:
        api = api_for(gw)
        ids = {api.get("/api/session").headers["X-Request-ID"] for _ in range(5)}
    assert len(ids) == 5


# ---------------------------------------------------------------- login and exposure


async def test_every_dashboard_route_needs_the_approver_login() -> None:
    async with running_gateway(rules=True) as gw:
        api = api_for(gw)
        api.auth = None
        routes = [
            ("GET", "/api/session"),
            ("GET", "/api/overview"),
            ("GET", "/api/audit/events"),
            ("GET", "/api/audit/events/1"),
            ("GET", "/api/audit/verify"),
            ("GET", "/api/alerts"),
            ("GET", "/api/approvals"),
            ("GET", "/api/simulations/scenarios"),
            ("POST", "/api/simulations/run"),
            ("POST", "/api/investigations"),
        ]
        statuses = [api.request(m, p).status_code for m, p in routes]
        wrong = api.get("/api/session", auth=(APPROVER_USER, "nope"))
        agent_key = api.get(
            "/api/overview", headers={"Authorization": f"Bearer {gw.keys['finance'].key}"}
        )
        from_dashboard = api.get("/api/session", headers={"X-Requested-With": "dashboard"})
    assert statuses == [401] * len(routes)
    assert wrong.status_code == 401
    assert agent_key.status_code == 401  # an agent key is not an approver login
    assert "WWW-Authenticate" in wrong.headers
    assert "WWW-Authenticate" not in from_dashboard.headers  # no browser popup over our form


async def test_failed_dashboard_logins_are_audited() -> None:
    async with running_gateway(rules=True) as gw:
        api = api_for(gw)
        api.get("/api/session", auth=(APPROVER_USER, "nope"))
        events = gw.audit_store.events()  # type: ignore[union-attr]
    assert any(e.event.reason_code == "APPROVER_AUTH_FAILED" for e in events)


async def test_dashboard_files_are_served_only_when_built(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<title>Agent Firewall</title>", encoding="utf-8")
    async with running_gateway(rules=True) as gw:
        with_ui = api_for(gw, dist=tmp_path)
        without_ui = api_for(gw, dist=tmp_path / "missing")
        page = with_ui.get("/")
        api_still_works = with_ui.get("/api/session")
        no_page = without_ui.get("/")
    assert page.status_code == 200 and "Agent Firewall" in page.text
    assert api_still_works.status_code == 200
    assert no_page.status_code == 404


async def test_investigation_on_the_live_log_is_advisory() -> None:
    async with running_gateway(rules=True) as gw:
        await populate(gw)
        before = gw.audit_store.count()  # type: ignore[union-attr]
        response = api_for(gw).post("/api/investigations", json={"agent_id": "finance-agent"})
        after = gw.audit_store.count()  # type: ignore[union-attr]
    assert response.status_code == 200
    assert response.json()["report"]["advisory_only"] is True
    assert after == before  # investigating writes nothing


# ---------------------------------------------------------------- AC-45: end to end


async def test_end_to_end_agent_asks_dashboard_approves_agent_runs_once() -> None:
    """The whole loop with the calls the dashboard makes (not browser-driven)."""
    async with running_gateway(rules=True) as gw:
        api = api_for(gw)
        async with gw.client(gw.keys["finance"].key) as client:
            paused = body(await ask(client))
            assert paused["decision"] == "REQUIRE_APPROVAL" and gw.downstream.calls == []

            shown = api.get("/api/approvals").json()
            assert [(a["approval_id"], a["status"]) for a in shown] == [
                (paused["approval_id"], "pending")
            ]
            assert shown[0]["args"] == BANK_ARGS  # the approver judges the exact request

            assert api.post(f"/approvals/{paused['approval_id']}/approve").status_code == 200
            done = await retry(client, paused["approval_id"])
            replay = await retry(client, paused["approval_id"])

        assert not done.is_error
        assert [(c.tool, c.args) for c in gw.downstream.calls] == [(BANK_TOOL, BANK_ARGS)]
        assert replay.is_error and body(replay)["reason_code"] == "APPROVAL_ALREADY_USED"
        final = api.get("/api/approvals").json()[0]
        assert (final["status"], final["decided_by"]) == ("used", APPROVER_USER)
        # The decision is in the audit log the dashboard shows, tied to the approval.
        decided = api.get("/api/audit/events", params={"method": "approval/decide"}).json()
        assert decided["events"][0]["approval_id"] == paused["approval_id"]
        assert decided["events"][0]["approver_id"] == APPROVER_USER
        assert api.get("/api/audit/verify").json()["ok"] is True


async def test_end_to_end_rejection_means_the_call_never_runs() -> None:
    async with running_gateway(rules=True) as gw:
        api = api_for(gw)
        async with gw.client(gw.keys["finance"].key) as client:
            paused = body(await ask(client))
            assert api.post(f"/approvals/{paused['approval_id']}/reject").status_code == 200
            result = await retry(client, paused["approval_id"])
        assert result.is_error and body(result)["reason_code"] == "APPROVAL_REJECTED"
        assert gw.downstream.calls == []
        assert api.get("/api/approvals").json()[0]["status"] == "rejected"
