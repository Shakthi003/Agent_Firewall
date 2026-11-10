"""Stage 5 detection tests (AC-36, AC-37, AC-38).

AC-36  each rule fires on its simulated attack and stays quiet on normal simulator traffic
AC-37  the same seeded run gives the same alerts, byte for byte
AC-38  the anomaly model and the monitor never change a deterministic policy decision
"""

from __future__ import annotations

import ast
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

from gateway.mcp_gateway.audit import AuditEvent
from monitoring.detection.anomaly import windows_of
from monitoring.detection.evaluate import evaluate, rule_hits_by_event, train_model
from monitoring.detection.rules import (
    RESPONSE_BY_LEVEL,
    BehaviourMonitor,
    MonitorResult,
    RuleConfig,
    risk_level,
)
from monitoring.detection.simulator import (
    RULE_COVERED,
    Episode,
    TrafficSimulator,
    all_events,
)
from tests.gateway_harness import running_gateway

# attack kind -> the rule that must fire on it
EXPECTED_RULE = {
    "burst": "BURST",
    "large_export": "LARGE_EXPORT",
    "repeated_denials": "REPEATED_DENIALS",
    "unusual_sequence": "UNUSUAL_SEQUENCE",
    "off_hours": "OFF_HOURS",
}
ROOT = Path(__file__).resolve().parents[2]
BUSINESS_HOURS = 1_772_000_000.0 + 10 * 3600  # a fixed timestamp inside business hours (UTC)


@pytest.fixture(scope="module")
def episodes() -> list[Episode]:
    return TrafficSimulator(2002).generate()


def rules_on(ep: Episode) -> set[str]:
    """Rules that hit anywhere in this episode when it is the only traffic."""
    hits = rule_hits_by_event(list(ep.events))
    return {rule for h in hits.values() for rule in h}


def call(
    cid: str,
    ts: float,
    *,
    agent: str = "a",
    tool: str = "get_invoice",
    decision: str = "ALLOW",
    args: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        timestamp=ts,
        correlation_id=cid,
        method="tools/call",
        decision=decision,
        reason_code="X",
        agent_id=agent,
        tool=tool,
        sanitized_args=args or {},
    )


# ------------------------------------------------------------------ AC-36


@pytest.mark.parametrize("kind", RULE_COVERED)
def test_each_rule_fires_on_every_simulated_episode_of_its_attack(
    kind: str, episodes: list[Episode]
) -> None:
    attacks = [e for e in episodes if e.kind == kind]
    assert len(attacks) == 6
    for ep in attacks:
        assert EXPECTED_RULE[kind] in rules_on(ep), (kind, [e.tool for e in ep.events][:5])


def test_no_rule_fires_on_any_normal_session(episodes: list[Episode]) -> None:
    normal = [e for e in episodes if not e.is_attack]
    assert len(normal) == 120
    for ep in normal:
        assert rules_on(ep) == set(), [(e.tool, e.decision) for e in ep.events]


def test_no_rule_fires_on_the_whole_normal_stream_run_together() -> None:
    """Sessions of different agents interleave in real traffic; they must still stay quiet."""
    stream = all_events(TrafficSimulator(5).generate(days=10, attacks_per_kind=0))
    assert len(stream) > 400
    assert BehaviourMonitor().run(stream) == []


def test_other_seeds_also_stay_quiet_on_normal_traffic() -> None:
    for seed in (1, 2, 3, 4):
        stream = all_events(TrafficSimulator(seed).generate(attacks_per_kind=0))
        assert BehaviourMonitor().run(stream) == [], seed


def test_the_slow_scrape_is_a_known_blind_spot_of_the_rules(episodes: list[Episode]) -> None:
    """Documented, not hidden: the rules do not catch a slow, steady trickle of reads."""
    scrapes = [e for e in episodes if e.kind == "slow_scrape"]
    assert scrapes and all(rules_on(e) == set() for e in scrapes)


def test_scenario_d_a_bulk_export_request_is_flagged() -> None:
    """Scenario D: the planned unsafe call export_records(invoices, limit 5000)."""
    result = BehaviourMonitor().observe(
        call(
            "d1",
            BUSINESS_HOURS,
            agent="finance-agent",
            tool="export_records",
            decision="REQUIRE_APPROVAL",
            args={"table": "invoices", "limit": 5000},
        )
    )
    assert "LARGE_EXPORT" in result.hits
    assert result.score >= 0.7
    assert [a.rule for a in result.alerts] == ["LARGE_EXPORT"]
    assert result.alerts[0].evidence == ("d1",)


def test_an_export_within_the_normal_ceiling_is_not_flagged() -> None:
    event = call(
        "ok", BUSINESS_HOURS, tool="export_records", args={"table": "invoices", "limit": 100}
    )
    assert BehaviourMonitor().observe(event).hits == ()


def test_thresholds_are_exact_for_burst_and_denials() -> None:
    cfg = RuleConfig(burst_calls=5, burst_window_s=10, denial_count=3, denial_window_s=60)
    base = BUSINESS_HOURS

    four = BehaviourMonitor(cfg)
    assert all(four.observe(call(f"e{i}", base + i)).hits == () for i in range(4))
    assert four.observe(call("e4", base + 4)).hits == ("BURST",)  # the 5th inside the window

    slow = BehaviourMonitor(cfg)
    assert all(slow.observe(call(f"e{i}", base + i * 11)).hits == () for i in range(8))

    denied = BehaviourMonitor(cfg)
    assert denied.observe(call("0", base, decision="BLOCK")).hits == ()
    assert denied.observe(call("1", base + 1, decision="BLOCK")).hits == ()
    assert denied.observe(call("2", base + 2, decision="BLOCK")).hits == ("REPEATED_DENIALS",)

    spread = BehaviourMonitor(cfg)
    spaced = [spread.observe(call(f"s{i}", base + i * 40, decision="BLOCK")).hits for i in range(4)]
    assert spaced == [()] * 4


def test_the_sequence_rule_needs_both_calls_by_the_same_agent_in_order() -> None:
    base = BUSINESS_HOURS
    bank = "update_beneficiary_bank_details"

    wrong_order = BehaviourMonitor()
    wrong_order.observe(call("1", base, tool=bank))
    assert wrong_order.observe(call("2", base + 5, tool="get_invoice")).hits == ()

    other_agent = BehaviourMonitor()
    other_agent.observe(call("1", base, agent="a", tool="get_invoice"))
    assert other_agent.observe(call("2", base + 5, agent="b", tool=bank)).hits == ()

    too_late = BehaviourMonitor()
    too_late.observe(call("1", base, tool="get_invoice"))
    assert too_late.observe(call("2", base + 500, tool=bank)).hits == ()

    in_order = BehaviourMonitor()
    in_order.observe(call("1", base, tool="get_invoice"))
    found = in_order.observe(call("2", base + 5, tool=bank))
    assert found.hits == ("UNUSUAL_SEQUENCE",)
    assert found.alerts[0].evidence == ("1", "2")


def test_the_cooldown_limits_alerts_but_not_the_score() -> None:
    monitor = BehaviourMonitor()
    results = [
        monitor.observe(
            call(
                f"e{i}",
                BUSINESS_HOURS + i,
                tool="export_records",
                decision="REQUIRE_APPROVAL",
                args={"limit": 5000},
            )
        )
        for i in range(5)
    ]
    assert [len(r.alerts) for r in results] == [1, 0, 0, 0, 0]
    assert all(r.score >= 0.7 for r in results)  # every one of them is still scored high


def test_off_hours_is_judged_on_the_event_time_not_the_wall_clock() -> None:
    night = 1_772_000_000.0 + 3 * 3600 - (1_772_000_000.0 % 86400)  # 03:00 UTC that day
    assert BehaviourMonitor().observe(call("n", night)).hits == ("OFF_HOURS",)
    assert BehaviourMonitor().observe(call("d", night + 8 * 3600)).hits == ()


def test_only_tool_calls_are_scored() -> None:
    listing = replace(call("l", BUSINESS_HOURS), method="tools/list")
    assert BehaviourMonitor().observe(listing).score == 0.0


# ------------------------------------------------------------------ AC-37


def test_the_simulator_is_byte_for_byte_repeatable() -> None:
    a = [asdict(e) for e in all_events(TrafficSimulator(42).generate())]
    b = [asdict(e) for e in all_events(TrafficSimulator(42).generate())]
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert len(a) > 600


def test_different_seeds_give_different_traffic() -> None:
    a = [e.args_hash for e in all_events(TrafficSimulator(1).generate())]
    b = [e.args_hash for e in all_events(TrafficSimulator(2).generate())]
    assert a != b


def test_the_same_run_gives_the_same_alerts() -> None:
    runs = [BehaviourMonitor().run(all_events(TrafficSimulator(2002).generate())) for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]
    assert len(runs[0]) > 20


def test_the_alerts_do_not_depend_on_other_work_in_the_process() -> None:
    first = BehaviourMonitor().run(all_events(TrafficSimulator(7).generate()))
    BehaviourMonitor().run(all_events(TrafficSimulator(8).generate()))  # unrelated work
    second = BehaviourMonitor().run(all_events(TrafficSimulator(7).generate()))
    assert first == second


def test_the_anomaly_model_is_repeatable() -> None:
    test = windows_of(all_events(TrafficSimulator(2002).generate()))
    assert train_model().scores(test) == train_model().scores(test)


def test_the_full_evaluation_is_repeatable() -> None:
    assert evaluate().as_text() == evaluate().as_text()


# ------------------------------------------------------------------ the measured results


def test_the_measured_quality_of_the_detections() -> None:
    """Guard rails on the numbers reported in the docs. If these move, the docs must change."""
    report = evaluate()
    assert report.normal_episodes == 120 and report.attack_episodes == 36
    for kind in RULE_COVERED:
        assert report.rule_caught[kind] == (6, 6), kind
    assert report.rule_caught["slow_scrape"] == (0, 6)  # the rules' blind spot
    assert report.rules_false_alarm_episodes == 0
    assert report.rules.precision == 1.0
    assert report.rules.recall > 0.7
    # The model is a second, weaker opinion: it must find something real without drowning
    # the rules' clean record in false alarms.
    assert report.model.recall > 0.3
    assert report.model.precision > 0.8
    assert report.model_false_alarm_episodes <= 6
    assert report.combined.recall >= report.rules.recall


# ------------------------------------------------------------------ AC-38


def test_a_risk_level_only_ever_means_none_or_alert() -> None:
    assert set(RESPONSE_BY_LEVEL.values()) <= {"none", "alert"}
    assert risk_level(0.0) == "normal"
    assert risk_level(0.5) == "elevated"
    assert risk_level(0.9) == "high"


def test_nothing_in_the_enforcement_path_imports_the_detectors() -> None:
    """Static check: policy, identity and approvals never import the rules, model or sklearn."""
    forbidden = ("monitoring.detection", "sklearn")
    for folder in ("gateway/policy", "gateway/identity", "gateway/approvals"):
        for path in (ROOT / folder).rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    assert not name.startswith(forbidden), (path, name)
    server = (ROOT / "gateway/mcp_gateway/server.py").read_text(encoding="utf-8")
    assert "monitoring.detection" not in server
    assert "sklearn" not in server


class _AlwaysMax(BehaviourMonitor):
    """A monitor that rates every call as maximally anomalous."""

    def observe(self, event: AuditEvent) -> MonitorResult:
        return replace(super().observe(event), score=1.0)


MIXED_CALLS = [
    ("finance", "get_invoice", {"invoice_id": "INV-0005"}),
    ("finance", "export_records", {"table": "invoices", "limit": 5000}),
    ("finance", "list_invoices", {"limit": 100}),
    ("it_ops", "delete_resource", {"resource_id": "RES-001", "env": "prod"}),
    ("it_ops", "get_service_status", {"service": "search", "env": "staging"}),
    ("developer", "repo_push_commit", {"repo": "billing-service", "branch": "main"}),
]


async def _decisions(monitor: BehaviourMonitor | None) -> tuple[list[tuple[str, str]], list[str]]:
    async with running_gateway(rules=True, monitor=monitor) as gw:
        out: list[tuple[str, str]] = []
        for agent, tool, args in MIXED_CALLS:
            async with gw.client(gw.keys[agent].key) as client:
                result = await client.call_tool(tool, args)
            body = result.structured_content or {}
            out.append((body.get("decision", "ALLOW"), body.get("reason_code", "")))
        return out, [c.tool for c in gw.downstream.calls]


async def test_a_maximum_anomaly_score_does_not_change_what_the_gateway_decides() -> None:
    """The same calls through two gateways: one scoring everything 1.0, one with the default."""
    plain = await _decisions(None)
    maxed = await _decisions(_AlwaysMax())
    assert plain == maxed
    decisions, forwarded = plain
    assert decisions[1][0] == "REQUIRE_APPROVAL" and decisions[3][0] == "BLOCK"
    assert forwarded == ["get_invoice", "get_service_status"]


async def test_a_high_score_is_stored_but_the_call_was_still_allowed_and_forwarded() -> None:
    async with running_gateway(rules=True, monitor=_AlwaysMax()) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        assert not result.is_error
        assert [c.tool for c in gw.downstream.calls] == ["get_invoice"]
        assert gw.audit_store is not None
        event = next(s.event for s in gw.audit_store.events() if s.event.method == "tools/call")
        assert event.anomaly_score == 1.0
        assert (event.decision, event.enforcement_action) == ("ALLOW", "forwarded")


async def test_a_crashing_monitor_does_not_stop_the_call_or_the_audit_record() -> None:
    class Crashing(BehaviourMonitor):
        def observe(self, event: AuditEvent) -> MonitorResult:
            raise RuntimeError("monitor bug")

    async with running_gateway(rules=True, monitor=Crashing()) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            result = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        assert not result.is_error
        assert gw.audit_store is not None
        assert gw.audit_store.count() >= 1 and gw.audit_store.verify().ok


async def test_alerts_are_saved_with_evidence_pointing_at_real_audit_events() -> None:
    async with running_gateway(rules=True) as gw:
        async with gw.client(gw.keys["finance"].key) as client:
            await client.call_tool("export_records", {"table": "invoices", "limit": 5000})
        assert gw.alerts is not None and gw.audit_store is not None
        # OFF_HOURS also fires when this runs outside 06:00-22:00 UTC (it reads the wall clock),
        # so only the rule this test is about is checked.
        saved = [a for a in gw.alerts.list_alerts() if a.rule == "LARGE_EXPORT"]
        assert len(saved) == 1
        for cid in saved[0].evidence:
            assert gw.audit_store.get_by_correlation(cid), "an alert cites a missing audit event"
