"""Stage 6 tests: the investigation workflow with a FAKED model (AC-39 to AC-43).

AC-39  output matches its schema and is validated before display
AC-40  every finding and recommendation cites at least one real audit event ID
AC-41  facts and hypotheses are labelled separately
AC-42  the workflow cannot change policy or execute remediation
AC-43  if the LLM fails, a fallback summary is produced and the failure is logged
"""

from __future__ import annotations

import ast
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from core.db import make_engine
from core.llm import Message, ModelError, ToolSpec
from gateway.mcp_gateway.audit import AuditEvent
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore
from monitoring.detection.rules import Alert
from workflows.investigation import evidence as evidence_module
from workflows.investigation.evidence import READ_ONLY_TOOLS, AuditEvidence
from workflows.investigation.graph import InvestigationWorkflow, severity_floor
from workflows.investigation.schemas import Finding, Investigation, Triage

ROOT = Path(__file__).resolve().parents[2]
AGENT = "it-ops-agent"


def event(
    cid: str,
    *,
    tool: str = "get_service_status",
    decision: str = "ALLOW",
    reason: str = "ALLOWED_BY_POLICY",
    agent: str = AGENT,
    args: dict[str, Any] | None = None,
    **extra: Any,
) -> AuditEvent:
    return AuditEvent(
        timestamp=1_772_000_000.0 + int(cid[1:]),
        correlation_id=cid,
        method="tools/call",
        decision=decision,
        reason_code=reason,
        agent_id=agent,
        tool=tool,
        sanitized_args=args or {},
        **extra,
    )


def make_store(events: list[AuditEvent]) -> tuple[AuditStore, AlertStore]:
    engine = make_engine("sqlite://")
    store, alerts = AuditStore(engine), AlertStore(engine)
    store.create_tables()
    alerts.create_tables()
    for e in events:
        store.record(e)
    return store, alerts


NORMAL = [event("c1"), event("c2", tool="update_ticket")]
ATTACK = [
    event("c1", tool="update_ticket"),
    event(
        "c2",
        tool="delete_resource",
        decision="BLOCK",
        reason="PROD_DESTRUCTIVE_DENIED",
        args={"resource_id": "RES-001", "env": "prod"},
    ),
    event("c3", tool="disable_monitoring", decision="BLOCK", reason="PROD_DESTRUCTIVE_DENIED"),
]


class FakeModel:
    """Replies per stage (chosen by the system prompt). A reply may be text or an exception."""

    def __init__(self, **replies: Any) -> None:
        self.replies = {k: list(v) if isinstance(v, list) else [v] for k, v in replies.items()}
        self.prompts: list[tuple[str, str]] = []

    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message:
        assert not tools  # the investigation never offers the model any tool
        stage = (
            "analyst"
            if "security analyst" in system
            else "investigator"
            if "incident investigator" in system
            else "advisor"
        )
        self.prompts.append((stage, messages[-1].text))
        queue = self.replies[stage]
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(reply, Exception):
            raise reply
        return Message(role="model", text=reply if isinstance(reply, str) else json.dumps(reply))


def triage(severity: str = "high", ids: list[int] | None = None) -> dict[str, Any]:
    return {
        "severity": severity,
        "summary": "The agent tried destructive calls.",
        "event_ids": ids or [2, 3],
    }


def investigation(ids: list[int] | None = None) -> dict[str, Any]:
    ids = ids or [2, 3]
    return {
        "timeline": [{"event_id": i, "description": f"blocked call {i}"} for i in ids],
        "root_cause": {"kind": "hypothesis", "statement": "A poisoned ticket.", "event_ids": ids},
        "findings": [
            {"kind": "fact", "statement": "Two prod actions were blocked.", "event_ids": ids},
            {"kind": "hypothesis", "statement": "Prompt injection.", "event_ids": [2]},
        ],
    }


def advice(ids: list[int] | None = None) -> dict[str, Any]:
    return {
        "recommendations": [
            {
                "action": "Inspect ticket TCK-002",
                "rationale": "likely source",
                "event_ids": ids or [2],
            }
        ]
    }


def good_model() -> FakeModel:
    return FakeModel(analyst=triage(), investigator=investigation(), advisor=advice())


def workflow(
    events: list[AuditEvent], model: FakeModel
) -> tuple[InvestigationWorkflow, AuditStore]:
    store, alerts = make_store(events)
    return InvestigationWorkflow(AuditEvidence(store, alerts), model), store


# ------------------------------------------------------------------ AC-39 / AC-40 / AC-41


async def test_happy_path_report_is_valid_cited_and_labelled() -> None:
    wf, store = workflow(ATTACK, good_model())
    report = await wf.run(agent_id=AGENT)

    assert report.severity == "high" and not report.degraded and report.failures == []
    assert report.audit_chain_ok and report.events_examined == 3
    real = {s.seq for s in store.events()}
    assert report.cited_ids() and report.cited_ids() <= real  # AC-40
    for finding in report.findings:
        assert finding.event_ids and set(finding.event_ids) <= real
    for rec in report.recommendations:
        assert rec.event_ids and set(rec.event_ids) <= real
    assert {f.kind for f in report.findings} == {"fact", "hypothesis"}  # AC-41
    md = report.to_markdown()
    assert "## Facts" in md and "## Hypotheses (not proven)" in md
    assert md.index("## Facts") < md.index("Two prod actions") < md.index("## Hypotheses")
    assert md.index("## Hypotheses") < md.index("Prompt injection")


def test_schemas_reject_unlabelled_uncited_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({"kind": "guess", "statement": "x", "event_ids": [1]})
    with pytest.raises(ValidationError):
        Finding.model_validate({"kind": "fact", "statement": "x", "event_ids": []})  # no citation
    with pytest.raises(ValidationError):
        Triage.model_validate({**triage(), "run_command": "rm -rf /"})  # extra field
    with pytest.raises(ValidationError):
        Triage.model_validate(triage("catastrophic"))
    with pytest.raises(ValidationError):
        Investigation.model_validate({**investigation(), "findings": []})


async def test_reply_in_a_code_fence_is_accepted() -> None:
    fenced = "```json\n" + json.dumps(triage("medium")) + "\n```"
    model = FakeModel(analyst=fenced, investigator=investigation(), advisor=advice())
    wf, _ = workflow(ATTACK, model)
    report = await wf.run(agent_id=AGENT)
    assert report.failures == []


async def test_invalid_reply_is_retried_once_with_the_reason_then_accepted() -> None:
    model = FakeModel(
        analyst=["not json at all", triage("medium")],
        investigator=investigation(),
        advisor=advice(),
    )
    wf, _ = workflow(ATTACK, model)
    report = await wf.run(agent_id=AGENT)
    assert report.failures == [] and not report.degraded
    analyst_prompts = [p for stage, p in model.prompts if stage == "analyst"]
    assert len(analyst_prompts) == 2 and "previous reply was rejected" in analyst_prompts[1]


async def test_invented_event_ids_are_rejected_not_displayed() -> None:
    model = FakeModel(analyst=triage(ids=[2, 999]), investigator=investigation(), advisor=advice())
    wf, store = workflow(ATTACK, model)
    report = await wf.run(agent_id=AGENT)
    assert report.degraded and "999" in report.failures[0]
    assert 999 not in report.cited_ids() and report.cited_ids() <= {s.seq for s in store.events()}


async def test_invented_ids_in_investigator_and_advisor_fall_back_too() -> None:
    model = FakeModel(analyst=triage(), investigator=investigation([2, 77]), advisor=advice([88]))
    wf, store = workflow(ATTACK, model)
    report = await wf.run(agent_id=AGENT)
    assert report.degraded and len(report.failures) == 2
    assert report.cited_ids() <= {s.seq for s in store.events()}
    assert report.findings and report.recommendations  # still useful


# ------------------------------------------------------------------ AC-43


async def test_llm_failure_gives_a_fallback_summary_and_logs_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    boom = ModelError("quota exhausted")
    model = FakeModel(analyst=boom, investigator=boom, advisor=boom)
    wf, store = workflow(ATTACK, model)
    with caplog.at_level(logging.WARNING, logger="agent_firewall.investigation"):
        report = await wf.run(agent_id=AGENT)

    assert report.degraded
    assert {f.split(":")[0] for f in report.failures} == {"analyst", "investigator", "advisor"}
    assert "Fallback summary" in report.summary
    assert report.severity == "high"  # the deterministic floor, with no model at all
    assert report.requires_human_review and report.review_status == "pending_human_review"
    assert report.cited_ids() <= {s.seq for s in store.events()} and report.findings
    assert "quota exhausted" in caplog.text and "fallback" in caplog.text.lower()
    assert "Degraded" in report.to_markdown()


# ------------------------------------------------------------------ routing and human review


async def test_low_severity_stops_after_triage_and_needs_no_review() -> None:
    model = FakeModel(analyst=triage("low", [1, 2]))
    wf, _ = workflow(NORMAL, model)
    report = await wf.run(agent_id=AGENT)
    assert report.severity == "low" and not report.requires_human_review
    assert report.review_status == "not_required"
    assert report.timeline == [] and report.recommendations == []
    assert {s for s, _ in model.prompts} == {"analyst"}  # investigator/advisor never ran


async def test_medium_runs_all_three_nodes_without_human_review() -> None:
    events = [event("c1"), event("c2", decision="BLOCK", reason="TOOL_NOT_GRANTED")]
    model = FakeModel(
        analyst=triage("medium", [2]), investigator=investigation([2]), advisor=advice([2])
    )
    wf, _ = workflow(events, model)
    report = await wf.run(agent_id=AGENT)
    assert report.severity == "medium" and not report.requires_human_review
    assert [s for s, _ in model.prompts] == ["analyst", "investigator", "advisor"]


async def test_high_severity_is_marked_pending_human_review() -> None:
    wf, _ = workflow(ATTACK, good_model())
    report = await wf.run(agent_id=AGENT)
    assert report.requires_human_review and report.review_status == "pending_human_review"
    assert "pending human review" in report.to_markdown()


async def test_the_model_cannot_lower_severity_below_the_deterministic_floor() -> None:
    model = FakeModel(analyst=triage("low", [2]), investigator=investigation(), advisor=advice())
    wf, _ = workflow(ATTACK, model)  # prod-destructive denials => floor is high
    report = await wf.run(agent_id=AGENT)
    assert report.severity == "high" and report.requires_human_review


async def test_no_events_gives_a_low_report_without_calling_the_model() -> None:
    model = FakeModel()
    wf, _ = workflow([], model)
    report = await wf.run(agent_id=AGENT)
    assert report.severity == "low" and report.events_examined == 0
    assert model.prompts == [] and report.cited_ids() == set()


async def test_alerts_raise_the_floor_and_are_shown_to_the_model() -> None:
    store, alerts = make_store(NORMAL)
    alerts.add(
        Alert(
            rule="BURST",
            agent_id=AGENT,
            timestamp=1.0,
            score=0.9,
            severity="high",
            detail="too many calls",
            evidence=("c1", "c2"),
        )
    )
    model = FakeModel(
        analyst=triage("low", [1]), investigator=investigation([1]), advisor=advice([1])
    )
    report = await InvestigationWorkflow(AuditEvidence(store, alerts), model).run(agent_id=AGENT)
    assert report.severity == "high"
    assert "too many calls" in model.prompts[0][1] and '"event_ids": [1, 2]' in model.prompts[0][1]


async def test_a_broken_audit_chain_is_reported_and_forces_high_severity() -> None:
    store, alerts = make_store(ATTACK)
    with store._engine.begin() as conn:  # tamper, as an attacker with database access would
        conn.execute(
            text(
                "UPDATE audit_events SET event_json = replace(event_json, 'BLOCK', 'ALLOW') "
                "WHERE seq = 2"
            )
        )
    model = good_model()
    report = await InvestigationWorkflow(AuditEvidence(store, alerts), model).run(agent_id=AGENT)
    assert not report.audit_chain_ok and report.severity == "high"
    assert any("audit chain broken" in f for f in report.failures)
    assert "NO - evidence may be altered" in report.to_markdown()


# ------------------------------------------------------------------ evidence hygiene


async def test_evidence_sent_to_the_model_holds_no_secrets_and_is_scoped_to_the_agent() -> None:
    secret = "afk_CANARYKEY0123456789abcdefghijklmnop"  # secret-scan: ignore
    events = [
        *ATTACK,
        event("c4", agent="finance-agent", tool="get_invoice", args={"note": secret}),
    ]
    model = good_model()
    wf, _ = workflow(events, model)
    await wf.run(agent_id=AGENT)
    sent = " ".join(p for _, p in model.prompts)
    assert secret not in sent and "finance-agent" not in sent
    assert "EVIDENCE:" in sent


async def test_limit_truncates_and_says_so() -> None:
    many = [event(f"c{i}") for i in range(1, 8)]
    wf, _ = workflow(many, FakeModel(analyst=triage("low", [1])))
    report = await wf.run(agent_id=AGENT, limit=5)
    assert report.events_examined == 5 and report.truncated
    assert "truncated" in report.to_markdown()


def test_severity_floor_rules() -> None:
    def state(
        events: list[dict[str, Any]], alerts: list[dict[str, Any]] | None = None, ok: bool = True
    ) -> Any:
        return {"evidence": events, "alerts": alerts or [], "chain_ok": ok}

    allow = {"event_id": 1, "decision": "ALLOW", "reason_code": "ALLOWED_BY_POLICY"}
    deny = {"event_id": 2, "decision": "BLOCK", "reason_code": "TOOL_NOT_GRANTED"}
    prod = {"event_id": 3, "decision": "BLOCK", "reason_code": "PROD_DESTRUCTIVE_DENIED"}
    assert severity_floor(state([allow])) == "low"
    assert severity_floor(state([allow, deny])) == "medium"
    assert severity_floor(state([allow, prod])) == "high"
    assert severity_floor(state([allow], ok=False)) == "high"
    assert severity_floor(state([allow], [{"severity": "elevated"}])) == "medium"


# ------------------------------------------------------------------ AC-42


def test_the_workflow_tool_set_is_exactly_the_two_read_only_operations() -> None:
    assert READ_ONLY_TOOLS == ("fetch_events", "verify_chain")
    public = {n for n in dir(AuditEvidence) if not n.startswith("_")}
    assert public == set(READ_ONLY_TOOLS)


def test_the_evidence_source_has_no_write_path() -> None:
    class ReadOnly:
        """Only the two read methods exist; anything else raises AttributeError."""

        def __init__(self, store: AuditStore) -> None:
            self._store = store

        def events(self, **kwargs: Any) -> Any:
            return self._store.events(**kwargs)

        def verify(self) -> Any:
            return self._store.verify()

    store, _ = make_store(ATTACK)
    ev = AuditEvidence(ReadOnly(store))  # type: ignore[arg-type]
    assert len(ev.fetch_events(agent_id=AGENT).events) == 3
    before = store.head()
    ev.verify_chain()
    assert store.head() == before


def test_investigation_code_imports_nothing_that_can_change_the_system() -> None:
    forbidden = (
        "gateway.policy",
        "gateway.approvals",
        "gateway.identity",
        "gateway.mcp_gateway.server",
        "gateway.mcp_gateway.downstream",
        "mcp_servers",
        "agents.business",
    )
    for path in (ROOT / "workflows" / "investigation").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            modules = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            for module in modules:
                assert not module.startswith(forbidden), (path.name, module)
    source = Path(evidence_module.__file__).read_text(encoding="utf-8")
    for call in (".record(", ".add(", ".approve(", ".reject(", ".call_tool("):
        assert call not in source


async def test_a_high_severity_run_changes_nothing_in_the_audit_log() -> None:
    wf, store = workflow(ATTACK, good_model())
    before = (store.head(), store.count())
    await wf.run(agent_id=AGENT)
    assert (store.head(), store.count()) == before and store.verify().ok
