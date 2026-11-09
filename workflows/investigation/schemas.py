"""Typed state and validated outputs of the security investigation workflow (Stage 6).

Every LLM reply is parsed into one of these models before it is used (AC-39). Every claim
carries `event_ids`: the audit sequence numbers (`seq`) of the events behind it (AC-40). Facts
and hypotheses are separate values of `Finding.kind` (AC-41).
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high"]
SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}
MAX_ITEMS = 50

EventIds = Field(min_length=1, max_length=MAX_ITEMS)


def higher(a: Severity, b: Severity) -> Severity:
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Triage(_Strict):
    """Security Analyst output."""

    severity: Severity
    summary: str = Field(min_length=1, max_length=800)
    event_ids: list[int] = EventIds

    def cited_ids(self) -> list[int]:
        return list(self.event_ids)


class TimelineEntry(_Strict):
    event_id: int
    description: str = Field(min_length=1, max_length=300)


class Finding(_Strict):
    """`fact`: stated directly by recorded events. `hypothesis`: an inference, not proven."""

    kind: Literal["fact", "hypothesis"]
    statement: str = Field(min_length=1, max_length=600)
    event_ids: list[int] = EventIds


class Investigation(_Strict):
    """Incident Investigator output."""

    timeline: list[TimelineEntry] = Field(min_length=1, max_length=MAX_ITEMS)
    root_cause: Finding
    findings: list[Finding] = Field(min_length=1, max_length=MAX_ITEMS)

    def cited_ids(self) -> list[int]:
        return [
            *(t.event_id for t in self.timeline),
            *self.root_cause.event_ids,
            *(i for f in self.findings for i in f.event_ids),
        ]


class Recommendation(_Strict):
    """Advice for a human. Nothing in this workflow carries it out."""

    action: str = Field(min_length=1, max_length=400)
    rationale: str = Field(min_length=1, max_length=400)
    event_ids: list[int] = EventIds


class Recommendations(_Strict):
    """Remediation Advisor output."""

    recommendations: list[Recommendation] = Field(min_length=1, max_length=MAX_ITEMS)

    def cited_ids(self) -> list[int]:
        return [i for r in self.recommendations for i in r.event_ids]


class InvestigationReport(BaseModel):
    """The final, display-ready result."""

    advisory_only: Literal[True] = True
    agent_id: str | None
    severity: Severity
    summary: str
    summary_event_ids: list[int]
    events_examined: int
    truncated: bool
    audit_chain_ok: bool
    timeline: list[TimelineEntry]
    root_cause: Finding | None
    findings: list[Finding]
    recommendations: list[Recommendation]
    requires_human_review: bool
    review_status: Literal["not_required", "pending_human_review"]
    degraded: bool  # True if any step used the deterministic fallback instead of the LLM
    failures: list[str]

    def cited_ids(self) -> set[int]:
        ids = {t.event_id for t in self.timeline} | set(self.summary_event_ids)
        if self.root_cause is not None:
            ids.update(self.root_cause.event_ids)
        ids.update(i for f in self.findings for i in f.event_ids)
        ids.update(i for r in self.recommendations for i in r.event_ids)
        return ids

    def to_markdown(self) -> str:
        def cites(ids: list[int]) -> str:
            return "[events " + ", ".join(str(i) for i in sorted(set(ids))) + "]"

        lines = [
            f"# Incident report: {self.agent_id or 'all agents'}",
            "",
            f"- Severity: **{self.severity}**",
            f"- Events examined: {self.events_examined}"
            + (" (truncated to the limit)" if self.truncated else ""),
            "- Audit chain verified: "
            + ("yes" if self.audit_chain_ok else "NO - evidence may be altered"),
            f"- Review: {self.review_status.replace('_', ' ')}",
            "- Advisory only: nothing in this report was executed.",
        ]
        if self.degraded:
            lines.append("- Degraded: the LLM failed, so the deterministic fallback was used.")
        summary = self.summary + (
            f" {cites(self.summary_event_ids)}" if self.summary_event_ids else ""
        )
        lines += ["", "## Summary", "", summary, ""]
        if self.timeline:
            lines += ["## Timeline", ""]
            lines += [f"- event {t.event_id}: {t.description}" for t in self.timeline]
            lines.append("")
        if self.root_cause is not None:
            rc = self.root_cause
            lines += [
                "## Root cause",
                "",
                f"{rc.kind.upper()}: {rc.statement} {cites(rc.event_ids)}",
                "",
            ]
        for title, kind in (("Facts", "fact"), ("Hypotheses (not proven)", "hypothesis")):
            items = [f for f in self.findings if f.kind == kind]
            if items:
                lines += [f"## {title}", ""]
                lines += [f"- {f.statement} {cites(f.event_ids)}" for f in items]
                lines.append("")
        if self.recommendations:
            lines += ["## Recommendations (for a human to decide)", ""]
            lines += [
                f"- {r.action} (why: {r.rationale}) {cites(r.event_ids)}"
                for r in self.recommendations
            ]
            lines.append("")
        if self.failures:
            lines += ["## Failures", ""] + [f"- {f}" for f in self.failures] + [""]
        return "\n".join(lines)


class InvestigationState(TypedDict, total=False):
    """What flows between the graph nodes."""

    scope: dict[str, Any]  # agent_id, after_seq, limit
    evidence: list[dict[str, Any]]  # sanitized audit events
    alerts: list[dict[str, Any]]
    evidence_seqs: list[int]
    truncated: bool
    chain_ok: bool
    triage: Triage
    severity: Severity
    investigation: Investigation
    recommendations: list[Recommendation]
    failures: list[str]
    review_status: Literal["not_required", "pending_human_review"]
    report: InvestigationReport
