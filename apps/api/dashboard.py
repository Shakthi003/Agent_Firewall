"""Read endpoints for the dashboard (Stage 7).

Everything here is behind the approver login and is READ-ONLY, apart from the simulation (which
runs in a throw-away sandbox, see `simulation.py`) and the investigation (advisory, read-only by
construction, see `workflows/investigation/evidence.py`). Approving and rejecting stay on the
Stage 4 endpoints in `main.py`.

    GET  /api/session                     who is logged in
    GET  /api/overview                    totals, decisions, top reasons, agents, 24h timeline
    GET  /api/audit/events                newest first, filterable, paged by `before_seq`
    GET  /api/audit/events/{seq}          one event, its call's other events, linked alerts
    GET  /api/audit/verify                walks the hash chain: intact or broken
    GET  /api/alerts                      behaviour-monitor alerts
    GET  /api/approvals                   every approval, not only the pending ones
    GET  /api/simulations/scenarios       the documented attack scenarios
    POST /api/simulations/run             run one in the sandbox, with its investigation
    POST /api/investigations              investigate the live audit log (advisory)
"""

import asyncio
from collections import Counter, defaultdict
from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from apps.api.simulation import (
    SCENARIO_IDS,
    SimulationUnavailable,
    event_view,
    run_scenario,
    scenario_catalog,
)
from core.llm import ChatModel
from gateway.approvals.store import ApprovalRecord, ApprovalStore
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore
from workflows.investigation.evidence import AuditEvidence
from workflows.investigation.graph import InvestigationWorkflow

DECISIONS = ("ALLOW", "BLOCK", "REQUIRE_APPROVAL", "APPROVED", "REJECTED")
_BUCKETS = 24
_BUCKET_SECONDS = 3600


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["A", "B", "C", "D"]
    use_llm: bool = False  # False: deterministic fallback summary, no network, no key needed


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    limit: int = Field(default=200, ge=1, le=500)
    use_llm: bool = False


def build_router(
    *,
    auth: Callable[..., str],
    store: ApprovalStore,
    audit_store: AuditStore | None,
    alerts: AlertStore | None,
    view: Callable[[ApprovalRecord], dict[str, Any]],
    model_factory: Callable[[bool], ChatModel],
    clock: Callable[[], float],
) -> APIRouter:
    router = APIRouter(prefix="/api", dependencies=[Depends(auth)])
    sandbox_lock = asyncio.Lock()  # one simulation at a time keeps the server responsive

    def need_audit() -> AuditStore:
        if audit_store is None:
            raise HTTPException(status_code=503, detail="The audit store is not connected.")
        return audit_store

    @router.get("/session")
    def session(who: Annotated[str, Depends(auth)]) -> dict[str, Any]:
        return {"user": who, "role": "approver"}

    @router.get("/overview")
    def overview() -> dict[str, Any]:
        audit = need_audit()
        rows = audit.summary_rows()
        calls = [r for r in rows if r[4] != "tools/list"]
        decisions = Counter(r[1] for r in calls)
        reasons = Counter(r[2] for r in calls if r[1] != "ALLOW")
        per_agent: dict[str, Counter[str]] = defaultdict(Counter)
        for _, decision, _, agent, _, _ in calls:
            if agent:
                per_agent[agent]["total"] += 1
                per_agent[agent][decision] += 1
        end = max((r[0] for r in rows), default=clock())
        buckets = [
            {"t": end - (_BUCKETS - 1 - i) * _BUCKET_SECONDS, "allow": 0, "block": 0, "approval": 0}
            for i in range(_BUCKETS)
        ]
        start = buckets[0]["t"]
        for ts, decision, *_ in calls:
            if ts < start:
                continue
            index = min(int((ts - start) // _BUCKET_SECONDS), _BUCKETS - 1)
            key = {"ALLOW": "allow", "BLOCK": "block"}.get(decision, "approval")
            buckets[index][key] += 1
        head = audit.head()
        latest = next(
            (s.event.policy_version for s in audit.list_events(limit=50) if s.event.policy_version),
            None,
        )
        return {
            "totals": {
                "events": len(rows),
                "calls": len(calls),
                "allowed": decisions["ALLOW"],
                "blocked": decisions["BLOCK"],
                "needs_approval": decisions["REQUIRE_APPROVAL"],
            },
            "decisions": {d: decisions[d] for d in DECISIONS},
            "top_reasons": [{"reason": r, "count": n} for r, n in reasons.most_common(8)],
            "agents": sorted(
                (
                    {
                        "agent_id": a,
                        "total": c["total"],
                        "blocked": c["BLOCK"],
                        "needs_approval": c["REQUIRE_APPROVAL"],
                    }
                    for a, c in per_agent.items()
                ),
                key=lambda x: -x["total"],
            ),
            "timeline": buckets,
            "pending_approvals": len(store.list_pending()),
            "alerts": alerts.count() if alerts is not None else 0,
            "policy_version": latest,
            "head": {"last_seq": head.last_seq, "last_hash": head.last_hash, "count": head.count},
        }

    @router.get("/audit/events")
    def audit_events(
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        before_seq: Annotated[int | None, Query(ge=1)] = None,
        decision: Annotated[str | None, Query(pattern=r"^[A-Z_]{1,32}$")] = None,
        agent_id: Annotated[str | None, Query(max_length=64)] = None,
        method: Annotated[str | None, Query(pattern=r"^[a-z/]{1,32}$")] = None,
        search: Annotated[str | None, Query(max_length=64)] = None,
    ) -> dict[str, Any]:
        found = need_audit().list_events(
            limit=limit + 1,
            before_seq=before_seq,
            decision=decision,
            agent_id=agent_id,
            method=method,
            search=search,
        )
        page = found[:limit]
        return {
            "events": [event_view(s) for s in page],
            "next_before_seq": page[-1].seq if len(found) > limit and page else None,
        }

    @router.get("/audit/events/{seq}")
    def audit_event(seq: int) -> dict[str, Any]:
        audit = need_audit()
        found = audit.get_by_seq(seq)
        if found is None:
            raise HTTPException(status_code=404, detail="No such audit event.")
        same_call = audit.get_by_correlation(found.event.correlation_id)
        linked = [
            a
            for a in (alerts.list_recent(limit=500) if alerts is not None else [])
            if found.event.correlation_id in a["evidence"]
        ]
        return {
            "event": event_view(found),
            "same_call": [event_view(s) for s in same_call if s.seq != seq],
            "alerts": linked,
        }

    @router.get("/audit/verify")
    def audit_verify() -> dict[str, Any]:
        result = need_audit().verify()
        head = need_audit().head()
        return {
            "ok": result.ok,
            "checked": result.checked,
            "first_bad_seq": result.first_bad_seq,
            "reason": result.reason,
            "head_seq": head.last_seq,
            "head_hash": head.last_hash,
        }

    @router.get("/alerts")
    def list_alerts(limit: Annotated[int, Query(ge=1, le=200)] = 100) -> list[dict[str, Any]]:
        return alerts.list_recent(limit=limit) if alerts is not None else []

    @router.get("/approvals")
    def list_approvals(limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict[str, Any]]:
        return [view(a) for a in store.list_recent(limit)]

    @router.get("/simulations/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return scenario_catalog()

    @router.post("/simulations/run")
    async def simulate(body: SimulationRequest) -> dict[str, Any]:
        if body.scenario not in SCENARIO_IDS:  # the Literal already guards this
            raise HTTPException(status_code=404, detail="No such scenario.")
        async with sandbox_lock:
            try:
                return await run_scenario(body.scenario, model_factory(body.use_llm))
            except SimulationUnavailable as err:
                raise HTTPException(status_code=503, detail=str(err)) from None

    @router.post("/investigations")
    async def investigate(body: InvestigationRequest) -> dict[str, Any]:
        audit = need_audit()
        workflow = InvestigationWorkflow(AuditEvidence(audit, alerts), model_factory(body.use_llm))
        report = await workflow.run(agent_id=body.agent_id, limit=body.limit)
        return {"report": report.model_dump(), "markdown": report.to_markdown()}

    return router
