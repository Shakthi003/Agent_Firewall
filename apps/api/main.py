"""Approver API (Stage 4): FastAPI endpoints for human approval of paused requests.

    GET  /approvals/pending              pending requests the approver can decide
    GET  /approvals/{approval_id}        one request
    POST /approvals/{approval_id}/approve
    POST /approvals/{approval_id}/reject

Only the single `approver` login (HTTP Basic, from `APPROVER_USERNAME` / `APPROVER_PASSWORD`)
may call these. An agent API key is a different kind of credential and is never accepted here.
Every decision, and every refused attempt, is written to the audit log with the approver's identity.

The approver sees the full request, because they have to judge it. The audit log does not: it
keeps the argument names and a hash only.
"""

# No `from __future__ import annotations` here: FastAPI reads the endpoint annotations at runtime,
# and the `Approver` alias below is local to `create_app`.
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from gateway.approvals.store import ApprovalError, ApprovalRecord, ApprovalStore
from gateway.mcp_gateway.audit import AuditEvent, AuditSink

APPROVER_DECIDED = "APPROVER_DECISION"
APPROVER_REFUSED = "APPROVER_REFUSED"
APPROVER_AUTH_FAILED = "APPROVER_AUTH_FAILED"

# Safe messages for the approver; the store's codes say what went wrong, not how to get round it.
_ERRORS: dict[str, tuple[int, str]] = {
    "NOT_FOUND": (404, "No such approval."),
    "NOT_PENDING": (409, "This approval was already decided."),
    "EXPIRED": (409, "This approval has expired."),
    "SELF_APPROVAL": (403, "You cannot decide a request you made yourself."),
}


def create_app(
    store: ApprovalStore,
    audit: AuditSink,
    *,
    username: str,
    password: str,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    if not username or not password:
        raise ValueError("The approver username and password must be set")
    app = FastAPI(title="Agent Firewall approvals", docs_url=None, redoc_url=None)
    basic = HTTPBasic(auto_error=False)

    def record(
        *,
        decision: str,
        reason: str,
        approver: str | None,
        approval: ApprovalRecord | None = None,
        approval_id: str | None = None,
        auth_failure: str | None = None,
    ) -> None:
        audit.record(
            AuditEvent(
                timestamp=clock(),
                correlation_id=uuid.uuid4().hex,
                method="approval/decide",
                decision=decision,
                reason_code=reason,
                agent_id=approval.requester_agent_id if approval else None,
                role=approval.requester_role if approval else None,
                auth_failure=auth_failure,
                tool=approval.tool if approval else None,
                server=approval.server if approval else None,
                policy_version=approval.policy_version if approval else None,
                args_hash=approval.args_hash if approval else None,
                approval_id=approval.approval_id if approval else approval_id,
                approver_id=approver,
            )
        )

    def approver(credentials: Annotated[HTTPBasicCredentials | None, Depends(basic)]) -> str:
        ok = credentials is not None and (
            secrets.compare_digest(credentials.username.encode(), username.encode())
            & secrets.compare_digest(credentials.password.encode(), password.encode())
        )
        if not ok:
            record(decision="BLOCK", reason=APPROVER_AUTH_FAILED, approver=None, auth_failure="bad")
            raise HTTPException(
                status_code=401,
                detail="Authentication failed.",
                headers={"WWW-Authenticate": "Basic"},
            )
        return username

    Approver = Annotated[str, Depends(approver)]

    @app.get("/approvals/pending")
    def list_pending(who: Approver) -> list[dict[str, Any]]:
        return [_view(a) for a in store.list_pending()]

    @app.get("/approvals/{approval_id}")
    def get_approval(approval_id: str, who: Approver) -> dict[str, Any]:
        found = store.get(approval_id)
        if found is None:
            raise HTTPException(status_code=404, detail=_ERRORS["NOT_FOUND"][1])
        return _view(found)

    def decide(approval_id: str, who: str, *, approve: bool) -> dict[str, Any]:
        try:
            decided = store.decide(approval_id, who, approve=approve)
        except ApprovalError as err:
            record(
                decision="BLOCK",
                reason=APPROVER_REFUSED,
                approver=who,
                approval=store.get(approval_id),
                approval_id=approval_id,
            )
            status, message = _ERRORS.get(err.code, (409, "The decision was refused."))
            raise HTTPException(status_code=status, detail=message) from None
        record(
            decision="APPROVED" if approve else "REJECTED",
            reason=APPROVER_DECIDED,
            approver=who,
            approval=decided,
        )
        return _view(decided)

    @app.post("/approvals/{approval_id}/approve")
    def approve(approval_id: str, who: Approver) -> dict[str, Any]:
        return decide(approval_id, who, approve=True)

    @app.post("/approvals/{approval_id}/reject")
    def reject(approval_id: str, who: Approver) -> dict[str, Any]:
        return decide(approval_id, who, approve=False)

    return app


def _view(a: ApprovalRecord) -> dict[str, Any]:
    view = asdict(a)
    view["args_hash"] = a.args_hash[:12]  # enough to recognise, not needed in full
    return view
