"""Approver API (Stage 4) and dashboard API (Stage 7): FastAPI.

    GET  /approvals/pending              pending requests the approver can decide
    GET  /approvals/{approval_id}        one request
    POST /approvals/{approval_id}/approve
    POST /approvals/{approval_id}/reject

Stage 7 adds the read endpoints under `/api` (see `dashboard.py`) and serves the built React
dashboard (`apps/dashboard/dist`) from `/` when it exists.

Only the single `approver` login (HTTP Basic, from `APPROVER_USERNAME` / `APPROVER_PASSWORD`)
may call these. An agent API key is a different kind of credential and is never accepted here.
Every decision, and every refused attempt, is written to the audit log with the approver's identity.

The approver sees the full request, because they have to judge it. The audit log does not: it
keeps the argument names and a hash only.

Errors (AC-48): every response carries `X-Request-ID`. Invalid input is a 422 and any unhandled
error is a 500; both bodies hold the request ID and a fixed message, never a stack trace.
"""

# No `from __future__ import annotations` here: FastAPI reads the endpoint annotations at runtime,
# and the `Approver` alias below is local to `create_app`.
import logging
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

from apps.api.dashboard import build_router
from apps.api.simulation import default_model_factory
from core.llm import ChatModel
from gateway.approvals.store import ApprovalError, ApprovalRecord, ApprovalStore
from gateway.mcp_gateway.audit import AuditEvent, AuditSink
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore

logger = logging.getLogger("agent_firewall.api")
DASHBOARD_DIST = Path(__file__).resolve().parents[1] / "dashboard" / "dist"

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
    audit_store: AuditStore | None = None,
    alerts: AlertStore | None = None,
    model_factory: Callable[[bool], ChatModel] = default_model_factory,
    dashboard_dir: Path | None = DASHBOARD_DIST,
) -> FastAPI:
    if not username or not password:
        raise ValueError("The approver username and password must be set")
    app = FastAPI(title="Agent Firewall approvals", docs_url=None, redoc_url=None)
    basic = HTTPBasic(auto_error=False)

    @app.middleware("http")
    async def request_id(request: Request, call_next: Callable[..., Any]) -> Any:
        request.state.request_id = uuid.uuid4().hex[:12]
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    def rid(request: Request) -> str:
        return getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [".".join(str(p) for p in e["loc"] if p != "body") for e in exc.errors()]
        return JSONResponse(
            status_code=422,
            content={
                "detail": "The request was not valid.",
                "fields": sorted(set(fields)),
                "request_id": rid(request),
            },
            headers={"X-Request-ID": rid(request)},
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        request_id = rid(request)
        logger.error("unhandled error (request %s)", request_id, exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Something went wrong.", "request_id": request_id},
            headers={"X-Request-ID": request_id},
        )

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

    def approver(
        request: Request, credentials: Annotated[HTTPBasicCredentials | None, Depends(basic)]
    ) -> str:
        ok = credentials is not None and (
            secrets.compare_digest(credentials.username.encode(), username.encode())
            & secrets.compare_digest(credentials.password.encode(), password.encode())
        )
        if not ok:
            record(decision="BLOCK", reason=APPROVER_AUTH_FAILED, approver=None, auth_failure="bad")
            # The dashboard has its own login form; asking for Basic would pop up the browser's.
            from_dashboard = request.headers.get("x-requested-with") == "dashboard"
            raise HTTPException(
                status_code=401,
                detail="Authentication failed.",
                headers=None if from_dashboard else {"WWW-Authenticate": "Basic"},
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

    app.include_router(
        build_router(
            auth=approver,
            store=store,
            audit_store=audit_store,
            alerts=alerts,
            view=_view,
            model_factory=model_factory,
            clock=clock,
        )
    )
    if dashboard_dir is not None and (dashboard_dir / "index.html").is_file():
        # Last, so it never shadows an API route. Plain files only; no directory listings.
        app.mount("/", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")

    return app


def _view(a: ApprovalRecord) -> dict[str, Any]:
    view = asdict(a)
    view["args_hash"] = a.args_hash[:12]  # enough to recognise, not needed in full
    return view
