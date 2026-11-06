"""The MCP Security Gateway (Stage 2, approvals added in Stage 4).

An MCP server facing the agents and an MCP client facing the three downstream servers. A
standard MCP client works against it unmodified (`tools/list`, `tools/call`).

Every `tools/call` goes through the pipeline in `docs/architecture.md` section 3, and any
failed step ends the request:

    1. correlation ID          5. argument schema (P-004)
    2. identity (P-002)        6. policy decision (rate limit, then the YAML rules)
    3. tool registered (P-001) 7. forward downstream, with a timeout
    4. tool granted (P-003)    8. audit event, then return a result or a safe denial

Approvals (Stage 4): on `REQUIRE_APPROVAL` the gateway stores the request and returns "pending"
with an approval ID. The agent retries the same call with that ID in the request's `_meta`
(`approval_id`). The policy is evaluated again first; only if it still says `REQUIRE_APPROVAL`
is the approval spent (once), and the stored request is what runs. Any failure is a denial.

Safe means: agents get a decision, a reason code and a correlation ID. They never get a stack
trace, a policy rule or a database error. Details go to the server-side log and the audit event.

Identity comes only from the verified credential (`gateway/identity/middleware.py`). Identity-like
fields in the payload (`agent_name` and similar) are ignored, removed before forwarding, and
logged as a spoofing attempt when they disagree with the credential.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any, get_args

from jsonschema import Draft202012Validator
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError
from mcp_types import (
    INVALID_REQUEST,
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)
from starlette.applications import Starlette

from gateway.approvals.store import ApprovalError, ApprovalStore, ErrorCode
from gateway.identity.middleware import IdentityMiddleware, auth_result
from gateway.identity.registry import AgentRegistry, AuthResult, Identity
from gateway.mcp_gateway.audit import AuditEvent, AuditSink, ExecutionStatus, hash_args
from gateway.mcp_gateway.downstream import CORRELATION_META_KEY, Downstream
from gateway.mcp_gateway.tools import ToolRegistry
from gateway.policy.decision import (
    APPROVAL_ALREADY_USED,
    APPROVAL_EXPIRED,
    APPROVAL_GRANTED,
    APPROVAL_INVALID,
    APPROVAL_MISMATCH,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    APPROVAL_REQUIRED,
    DOWNSTREAM_ERROR,
    DOWNSTREAM_TIMEOUT,
    INVALID_ARGUMENTS,
    POLICY_UNAVAILABLE,
    RATE_LIMIT_EXCEEDED,
    TOOL_NOT_GRANTED,
    UNKNOWN_TOOL,
    UNREGISTERED_AGENT,
    Decision,
    PolicyDecision,
    PolicyEngine,
)

logger = logging.getLogger(__name__)

GATEWAY_NAME = "agent-firewall-gateway"
DEFAULT_CALL_TIMEOUT_SECONDS = 30.0
DECISIONS = frozenset(get_args(Decision))
APPROVAL_META_KEY = "approval_id"
_APPROVAL_ID = re.compile(r"^[0-9a-f]{32}$")

# What a failed approval check means for the agent: (reason code, decision). A request that is
# merely not decided yet stays REQUIRE_APPROVAL so the agent keeps waiting; the rest are final.
_APPROVAL_FAILURES: dict[ErrorCode, tuple[str, Decision]] = {
    "PENDING": (APPROVAL_PENDING, "REQUIRE_APPROVAL"),
    "REJECTED": (APPROVAL_REJECTED, "BLOCK"),
    "EXPIRED": (APPROVAL_EXPIRED, "BLOCK"),
    "USED": (APPROVAL_ALREADY_USED, "BLOCK"),
    "MISMATCH": (APPROVAL_MISMATCH, "BLOCK"),
    "INVALID": (APPROVAL_INVALID, "BLOCK"),
    "NOT_FOUND": (APPROVAL_INVALID, "BLOCK"),
    "NOT_PENDING": (APPROVAL_INVALID, "BLOCK"),
    "SELF_APPROVAL": (APPROVAL_INVALID, "BLOCK"),
}

# Payload fields that claim an identity. They are never trusted.
IDENTITY_FIELDS = frozenset(
    {
        "agent_name",
        "agent_id",
        "agent",
        "role",
        "identity",
        "caller",
        "user",
        "user_id",
        "requested_by",
        "on_behalf_of",
    }
)

_MESSAGES = {
    UNREGISTERED_AGENT: "Authentication failed.",
    UNKNOWN_TOOL: "This tool is not in the approved tool registry.",
    TOOL_NOT_GRANTED: "This tool is not granted to your role.",
    INVALID_ARGUMENTS: "The arguments do not match the tool's input schema.",
    POLICY_UNAVAILABLE: "The request could not be checked, so it was not run.",
    RATE_LIMIT_EXCEEDED: "Too many requests. Wait and try again.",
    APPROVAL_REQUIRED: "This action needs human approval and was not run.",
    APPROVAL_PENDING: "Still waiting for a human decision. The action was not run.",
    APPROVAL_REJECTED: "A human rejected this action. It was not run.",
    APPROVAL_EXPIRED: "The approval expired. The action was not run.",
    APPROVAL_ALREADY_USED: "This approval was already used. The action was not run.",
    APPROVAL_MISMATCH: "The request does not match what was approved. It was not run.",
    APPROVAL_INVALID: "This approval is not valid for this request. It was not run.",
    DOWNSTREAM_TIMEOUT: "The tool took too long to answer.",
    DOWNSTREAM_ERROR: "The tool could not be reached.",
}


class Gateway:
    def __init__(
        self,
        *,
        registry: AgentRegistry,
        tools: ToolRegistry,
        catalog: Mapping[str, Tool],
        downstream: Downstream,
        policy: PolicyEngine,
        audit: AuditSink,
        approvals: ApprovalStore | None = None,
        call_timeout: float = DEFAULT_CALL_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        missing = tools.names() - catalog.keys()
        if missing:
            raise ValueError(f"The catalog has no definition for approved tools: {sorted(missing)}")
        self._registry = registry
        self._tools = tools
        self._catalog = dict(catalog)
        self._validators = {
            name: Draft202012Validator(_strict(tool.input_schema))
            for name, tool in self._catalog.items()
        }
        self._downstream = downstream
        self._policy = policy
        self._audit = audit
        self._approvals = approvals  # None: REQUIRE_APPROVAL is a plain denial, as in Stage 3
        self._call_timeout = call_timeout
        self._clock = clock

    # ---- assembly

    def build_server(self) -> Server[Any]:
        return Server(
            GATEWAY_NAME,
            on_list_tools=self._on_list_tools,
            on_call_tool=self._on_call_tool,
        )

    def build_app(self, *, host: str = "127.0.0.1") -> Starlette:
        """The ASGI app. Stateless: every request stands alone and carries its own credential."""
        app = self.build_server().streamable_http_app(
            stateless_http=True, json_response=True, host=host
        )
        app.add_middleware(IdentityMiddleware, registry=self._registry)
        return app

    # ---- tools/list

    async def _on_list_tools(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        started = time.perf_counter()
        cid = _new_correlation_id()
        auth = _auth_for(ctx)
        if auth.identity is None:
            self._record_list(cid, started, None, auth, "BLOCK", UNREGISTERED_AGENT, None)
            raise MCPError(
                code=INVALID_REQUEST,
                message=_MESSAGES[UNREGISTERED_AGENT],
                data=_payload("BLOCK", UNREGISTERED_AGENT, cid),
            )
        names = [n for n in self._tools.tools_for_role(auth.identity.role) if n in self._catalog]
        self._record_list(cid, started, auth.identity, auth, "ALLOW", "TOOLS_LISTED", len(names))
        return ListToolsResult(tools=[self._catalog[n] for n in names])

    def _record_list(
        self,
        cid: str,
        started: float,
        identity: Identity | None,
        auth: AuthResult,
        decision: str,
        reason: str,
        count: int | None,
    ) -> None:
        self._audit.record(
            AuditEvent(
                timestamp=self._clock(),
                correlation_id=cid,
                method="tools/list",
                decision=decision,
                reason_code=reason,
                agent_id=identity.agent_id if identity else None,
                role=identity.role if identity else None,
                key_version=identity.key_version if identity else None,
                auth_failure=auth.failure,
                latency_ms=_ms_since(started),
                tool_count=count,
            )
        )

    # ---- tools/call

    async def _on_call_tool(
        self, ctx: ServerRequestContext[Any], params: CallToolRequestParams
    ) -> CallToolResult:
        started = time.perf_counter()
        cid = _new_correlation_id()
        auth = _auth_for(ctx)
        identity = auth.identity
        tool = params.name
        args = params.arguments if isinstance(params.arguments, dict) else {}
        spoofed = _identity_fields(args, params.meta)
        entry = self._tools.get(tool)

        def finish(
            decision: str,
            reason: str,
            *,
            status: ExecutionStatus = "not_executed",
            policy_version: str | None = None,
            approval_id: str | None = None,
        ) -> None:
            self._audit.record(
                AuditEvent(
                    timestamp=self._clock(),
                    correlation_id=cid,
                    method="tools/call",
                    decision=decision,
                    reason_code=reason,
                    agent_id=identity.agent_id if identity else None,
                    role=identity.role if identity else None,
                    key_version=identity.key_version if identity else None,
                    auth_failure=auth.failure,
                    tool=tool if entry is not None else None,
                    server=entry.server if entry is not None else None,
                    policy_version=policy_version,
                    args_hash=hash_args(args),
                    arg_names=tuple(sorted(str(k) for k in args)),
                    spoofed_fields=tuple(sorted(spoofed)),
                    spoof_attempt=_is_spoof_attempt(spoofed, identity),
                    execution_status=status,
                    latency_ms=_ms_since(started),
                    approval_id=approval_id,
                )
            )

        def deny(reason: str, decision: Decision = "BLOCK") -> CallToolResult:
            finish(decision, reason)
            return _denial(decision, reason, cid)

        requested_approval: str | None = None
        try:
            if identity is None:
                return deny(UNREGISTERED_AGENT)
            if entry is None:
                return deny(UNKNOWN_TOOL)
            if not self._tools.is_granted(tool, identity.role):
                return deny(TOOL_NOT_GRANTED)
            # Identity claims are removed first (and were logged above); everything left must
            # match the tool's schema exactly, with no extra arguments.
            clean_args = self._without_identity_fields(tool, args)
            if not self._arguments_valid(tool, clean_args):
                return deny(INVALID_ARGUMENTS)
            raw_approval = (params.meta or {}).get(APPROVAL_META_KEY)
            if raw_approval is not None:
                if not isinstance(raw_approval, str) or not _APPROVAL_ID.match(raw_approval):
                    return deny(APPROVAL_INVALID)
                requested_approval = raw_approval
            decision = self._policy.evaluate(identity, tool, clean_args)
            # Only a well-formed decision is acted on. Anything else is a policy fault.
            if not isinstance(decision, PolicyDecision) or decision.decision not in DECISIONS:
                raise TypeError("the policy engine returned something that is not a decision")
        except Exception:
            # Fail closed: a gateway or policy fault must never turn into a forwarded call.
            logger.exception("gateway pipeline failed before forwarding (correlation %s)", cid)
            return deny(POLICY_UNAVAILABLE)

        approval_id: str | None = None
        if decision.decision == "REQUIRE_APPROVAL" and self._approvals is not None:
            version = decision.policy_version
            try:
                if requested_approval is None:
                    pending = self._approvals.create(
                        identity,
                        tool=tool,
                        server=entry.server,
                        args=clean_args,
                        reason_code=decision.reason_code,
                        policy_version=version,
                        correlation_id=cid,
                    )
                    finish(
                        "REQUIRE_APPROVAL",
                        decision.reason_code,
                        policy_version=version,
                        approval_id=pending.approval_id,
                    )
                    return _denial(
                        "REQUIRE_APPROVAL",
                        decision.reason_code,
                        cid,
                        approval_id=pending.approval_id,
                        expires_at=pending.expires_at,
                    )
                stored = self._approvals.consume(
                    requested_approval,
                    agent_id=identity.agent_id,
                    tool=tool,
                    args_hash=hash_args(clean_args),
                )
            except ApprovalError as err:
                reason, outcome = _APPROVAL_FAILURES[err.code]
                finish(outcome, reason, policy_version=version, approval_id=requested_approval)
                return _denial(outcome, reason, cid, approval_id=requested_approval)
            except Exception:
                logger.exception("approval handling failed (correlation %s)", cid)
                return deny(POLICY_UNAVAILABLE)
            # A valid approval: run exactly the request that was stored and approved.
            approval_id = stored.approval_id
            clean_args = stored.args
            decision = PolicyDecision("ALLOW", APPROVAL_GRANTED, version)
        elif decision.decision != "ALLOW":
            finish(decision.decision, decision.reason_code, policy_version=decision.policy_version)
            return _denial(decision.decision, decision.reason_code, cid)

        version = decision.policy_version
        try:
            result = await self._downstream.call_tool(
                entry.server,
                tool,
                clean_args,
                correlation_id=cid,
                timeout=self._call_timeout,
            )
        except TimeoutError:
            self._record_execution(approval_id, "timeout")
            finish(
                "ALLOW",
                decision.reason_code,
                status="timeout",
                policy_version=version,
                approval_id=approval_id,
            )
            return _denial("ALLOW", DOWNSTREAM_TIMEOUT, cid)
        except Exception:
            logger.exception("downstream call failed (correlation %s, tool %s)", cid, tool)
            self._record_execution(approval_id, "error")
            finish(
                "ALLOW",
                decision.reason_code,
                status="error",
                policy_version=version,
                approval_id=approval_id,
            )
            return _denial("ALLOW", DOWNSTREAM_ERROR, cid)

        status: ExecutionStatus = "tool_error" if result.is_error else "ok"
        self._record_execution(approval_id, status)
        finish(
            "ALLOW",
            decision.reason_code,
            status=status,
            policy_version=version,
            approval_id=approval_id,
        )
        meta = {**(result.meta or {}), CORRELATION_META_KEY: cid}
        return result.model_copy(update={"meta": meta})

    # ---- helpers

    def _record_execution(self, approval_id: str | None, status: str) -> None:
        if approval_id is None or self._approvals is None:
            return
        try:
            self._approvals.record_execution(approval_id, status)
        except Exception:
            logger.exception("could not record the execution result of approval %s", approval_id)

    def _arguments_valid(self, tool: str, args: dict[str, Any]) -> bool:
        return self._validators[tool].is_valid(args)

    def _without_identity_fields(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """Drop identity-like fields the tool does not itself declare."""
        declared = set(self._catalog[tool].input_schema.get("properties", {}))
        return {k: v for k, v in args.items() if k.lower() not in IDENTITY_FIELDS or k in declared}


# ---------------------------------------------------------------------- module helpers


def _strict(schema: Mapping[str, Any]) -> dict[str, Any]:
    """The tool's own input schema, closed: arguments the tool does not declare are invalid."""
    closed = dict(schema)
    closed.setdefault("additionalProperties", False)
    return closed


def _new_correlation_id() -> str:
    return uuid.uuid4().hex


def _ms_since(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def _auth_for(ctx: ServerRequestContext[Any]) -> AuthResult:
    """Verified identity for this request. No HTTP request (stdio, in-memory) means no identity."""
    request = ctx.request
    if request is None:
        return AuthResult(failure="missing")
    return auth_result(request.scope)


def _payload(
    decision: str, reason: str, correlation_id: str, **extra: str | int | None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "decision": decision,
        "reason_code": reason,
        "correlation_id": correlation_id,
        "message": _MESSAGES.get(reason, "The request was not run."),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    return payload


def _denial(
    decision: str, reason: str, correlation_id: str, **extra: str | int | None
) -> CallToolResult:
    payload = _payload(decision, reason, correlation_id, **extra)
    return CallToolResult(
        content=[TextContent(text=json.dumps(payload))],
        structured_content=payload,
        is_error=True,
        meta={CORRELATION_META_KEY: correlation_id},
    )


def _identity_fields(args: Mapping[str, Any], meta: Mapping[str, Any] | None) -> dict[str, Any]:
    """Identity-like fields the agent put in its payload (arguments or `_meta`)."""
    found: dict[str, Any] = {}
    for source in (args, meta or {}):
        for key, value in source.items():
            if str(key).lower() in IDENTITY_FIELDS:
                found[str(key)] = value
    return found


def _is_spoof_attempt(spoofed: Mapping[str, Any], identity: Identity | None) -> bool:
    """A claimed identity that is not the authenticated one. Without a credential, any claim is."""
    if not spoofed:
        return False
    if identity is None:
        return True
    genuine = {identity.agent_id.lower(), identity.role.lower()}
    return any(str(v).lower() not in genuine for v in spoofed.values())
