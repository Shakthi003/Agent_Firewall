"""The MCP Security Gateway (Stage 2).

An MCP server facing the agents and an MCP client facing the three downstream servers. A
standard MCP client works against it unmodified (`tools/list`, `tools/call`).

Every `tools/call` goes through the pipeline in `docs/architecture.md` section 3, and any
failed step ends the request:

    1. correlation ID          5. argument schema (P-004)
    2. identity (P-002)        6. policy decision (rate limit, then the YAML rules)
    3. tool registered (P-001) 7. forward downstream, with a timeout
    4. tool granted (P-003)    8. audit event, then return a result or a safe denial

Safe means: agents get a decision, a reason code and a correlation ID. They never get a stack
trace, a policy rule or a database error. Details go to the server-side log and the audit event.

Identity comes only from the verified credential (`gateway/identity/middleware.py`). Identity-like
fields in the payload (`agent_name` and similar) are ignored, removed before forwarding, and
logged as a spoofing attempt when they disagree with the credential.
"""

from __future__ import annotations

import json
import logging
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

from gateway.identity.middleware import IdentityMiddleware, auth_result
from gateway.identity.registry import AgentRegistry, AuthResult, Identity
from gateway.mcp_gateway.audit import AuditEvent, AuditSink, ExecutionStatus, hash_args
from gateway.mcp_gateway.downstream import CORRELATION_META_KEY, Downstream
from gateway.mcp_gateway.tools import ToolRegistry
from gateway.policy.decision import (
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
                )
            )

        def deny(reason: str, decision: Decision = "BLOCK") -> CallToolResult:
            finish(decision, reason)
            return _denial(decision, reason, cid)

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
            decision = self._policy.evaluate(identity, tool, clean_args)
            # Only a well-formed decision is acted on. Anything else is a policy fault.
            if not isinstance(decision, PolicyDecision) or decision.decision not in DECISIONS:
                raise TypeError("the policy engine returned something that is not a decision")
        except Exception:
            # Fail closed: a gateway or policy fault must never turn into a forwarded call.
            logger.exception("gateway pipeline failed before forwarding (correlation %s)", cid)
            return deny(POLICY_UNAVAILABLE)

        if decision.decision != "ALLOW":
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
            finish("ALLOW", decision.reason_code, status="timeout", policy_version=version)
            return _denial("ALLOW", DOWNSTREAM_TIMEOUT, cid)
        except Exception:
            logger.exception("downstream call failed (correlation %s, tool %s)", cid, tool)
            finish("ALLOW", decision.reason_code, status="error", policy_version=version)
            return _denial("ALLOW", DOWNSTREAM_ERROR, cid)

        status: ExecutionStatus = "tool_error" if result.is_error else "ok"
        finish("ALLOW", decision.reason_code, status=status, policy_version=version)
        meta = {**(result.meta or {}), CORRELATION_META_KEY: cid}
        return result.model_copy(update={"meta": meta})

    # ---- helpers

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


def _payload(decision: str, reason: str, correlation_id: str) -> dict[str, str]:
    return {
        "decision": decision,
        "reason_code": reason,
        "correlation_id": correlation_id,
        "message": _MESSAGES.get(reason, "The request was not run."),
    }


def _denial(decision: str, reason: str, correlation_id: str) -> CallToolResult:
    payload = _payload(decision, reason, correlation_id)
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
