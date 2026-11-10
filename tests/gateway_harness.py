"""In-process gateway test harness (Stage 2), shared by the integration and security tests.

`GatewayHarness` runs the real gateway app in-process with the three real mock MCP servers
behind it. `Downstream` is wrapped so every forwarded call is counted and kept, which lets
tests prove that a denied call never reached a downstream server.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
import httpx
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import CallToolResult
from starlette.applications import Starlette

from apps.api.main import create_app as create_approver_app
from core.db import make_engine
from core.seed_generator import generate_all
from gateway.approvals.store import ApprovalStore
from gateway.identity.registry import AgentRegistry, IssuedKey
from gateway.mcp_gateway.audit import AuditSink, FanOutAuditSink, InMemoryAuditSink
from gateway.mcp_gateway.downstream import Downstream, load_catalog
from gateway.mcp_gateway.server import Gateway
from gateway.mcp_gateway.tools import ToolRegistry
from gateway.policy.decision import AllowAllPolicy, PolicyEngine
from gateway.policy.engine import RuleEngine
from gateway.policy.policy_file import default_policy_path
from gateway.policy.rate_limit import TokenBucketRateLimiter
from mcp_servers.company_data.server import create_server as create_company_data
from mcp_servers.developer_tools.server import create_server as create_developer_tools
from mcp_servers.operations.server import create_server as create_operations
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore, MonitoredAuditSink
from monitoring.detection.rules import BehaviourMonitor

BASE_URL = "http://127.0.0.1:8080/mcp"
APPROVER_USER = "approver"
APPROVER_PASSWORD = "test-approver-password"  # noqa: S105  # secret-scan: ignore


@dataclass
class ForwardedCall:
    server: str
    tool: str
    args: dict[str, Any]
    correlation_id: str


class RecordingDownstream(Downstream):
    """The real `Downstream`, plus a record of every call that was forwarded."""

    def __init__(self, connect: Any) -> None:
        super().__init__(connect)
        self.calls: list[ForwardedCall] = []

    async def call_tool(
        self,
        server: str,
        tool: str,
        args: dict[str, Any],
        *,
        correlation_id: str,
        timeout: float,
    ) -> CallToolResult:
        self.calls.append(ForwardedCall(server, tool, dict(args), correlation_id))
        return await super().call_tool(
            server, tool, args, correlation_id=correlation_id, timeout=timeout
        )


@dataclass
class GatewayHarness:
    app: Starlette
    registry: AgentRegistry
    audit: InMemoryAuditSink
    downstream: RecordingDownstream
    keys: dict[str, IssuedKey] = field(default_factory=dict)
    # Seconds every downstream connection waits before it opens (to test the call timeout).
    delay: dict[str, float] = field(default_factory=lambda: {"seconds": 0.0})
    catalog: dict[str, Any] = field(default_factory=dict)  # tool name -> MCP Tool definition
    approvals: ApprovalStore | None = None
    audit_store: AuditStore | None = None  # the real hash-chained log, written alongside `audit`
    alerts: AlertStore | None = None
    # The approval clock: tests move it to expire approvals.
    now: dict[str, float] = field(default_factory=lambda: {"t": time.time()})

    def client(self, key: str | None) -> AbstractAsyncContextManager[Client]:
        """A standard MCP client talking to the gateway with this bearer key."""
        return client_for(self.app, key)

    def approver_api(self) -> Any:
        """A test client for the approver API, on the same store and audit log as the gateway."""
        from fastapi.testclient import TestClient

        assert self.approvals is not None and self.audit_store is not None
        api = create_approver_app(
            self.approvals,
            FanOutAuditSink([self.audit, self.audit_store]),
            username=APPROVER_USER,
            password=APPROVER_PASSWORD,  # secret-scan: ignore
            clock=lambda: self.now["t"],
        )
        client = TestClient(api)
        client.auth = (APPROVER_USER, APPROVER_PASSWORD)
        return client


def client_for(app: Starlette, key: str | None) -> AbstractAsyncContextManager[Client]:
    @asynccontextmanager
    async def connect() -> AsyncIterator[Client]:
        headers = {"Authorization": f"Bearer {key}"} if key is not None else {}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), headers=headers
        ) as http:
            async with Client(streamable_http_client(BASE_URL, http_client=http)) as client:
                yield client

    return connect()


@asynccontextmanager
async def running_gateway(
    *,
    policy: PolicyEngine | None = None,
    rules: bool = False,
    limiter: TokenBucketRateLimiter | None = None,
    call_timeout: float = 5.0,
    tools: ToolRegistry | None = None,
    expiry_seconds: int = 900,
    audit_override: AuditSink | None = None,
    monitor: BehaviourMonitor | None = None,
    database_url: str = "sqlite://",
) -> AsyncIterator[GatewayHarness]:
    """`rules=True` runs the real Stage 3 engine on `policies/policy.yaml`. The limiter defaults
    to a roomy one so that tests which make many calls do not trip the rate limit.

    `database_url` defaults to in-memory SQLite, which shares ONE connection between threads and
    so is only safe for calls made one after another. Tests that send calls in parallel must pass
    a file URL (each thread then gets its own connection, as with PostgreSQL)."""
    company, operations, developer = generate_all()
    servers = {
        "company_data": create_company_data(company),
        "operations": create_operations(operations),
        "developer_tools": create_developer_tools(developer),
    }

    delay: dict[str, float] = {"seconds": 0.0}

    @asynccontextmanager
    async def connect(server: str) -> AsyncIterator[Client]:
        if delay["seconds"]:
            await anyio.sleep(delay["seconds"])
        async with Client(servers[server]) as client:
            yield client

    downstream = RecordingDownstream(connect)
    tools = tools or ToolRegistry.load()
    catalog = await load_catalog(tools, downstream)

    engine = make_engine(database_url)
    registry = AgentRegistry(engine)
    registry.create_tables()
    now: dict[str, float] = {"t": time.time()}
    approvals = ApprovalStore(engine, expiry_seconds=expiry_seconds, clock=lambda: now["t"])
    approvals.create_tables()
    audit = InMemoryAuditSink()
    audit_store = AuditStore(engine)
    audit_store.create_tables()
    alerts = AlertStore(engine)
    alerts.create_tables()
    scored = MonitoredAuditSink(audit_store, alerts, monitor or BehaviourMonitor())
    sink = FanOutAuditSink([audit, scored])
    if rules and policy is None:
        policy = RuleEngine.from_file(
            default_policy_path("policies"),
            tool_arguments={
                n: set(t.input_schema.get("properties", {})) for n, t in catalog.items()
            },
            limiter=limiter or TokenBucketRateLimiter(6000, 1000),
        )
    gateway = Gateway(
        registry=registry,
        tools=tools,
        catalog=catalog,
        downstream=downstream,
        policy=policy or AllowAllPolicy(),
        audit=audit_override or sink,
        approvals=approvals,
        call_timeout=call_timeout,
    )
    app = gateway.build_app()
    keys = {
        "finance": registry.register_agent("finance-agent", "finance"),
        "it_ops": registry.register_agent("it-ops-agent", "it_ops"),
        "developer": registry.register_agent("developer-agent", "developer"),
    }
    # The SDK's session manager owns an anyio task group, which must be entered and exited in
    # the same task. A pytest async-generator fixture can't promise that, so one background task
    # owns the whole lifespan.
    ready, stop = asyncio.Event(), asyncio.Event()

    async def hold_lifespan() -> None:
        async with app.router.lifespan_context(app):
            ready.set()
            await stop.wait()

    holder = asyncio.create_task(hold_lifespan())
    await ready.wait()
    try:
        yield GatewayHarness(
            app,
            registry,
            audit,
            downstream,
            keys,
            delay,
            dict(catalog),
            approvals,
            audit_store,
            alerts,
            now,
        )
    finally:
        stop.set()
        await holder
