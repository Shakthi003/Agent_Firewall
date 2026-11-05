"""The gateway's MCP client side: how it reaches the three downstream servers (Stage 2).

`Downstream` knows nothing about security. It lists a server's tools and forwards one call,
passing the correlation ID in the MCP request `_meta`. How a connection is made is injected:
real runs use Streamable HTTP on the internal network; tests use in-process servers.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

import anyio
import httpx
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import CallToolResult, Tool

from core.config import Settings
from gateway.mcp_gateway.tools import SERVERS, ToolRegistry

Connector = Callable[[str], AbstractAsyncContextManager[Client]]

CORRELATION_META_KEY = "correlation_id"
_CONNECT_TIMEOUT_SECONDS = 5.0


class GatewayStartupError(Exception):
    """The gateway cannot start safely (a registered tool is missing downstream, etc.)."""


class Downstream:
    def __init__(self, connect: Connector) -> None:
        self._connect = connect

    async def list_tools(self, server: str) -> list[Tool]:
        async with self._connect(server) as client:
            return list((await client.list_tools()).tools)

    async def call_tool(
        self,
        server: str,
        tool: str,
        args: dict[str, Any],
        *,
        correlation_id: str,
        timeout: float,
    ) -> CallToolResult:
        """Forward one call. Raises `TimeoutError` if it takes longer than `timeout` seconds."""
        with anyio.fail_after(timeout):
            async with self._connect(server) as client:
                return await client.call_tool(
                    tool, args, meta={CORRELATION_META_KEY: correlation_id}
                )


async def load_catalog(registry: ToolRegistry, downstream: Downstream) -> dict[str, Tool]:
    """Fetch the real tool definitions (including argument schemas) for every approved tool.

    Fails closed: if an approved tool is not offered by its server, the gateway must not start.
    Tools a server offers that are NOT in the registry are simply never exposed.
    """
    catalog: dict[str, Tool] = {}
    for server in SERVERS:
        wanted = set(registry.tools_for_server(server))
        if not wanted:
            continue
        try:
            offered = {t.name: t for t in await downstream.list_tools(server)}
        except Exception as exc:
            raise GatewayStartupError(
                f"Cannot reach the {server} server to read its tools: {type(exc).__name__}"
            ) from exc
        missing = sorted(wanted - offered.keys())
        if missing:
            raise GatewayStartupError(f"Server {server} does not offer approved tools: {missing}")
        catalog.update({name: offered[name] for name in wanted})
    return catalog


def http_connector(settings: Settings) -> Connector:
    """Connect to the downstream servers over Streamable HTTP (internal network)."""
    urls = {
        "company_data": settings.company_data_mcp_url,
        "operations": settings.operations_mcp_url,
        "developer_tools": settings.developer_tools_mcp_url,
    }

    @asynccontextmanager
    async def connect(server: str) -> Any:
        timeout = httpx.Timeout(
            settings.gateway_call_timeout_seconds, connect=_CONNECT_TIMEOUT_SECONDS
        )
        async with httpx.AsyncClient(timeout=timeout) as http:
            async with Client(streamable_http_client(urls[server], http_client=http)) as client:
                yield client

    return connect
