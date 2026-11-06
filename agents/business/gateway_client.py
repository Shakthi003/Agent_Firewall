"""How the business agents reach the gateway (Stage 2).

Agents no longer connect to the downstream servers. They hold one API key and talk to the
gateway through a standard MCP client; the key travels as `Authorization: Bearer <key>` on
every request. One gateway client serves every tool the agent may use, so the Developer Agent's
two "server" clients are simply the same connection.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import CallToolResult

from core.config import Settings

APPROVAL_META_KEY = "approval_id"  # must match gateway/mcp_gateway/server.py
DEFAULT_POLL_SECONDS = 2.0

KEY_SETTING = {
    "finance": "finance_agent_key",
    "it_ops": "it_ops_agent_key",
    "developer": "developer_agent_key",
}


def agent_key(agent: str, settings: Settings) -> str:
    """The agent's API key from settings. A missing key is an error, never a silent fallback."""
    secret = getattr(settings, KEY_SETTING[agent], None)
    value = secret.get_secret_value() if secret is not None else ""
    if not value:
        env = KEY_SETTING[agent].upper()
        raise RuntimeError(f"{env} is not set (run: uv run python -m scripts.register_agents)")
    return str(value)


def gateway_client(url: str, key: str, *, http: httpx.AsyncClient | None = None) -> Client:
    """A standard MCP client for the gateway. Enter it with `async with`."""
    http = http or httpx.AsyncClient(headers={"Authorization": f"Bearer {key}"})
    transport: Any = streamable_http_client(url, http_client=http)
    return Client(transport)


def pending_approval_id(result: CallToolResult) -> str | None:
    """The approval ID if the gateway paused this call and is waiting for a human, else None."""
    data = result.structured_content
    if not (result.is_error and isinstance(data, dict)):
        return None
    if data.get("decision") != "REQUIRE_APPROVAL":
        return None
    approval_id = data.get("approval_id")
    return approval_id if isinstance(approval_id, str) else None


async def call_tool_with_approval(
    client: Client,
    name: str,
    args: dict[str, Any],
    *,
    wait_seconds: float,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> CallToolResult:
    """Call a tool; if the gateway pauses it for approval, poll with the approval ID.

    Each retry is the same call with the same arguments plus the approval ID, so the gateway can
    check it is exactly what was approved. Returns the first result that is not "still waiting":
    the tool's result, or a final denial (rejected, expired, ...). With `wait_seconds` at 0 the
    call is made once and the "pending" answer is returned as it is.
    """
    result = await client.call_tool(name, args)
    approval_id = pending_approval_id(result)
    if approval_id is None:
        return result
    deadline = clock() + wait_seconds
    while clock() < deadline:
        await sleep(poll_seconds)
        result = await client.call_tool(name, args, meta={APPROVAL_META_KEY: approval_id})  # type: ignore[typeddict-unknown-key]
        data = result.structured_content
        if not (isinstance(data, dict) and data.get("reason_code") == "APPROVAL_PENDING"):
            return result
    return result
