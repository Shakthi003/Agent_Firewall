"""How the business agents reach the gateway (Stage 2).

Agents no longer connect to the downstream servers. They hold one API key and talk to the
gateway through a standard MCP client; the key travels as `Authorization: Bearer <key>` on
every request. One gateway client serves every tool the agent may use, so the Developer Agent's
two "server" clients are simply the same connection.
"""

from __future__ import annotations

from typing import Any

import httpx
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from core.config import Settings

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
