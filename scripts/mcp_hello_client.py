"""MCP hello-world client (Stage 0 environment check).

Connects over Streamable HTTP with a bearer token header, lists tools, calls `hello`.
Run the server first:  uv run python -m scripts.mcp_hello_server
Then:                  uv run python -m scripts.mcp_hello_client
"""

from __future__ import annotations

import asyncio
import sys

from mcp.client import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

URL = "http://127.0.0.1:9100/mcp"


async def main() -> int:
    http = create_mcp_http_client(headers={"Authorization": "Bearer demo-not-a-real-key"})
    # A Transport is the (not yet entered) context manager; Client enters it itself.
    transport = streamable_http_client(URL, http_client=http)
    async with Client(transport) as client:
        tools = await client.list_tools()
        names = [t.name for t in tools.tools]
        print("tools:", names)
        result = await client.call_tool("hello", {"name": "firewall"})
        text = result.content[0].text
        print("call hello ->", text)
        return 0 if names == ["hello"] and text == "hello, firewall" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
