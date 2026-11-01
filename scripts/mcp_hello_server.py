"""MCP hello-world server over Streamable HTTP (Stage 0 environment check).

Run:  uv run python -m scripts.mcp_hello_server
It exposes one tool, `hello`, at http://127.0.0.1:9100/mcp.
This is only a connectivity check, not part of the product.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("hello-world")


@server.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"hello, {name}"


if __name__ == "__main__":
    server.run("streamable-http", host="127.0.0.1", port=9100)
