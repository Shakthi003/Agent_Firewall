"""Start the gateway from settings (Stage 2).

    uv run python -m gateway.mcp_gateway                    # uses POSTGRES_* from .env
    uv run python -m gateway.mcp_gateway --database-url sqlite:///data/gateway.db

Start-up fails closed: if the registry file is bad, the database is unreachable, or an approved
tool is not offered by its downstream server, the gateway does not start.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

import uvicorn
from starlette.applications import Starlette

from core.config import Settings, get_settings
from core.db import make_engine
from gateway.identity.registry import AgentRegistry
from gateway.mcp_gateway.audit import LoggingAuditSink
from gateway.mcp_gateway.downstream import (
    Connector,
    Downstream,
    GatewayStartupError,
    http_connector,
    load_catalog,
)
from gateway.mcp_gateway.server import Gateway
from gateway.mcp_gateway.tools import RegistryError, ToolRegistry
from gateway.policy.decision import AllowAllPolicy


async def build_gateway(
    settings: Settings, *, database_url: str | None = None, connector: Connector | None = None
) -> Starlette:
    registry = AgentRegistry(make_engine(database_url or settings.database_url))
    registry.create_tables()
    downstream = Downstream(connector or http_connector(settings))
    tools = ToolRegistry.load()
    catalog = await load_catalog(tools, downstream)
    gateway = Gateway(
        registry=registry,
        tools=tools,
        catalog=catalog,
        downstream=downstream,
        policy=AllowAllPolicy(),  # Stage 3 replaces this with the YAML rule engine
        audit=LoggingAuditSink(),
        call_timeout=settings.gateway_call_timeout_seconds,
    )
    return gateway.build_app(host=settings.gateway_host)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent Firewall MCP gateway")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--database-url", default=None, help="override the PostgreSQL URL")
    args = parser.parse_args(argv)

    settings = get_settings()
    host = args.host or settings.gateway_host
    port = args.port or settings.gateway_port
    logging.basicConfig(level=logging.INFO)
    try:
        app = asyncio.run(build_gateway(settings, database_url=args.database_url))
    except (RegistryError, GatewayStartupError, RuntimeError) as exc:
        print(f"gateway not started: {exc}")
        return 1

    print("*** Gateway running with the Stage 2 allow-all policy: identity and registry only ***")
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
