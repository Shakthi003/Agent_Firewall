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
from pathlib import Path

import uvicorn
from starlette.applications import Starlette

from core.config import Settings, get_settings
from core.db import make_engine
from core.logging_setup import configure_logging
from gateway.approvals.store import ApprovalStore
from gateway.identity.registry import AgentRegistry
from gateway.mcp_gateway.audit import FanOutAuditSink, LoggingAuditSink
from gateway.mcp_gateway.downstream import (
    Connector,
    Downstream,
    GatewayStartupError,
    http_connector,
    load_catalog,
)
from gateway.mcp_gateway.server import Gateway
from gateway.mcp_gateway.tools import RegistryError, ToolRegistry
from gateway.policy.engine import RuleEngine
from gateway.policy.policy_file import PolicyFileError, default_policy_path
from gateway.policy.rate_limit import TokenBucketRateLimiter
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore, MonitoredAuditSink
from monitoring.detection.rules import BehaviourMonitor


async def build_gateway(
    settings: Settings,
    *,
    database_url: str | None = None,
    connector: Connector | None = None,
    policy_path: Path | None = None,
) -> Starlette:
    engine = make_engine(database_url or settings.database_url)
    registry = AgentRegistry(engine)
    registry.create_tables()
    approvals = ApprovalStore(engine, expiry_seconds=settings.approval_expiry_minutes * 60)
    approvals.create_tables()
    # Stage 5: every event goes to the hash-chained PostgreSQL log (scored by the rule-based
    # monitor on the way in) and to the JSON log. The approver API writes to the same chain.
    audit_store = AuditStore(engine)
    audit_store.create_tables()
    alerts = AlertStore(engine)
    alerts.create_tables()
    audit = FanOutAuditSink(
        [MonitoredAuditSink(audit_store, alerts, BehaviourMonitor()), LoggingAuditSink()]
    )
    downstream = Downstream(connector or http_connector(settings))
    tools = ToolRegistry.load()
    catalog = await load_catalog(tools, downstream)
    policy = RuleEngine.from_file(
        policy_path or default_policy_path(settings.policy_dir),
        tool_arguments={n: set(t.input_schema.get("properties", {})) for n, t in catalog.items()},
        limiter=TokenBucketRateLimiter(
            settings.rate_limit_calls_per_minute, settings.rate_limit_burst
        ),
    )
    logging.getLogger(__name__).info("policy loaded, version %s", policy.version)
    gateway = Gateway(
        registry=registry,
        tools=tools,
        catalog=catalog,
        downstream=downstream,
        policy=policy,
        audit=audit,
        approvals=approvals,
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
    configure_logging()
    try:
        app = asyncio.run(build_gateway(settings, database_url=args.database_url))
    except (RegistryError, GatewayStartupError, PolicyFileError, RuntimeError) as exc:
        print(f"gateway not started: {exc}")
        return 1

    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
