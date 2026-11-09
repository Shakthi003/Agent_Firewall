"""Start the approver API from settings (Stage 4).

    uv run python -m apps.api
    uv run python -m apps.api --database-url sqlite:///data/gateway.db

It must use the same database as the gateway, because that is where pending approvals live.
It does not start without `APPROVER_PASSWORD`.
"""

from __future__ import annotations

import argparse
import logging
import sys

import uvicorn

from apps.api.main import create_app
from core.config import get_settings
from core.db import make_engine
from gateway.approvals.store import ApprovalStore
from gateway.mcp_gateway.audit import FanOutAuditSink, LoggingAuditSink
from monitoring.audit.store import AuditStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent Firewall approver API")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--database-url", default=None, help="override the PostgreSQL URL")
    args = parser.parse_args(argv)

    settings = get_settings()
    password = settings.approver_password  # secret-scan: ignore
    if password is None or not password.get_secret_value():
        print("approver API not started: APPROVER_PASSWORD is not set (see .env.example)")
        return 1
    logging.basicConfig(level=logging.INFO)
    engine = make_engine(args.database_url or settings.database_url)
    store = ApprovalStore(engine, expiry_seconds=settings.approval_expiry_minutes * 60)
    store.create_tables()
    audit_store = AuditStore(engine)  # the gateway's hash chain: approvals are events in it too
    audit_store.create_tables()
    app = create_app(
        store,
        FanOutAuditSink([audit_store, LoggingAuditSink()]),
        username=settings.approver_username,
        password=password.get_secret_value(),  # secret-scan: ignore
    )
    uvicorn.run(app, host=args.host or settings.api_host, port=args.port or settings.api_port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
