"""Start the dashboard on throw-away demo data (Stage 7). For looking at the UI, nothing else.

    uv run python -m scripts.demo_dashboard            then open http://127.0.0.1:8000

It replays the documented attack scenarios and some normal traffic through the real in-process
gateway into a temporary SQLite database, leaves one approval pending, and serves the dashboard
and API on top of that. Login: user `approver`, password `demo-approver`. Nothing is written to
your real database, and the data is gone when the process stops.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

import uvicorn

from agents.business.scenarios import UNSAFE_CALLS
from apps.api.main import create_app
from core.db import make_engine
from gateway.approvals.store import ApprovalStore
from gateway.mcp_gateway.audit import FanOutAuditSink
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore
from scripts.run_investigation import NORMAL_CALL
from tests.gateway_harness import running_gateway
from tests.security.test_policy_enforcement import demo_run_registry

DEMO_USER = "approver"
DEMO_PASSWORD = "demo-approver"  # noqa: S105  # secret-scan: ignore


async def build(db_path: Path) -> tuple[ApprovalStore, AuditStore, AlertStore]:
    """Run traffic through the real gateway, then copy its database to `db_path`."""
    async with running_gateway(rules=True, tools=demo_run_registry()) as gw:
        assert gw.audit_store is not None and gw.alerts is not None and gw.approvals is not None
        for agent, (tool, args) in NORMAL_CALL.items():
            async with gw.client(gw.keys[agent].key) as client:
                for _ in range(4):
                    await client.call_tool(tool, args)
        for scenario in "ABCD":
            calls = [c for c in UNSAFE_CALLS if c.scenario == scenario]
            async with gw.client(gw.keys[calls[0].agent].key) as client:
                for call in calls:
                    await client.call_tool(call.tool, dict(call.args))
        source = gw.audit_store._engine  # the harness' in-memory SQLite engine
        target = make_engine(f"sqlite:///{db_path.as_posix()}")
        with source.raw_connection() as src, target.raw_connection() as dst:
            src.driver_connection.backup(dst.driver_connection)  # type: ignore[union-attr]
    store = ApprovalStore(target, expiry_seconds=3600)
    audit, alerts = AuditStore(target), AlertStore(target)
    return store, audit, alerts


def main() -> int:
    db = Path(tempfile.mkdtemp(prefix="af-demo-")) / "demo.db"
    store, audit, alerts = asyncio.run(build(db))
    app = create_app(
        store,
        FanOutAuditSink([audit]),
        username=DEMO_USER,
        password=DEMO_PASSWORD,  # secret-scan: ignore
        audit_store=audit,
        alerts=alerts,
    )
    print(f"Demo dashboard: http://127.0.0.1:8000   login {DEMO_USER} / {DEMO_PASSWORD}")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
