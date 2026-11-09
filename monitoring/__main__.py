"""Audit and monitoring command line (Stage 5).

    uv run python -m monitoring verify [--database-url URL]   check the hash chain (1 if broken)
    uv run python -m monitoring alerts [--database-url URL]   list saved alerts
    uv run python -m monitoring evaluate                      rules vs model on simulated traffic

`verify` is the check behind AC-33/AC-34: it is safe to run at any time and never changes data.
"""

from __future__ import annotations

import argparse
import sys

from core.config import get_settings
from core.db import make_engine
from monitoring.audit.store import AuditStore
from monitoring.detection.alerts import AlertStore
from monitoring.detection.evaluate import evaluate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="monitoring", description="Agent Firewall audit tools")
    parser.add_argument("command", choices=("verify", "alerts", "evaluate"))
    parser.add_argument("--database-url", default=None)
    args = parser.parse_args(argv)

    if args.command == "evaluate":
        print(evaluate().as_text())
        return 0

    engine = make_engine(args.database_url or get_settings().database_url)
    if args.command == "verify":
        result = AuditStore(engine).verify()
        if result.ok:
            print(f"audit chain OK: {result.checked} records verified")
            return 0
        print(
            f"audit chain BROKEN at record {result.first_bad_seq}: {result.reason} "
            f"({result.checked} records verified before it)"
        )
        return 1

    for alert in AlertStore(engine).list_alerts():
        print(
            f"{alert.timestamp:.0f} {alert.severity:<8} {alert.rule:<17} "
            f"{alert.agent_id}: {alert.detail}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
