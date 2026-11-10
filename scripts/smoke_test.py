"""Smoke test for a running stack (Stage 8, AC-53): one allowed call and one blocked call.

    docker compose --env-file .env -f infra/docker-compose.yml exec \
        -e FINANCE_AGENT_KEY=<key> agent python -m scripts.smoke_test

Run it from the `agent` container, which can only reach the gateway. It proves that the gateway
accepts the agent's key, lets a normal read through and refuses a request that is over the limit.
Exit code 0 means both happened as expected.
"""

from __future__ import annotations

import asyncio
import sys

from agents.business.gateway_client import agent_key, gateway_client
from core.config import get_settings


async def main() -> int:
    settings = get_settings()
    client = gateway_client(settings.gateway_url, agent_key("finance", settings))
    async with client:
        allowed = await client.call_tool("get_invoice", {"invoice_id": "INV-0005"})
        blocked = await client.call_tool("list_invoices", {"limit": 500})

    data = blocked.structured_content or {}
    print(f"allowed call : {'ran' if not allowed.is_error else 'REFUSED'}")
    print(f"over-limit   : {data.get('decision')} {data.get('reason_code')}")
    ok = not allowed.is_error and (data.get("decision"), data.get("reason_code")) == (
        "BLOCK",
        "ARG_LIMIT_EXCEEDED",
    )
    print("smoke test:", "passed" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
