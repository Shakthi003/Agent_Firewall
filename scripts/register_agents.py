"""Register the three business agents and print their API keys (Stage 2).

    uv run python -m scripts.register_agents --database-url sqlite:///data/gateway.db
    uv run python -m scripts.register_agents --rotate     # new keys for agents that exist

A key is shown ONCE, here. Only its hash is stored. Copy the printed lines into `.env`.
"""

from __future__ import annotations

import argparse
import sys

from core.config import get_settings
from core.db import make_engine
from gateway.identity.registry import AgentExistsError, AgentRegistry, IssuedKey

AGENTS: tuple[tuple[str, str, str], ...] = (
    ("finance-agent", "finance", "FINANCE_AGENT_KEY"),
    ("it-ops-agent", "it_ops", "IT_OPS_AGENT_KEY"),
    ("developer-agent", "developer", "DEVELOPER_AGENT_KEY"),
)


def register_all(registry: AgentRegistry, *, rotate: bool, ttl_days: int) -> dict[str, IssuedKey]:
    """Returns the issued keys by environment variable name. Existing agents are skipped unless
    `rotate` is set."""
    issued: dict[str, IssuedKey] = {}
    for agent_id, role, env_name in AGENTS:
        try:
            issued[env_name] = registry.register_agent(agent_id, role, ttl_days=ttl_days)
        except AgentExistsError:
            if rotate:
                issued[env_name] = registry.rotate_key(agent_id, ttl_days=ttl_days)
    return issued


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register the business agents.")
    parser.add_argument("--database-url", default=None, help="override the PostgreSQL URL")
    parser.add_argument("--rotate", action="store_true", help="re-key agents that already exist")
    args = parser.parse_args(argv)

    settings = get_settings()
    try:
        url = args.database_url or settings.database_url
    except RuntimeError as exc:
        print(exc)
        return 1
    registry = AgentRegistry(make_engine(url))
    registry.create_tables()

    issued = register_all(registry, rotate=args.rotate, ttl_days=settings.agent_key_ttl_days)
    if not issued:
        print("All agents already exist. Use --rotate to issue new keys.")
        return 0
    print("Copy these into .env. They are shown once and cannot be recovered:\n")
    for env_name, key in issued.items():
        print(f"{env_name}={key.key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
