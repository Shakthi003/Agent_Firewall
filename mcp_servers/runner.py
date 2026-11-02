"""Shared start-up code for the three mock MCP servers (Stage 1).

Each server module provides a `create_server(seed)` function and calls `serve(...)`:
load the seed file through the schema (a bad file stops start-up with a clear message),
build the server, and run it over Streamable HTTP.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ValidationError

from core.seed_models import load_seed

SeedT = TypeVar("SeedT", bound=BaseModel)


def serve(
    *,
    description: str,
    model: type[SeedT],
    create_server: Callable[[SeedT], MCPServer],
    default_seed_file: Path,
    default_port: int,
    argv: list[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=description)
    # Loopback by default; the Docker setup passes --host 0.0.0.0 on the internal network.
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--seed-file", type=Path, default=default_seed_file)
    args = parser.parse_args(argv)

    try:
        seed = load_seed(model, args.seed_file)
    except FileNotFoundError:
        print(
            f"seed file not found: {args.seed_file} (run: uv run python -m scripts.generate_seed)"
        )
        return 1
    except ValidationError as exc:
        print(f"seed file {args.seed_file} is invalid:\n{exc}")
        return 1

    server = create_server(seed)
    server.run("streamable-http", host=args.host, port=args.port)
    return 0
