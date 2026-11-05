"""Database helpers shared by the gateway modules (Stage 2).

One declarative `Base` for every table, and one place that builds the engine. PostgreSQL is the
real target; SQLite is accepted so tests and local runs need no server.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

IN_MEMORY_SQLITE = ("sqlite://", "sqlite:///:memory:")


class Base(DeclarativeBase):
    pass


def make_engine(url: str) -> Engine:
    """Build an engine. The gateway calls the database from worker threads, so SQLite is told
    that is fine; an in-memory SQLite database lives in one shared connection."""
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)
    kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
    if url in IN_MEMORY_SQLITE:
        kwargs["poolclass"] = StaticPool
    return create_engine(url, **kwargs)
