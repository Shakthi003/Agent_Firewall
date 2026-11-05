"""Agent registry and API keys (Stage 2, identity).

How it works (see `docs/architecture.md` section 2):

- An admin registers an agent (ID, role). The registry makes a long random key and returns it
  ONCE. Only the SHA-256 hash of the key is stored, never the key itself.
- A SHA-256 hash is enough here (no slow password hash) because the key is 256 random bits,
  so there is nothing to guess. The hash is also what makes the lookup by key possible.
- `authenticate(token)` hashes the presented key, looks it up, and checks status and expiry.
  The result is an `Identity` built from the registry row, never from anything the agent sent.
- Rotation replaces the key and raises the key version; the old key stops working at once.
  Disabling an agent takes effect on the next request.
- The caller learns only "authenticated or not". The detailed failure (`AuthFailure`) is for
  the audit log.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, get_args

from sqlalchemy import BigInteger, Engine, Integer, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from core.db import Base

Role = Literal["finance", "it_ops", "developer"]
Status = Literal["active", "disabled"]
AuthFailure = Literal["missing", "malformed", "unknown", "expired", "disabled"]

ROLES: tuple[str, ...] = get_args(Role)
KEY_PREFIX = "afk_"
MAX_KEY_LENGTH = 128
DEFAULT_TTL_DAYS = 90
_AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
_SECONDS_PER_DAY = 86_400


class AgentRow(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    role: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    key_version: Mapped[int] = mapped_column(Integer)
    key_expires_at: Mapped[int] = mapped_column(BigInteger)  # unix seconds
    created_at: Mapped[int] = mapped_column(BigInteger)  # unix seconds


class AgentExistsError(Exception):
    """An agent with this ID is already registered."""


class UnknownAgentError(Exception):
    """No agent with this ID is registered."""


@dataclass(frozen=True)
class Identity:
    """Who is calling. Built only from a verified registry row."""

    agent_id: str
    role: Role
    key_version: int


@dataclass(frozen=True)
class AuthResult:
    identity: Identity | None = None
    failure: AuthFailure | None = None


@dataclass(frozen=True)
class IssuedKey:
    """A new key, returned once. `key` is the only copy; it is hidden from `repr`."""

    agent_id: str
    role: Role
    key_version: int
    expires_at: int
    key: str = field(repr=False)


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    role: Role
    status: Status
    key_version: int
    key_expires_at: int


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class AgentRegistry:
    def __init__(self, engine: Engine, *, clock: Callable[[], float] = time.time) -> None:
        self._engine = engine
        self._clock = clock

    def create_tables(self) -> None:
        Base.metadata.create_all(self._engine, tables=[AgentRow.__table__])

    # ---- admin

    def register_agent(
        self, agent_id: str, role: str, *, ttl_days: int = DEFAULT_TTL_DAYS
    ) -> IssuedKey:
        if not _AGENT_ID.match(agent_id):
            raise ValueError(f"Invalid agent id {agent_id!r}: use lowercase letters, digits, _ -")
        _check_role(role)
        key, expires_at = self._new_key(ttl_days)
        with Session(self._engine) as session, session.begin():
            if session.get(AgentRow, agent_id) is not None:
                raise AgentExistsError(f"Agent {agent_id} is already registered")
            session.add(
                AgentRow(
                    agent_id=agent_id,
                    role=role,
                    status="active",
                    key_hash=hash_key(key),
                    key_version=1,
                    key_expires_at=expires_at,
                    created_at=int(self._clock()),
                )
            )
        return IssuedKey(agent_id, role, 1, expires_at, key)  # type: ignore[arg-type]

    def rotate_key(self, agent_id: str, *, ttl_days: int = DEFAULT_TTL_DAYS) -> IssuedKey:
        """Replace the agent's key. The old key stops working immediately."""
        key, expires_at = self._new_key(ttl_days)
        with Session(self._engine) as session, session.begin():
            row = session.get(AgentRow, agent_id)
            if row is None:
                raise UnknownAgentError(f"Agent {agent_id} is not registered")
            row.key_hash = hash_key(key)
            row.key_version += 1
            row.key_expires_at = expires_at
            return IssuedKey(agent_id, row.role, row.key_version, expires_at, key)  # type: ignore[arg-type]

    def set_status(self, agent_id: str, status: Status) -> None:
        with Session(self._engine) as session, session.begin():
            row = session.get(AgentRow, agent_id)
            if row is None:
                raise UnknownAgentError(f"Agent {agent_id} is not registered")
            row.status = status

    def get_agent(self, agent_id: str) -> AgentRecord | None:
        with Session(self._engine) as session:
            row = session.get(AgentRow, agent_id)
            return _record(row) if row is not None else None

    def list_agents(self) -> list[AgentRecord]:
        with Session(self._engine) as session:
            rows = session.scalars(select(AgentRow).order_by(AgentRow.agent_id))
            return [_record(row) for row in rows]

    # ---- request time

    def authenticate(self, token: str | None) -> AuthResult:
        if not token:
            return AuthResult(failure="missing")
        if not token.startswith(KEY_PREFIX) or len(token) > MAX_KEY_LENGTH:
            return AuthResult(failure="malformed")
        with Session(self._engine) as session:
            row = session.scalar(select(AgentRow).where(AgentRow.key_hash == hash_key(token)))
        if row is None or row.role not in ROLES:
            return AuthResult(failure="unknown")
        if row.status != "active":
            return AuthResult(failure="disabled")
        if self._clock() >= row.key_expires_at:
            return AuthResult(failure="expired")
        return AuthResult(identity=Identity(row.agent_id, row.role, row.key_version))  # type: ignore[arg-type]

    # ---- helpers

    def _new_key(self, ttl_days: int) -> tuple[str, int]:
        if ttl_days < 1:
            raise ValueError("ttl_days must be at least 1")
        return generate_key(), int(self._clock()) + ttl_days * _SECONDS_PER_DAY


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"Unknown role {role!r}: expected one of {ROLES}")


def _record(row: AgentRow) -> AgentRecord:
    return AgentRecord(
        row.agent_id,
        row.role,  # type: ignore[arg-type]
        row.status,  # type: ignore[arg-type]
        row.key_version,
        row.key_expires_at,
    )
