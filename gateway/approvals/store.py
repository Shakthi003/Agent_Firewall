"""Approval store (Stage 4): the pending requests behind `REQUIRE_APPROVAL`.

How it works (see `docs/architecture.md` section 6):

- When the policy says `REQUIRE_APPROVAL`, the gateway stores the exact request (tool, arguments,
  requester, policy reason and version) and gives the agent an approval ID. The stored request is
  never edited afterwards; only the status columns change.
- A human with the `approver` login approves or rejects it. The requester can never decide its own
  request.
- The agent retries with the approval ID. `consume` checks the request is the same one (same
  agent, same tool, same argument hash), that it is approved and not expired, and marks it used
  in one atomic update, so an approval can be spent exactly once even under concurrent retries.
- Expiry is derived from the clock (default 15 minutes after creation), so an old approval cannot
  be used even if nobody ever touched the row again.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import BigInteger, Engine, String, Text, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from core.db import Base
from gateway.identity.registry import Identity
from gateway.mcp_gateway.audit import hash_args

ApprovalStatus = Literal["pending", "approved", "rejected", "used", "expired"]
ErrorCode = Literal[
    "NOT_FOUND",  # no such approval (decide)
    "NOT_PENDING",  # already decided (decide): a replayed approve or reject
    "EXPIRED",
    "SELF_APPROVAL",  # the decider is the requester (decide)
    "INVALID",  # no such approval, or it belongs to another agent (consume)
    "MISMATCH",  # a different tool or different arguments (consume)
    "PENDING",  # not decided yet (consume)
    "REJECTED",
    "USED",
]

DEFAULT_EXPIRY_SECONDS = 15 * 60


class ApprovalRow(Base):
    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    requester_agent_id: Mapped[str] = mapped_column(String(64), index=True)
    requester_role: Mapped[str] = mapped_column(String(32))
    tool: Mapped[str] = mapped_column(String(64))
    server: Mapped[str] = mapped_column(String(64))
    args_json: Mapped[str] = mapped_column(Text)  # the exact request; never updated
    args_hash: Mapped[str] = mapped_column(String(64))
    policy_reason: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # pending | approved | rejected | used
    created_at: Mapped[int] = mapped_column(BigInteger)  # unix seconds
    expires_at: Mapped[int] = mapped_column(BigInteger)
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    used_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    execution_status: Mapped[str | None] = mapped_column(String(16), nullable=True)


class ApprovalError(Exception):
    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code)
        self.code: ErrorCode = code


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    requester_agent_id: str
    requester_role: str
    tool: str
    server: str
    args: dict[str, Any]
    args_hash: str
    policy_reason: str
    policy_version: str
    correlation_id: str
    status: ApprovalStatus  # "expired" is derived from the clock
    created_at: int
    expires_at: int
    decided_by: str | None
    decided_at: int | None
    used_at: int | None
    execution_status: str | None


class ApprovalStore:
    def __init__(
        self,
        engine: Engine,
        *,
        expiry_seconds: int = DEFAULT_EXPIRY_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if expiry_seconds < 1:
            raise ValueError("expiry_seconds must be at least 1")
        self._engine = engine
        self._expiry = expiry_seconds
        self._clock = clock

    def create_tables(self) -> None:
        Base.metadata.create_all(self._engine, tables=[ApprovalRow.__table__])

    # ---- gateway side

    def create(
        self,
        identity: Identity,
        *,
        tool: str,
        server: str,
        args: dict[str, Any],
        reason_code: str,
        policy_version: str,
        correlation_id: str,
    ) -> ApprovalRecord:
        """Store a pending request. The same agent repeating the same pending request gets the
        same approval back, so an agent that asks again does not flood the approver."""
        now = int(self._clock())
        args_hash = hash_args(args)
        with Session(self._engine) as session, session.begin():
            existing = session.scalar(
                select(ApprovalRow).where(
                    ApprovalRow.requester_agent_id == identity.agent_id,
                    ApprovalRow.tool == tool,
                    ApprovalRow.args_hash == args_hash,
                    ApprovalRow.status == "pending",
                    ApprovalRow.expires_at > now,
                )
            )
            if existing is not None:
                return _record(existing, now)
            row = ApprovalRow(
                approval_id=uuid.uuid4().hex,
                requester_agent_id=identity.agent_id,
                requester_role=identity.role,
                tool=tool,
                server=server,
                args_json=json.dumps(args, sort_keys=True, default=str),
                args_hash=args_hash,
                policy_reason=reason_code,
                policy_version=policy_version,
                correlation_id=correlation_id,
                status="pending",
                created_at=now,
                expires_at=now + self._expiry,
            )
            session.add(row)
            return _record(row, now)

    def consume(
        self, approval_id: str, *, agent_id: str, tool: str, args_hash: str
    ) -> ApprovalRecord:
        """Spend an approval. Returns the stored request, or raises `ApprovalError`.

        The status change from approved to used is one conditional UPDATE, so two concurrent
        retries cannot both win."""
        now = int(self._clock())
        with Session(self._engine) as session, session.begin():
            row = session.get(ApprovalRow, approval_id)
            if row is None or row.requester_agent_id != agent_id:
                raise ApprovalError("INVALID")
            if row.tool != tool or row.args_hash != args_hash:
                raise ApprovalError("MISMATCH")
            if row.status == "rejected":
                raise ApprovalError("REJECTED")
            if row.status == "used":
                raise ApprovalError("USED")
            if now >= row.expires_at:
                raise ApprovalError("EXPIRED")
            if row.status == "pending":
                raise ApprovalError("PENDING")
            spent = session.execute(
                update(ApprovalRow)
                .where(ApprovalRow.approval_id == approval_id, ApprovalRow.status == "approved")
                .values(status="used", used_at=now)
            )
            if spent.rowcount != 1:
                raise ApprovalError("USED")
            session.refresh(row)
            return _record(row, now)

    def record_execution(self, approval_id: str, execution_status: str) -> None:
        with Session(self._engine) as session, session.begin():
            session.execute(
                update(ApprovalRow)
                .where(ApprovalRow.approval_id == approval_id)
                .values(execution_status=execution_status)
            )

    # ---- approver side

    def get(self, approval_id: str) -> ApprovalRecord | None:
        now = int(self._clock())
        with Session(self._engine) as session:
            row = session.get(ApprovalRow, approval_id)
            return _record(row, now) if row is not None else None

    def list_recent(self, limit: int = 50) -> list[ApprovalRecord]:
        """Every approval, newest first (pending, decided, used and expired), for the dashboard."""
        now = int(self._clock())
        with Session(self._engine) as session:
            rows = session.scalars(
                select(ApprovalRow).order_by(ApprovalRow.created_at.desc()).limit(limit)
            )
            return [_record(row, now) for row in rows]

    def list_pending(self) -> list[ApprovalRecord]:
        now = int(self._clock())
        with Session(self._engine) as session:
            rows = session.scalars(
                select(ApprovalRow)
                .where(ApprovalRow.status == "pending", ApprovalRow.expires_at > now)
                .order_by(ApprovalRow.created_at)
            )
            return [_record(row, now) for row in rows]

    def decide(self, approval_id: str, approver_id: str, *, approve: bool) -> ApprovalRecord:
        """Approve or reject a pending request. Raises `ApprovalError` for anything else."""
        now = int(self._clock())
        with Session(self._engine) as session, session.begin():
            row = session.get(ApprovalRow, approval_id)
            if row is None:
                raise ApprovalError("NOT_FOUND")
            if approver_id == row.requester_agent_id:
                raise ApprovalError("SELF_APPROVAL")
            if row.status != "pending":
                raise ApprovalError("NOT_PENDING")
            if now >= row.expires_at:
                raise ApprovalError("EXPIRED")
            decided = session.execute(
                update(ApprovalRow)
                .where(ApprovalRow.approval_id == approval_id, ApprovalRow.status == "pending")
                .values(
                    status="approved" if approve else "rejected",
                    decided_by=approver_id,
                    decided_at=now,
                )
            )
            if decided.rowcount != 1:
                raise ApprovalError("NOT_PENDING")
            session.refresh(row)
            return _record(row, now)


def _record(row: ApprovalRow, now: int) -> ApprovalRecord:
    status = row.status
    if status in ("pending", "approved") and now >= row.expires_at:
        status = "expired"
    return ApprovalRecord(
        approval_id=row.approval_id,
        requester_agent_id=row.requester_agent_id,
        requester_role=row.requester_role,
        tool=row.tool,
        server=row.server,
        args=json.loads(row.args_json),
        args_hash=row.args_hash,
        policy_reason=row.policy_reason,
        policy_version=row.policy_version,
        correlation_id=row.correlation_id,
        status=status,  # type: ignore[arg-type]
        created_at=row.created_at,
        expires_at=row.expires_at,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
        used_at=row.used_at,
        execution_status=row.execution_status,
    )
