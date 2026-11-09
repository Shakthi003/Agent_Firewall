"""Hash-chained audit store (Stage 5): the tamper-evident record of every protected call.

Each stored record carries `prev_hash` (the previous record's hash) and `record_hash`
(SHA-256 over the previous hash, the record's sequence number and its canonical JSON). Editing
any field of a past record breaks its own hash; deleting or inserting a record breaks the link
or the sequence; so `verify()` fails. A one-row `audit_head` table holds the newest sequence
number, hash and count, which catches the case a chain alone cannot: records cut off the end.

What this protects against, and what it does not: it makes silent edits and deletions
*detectable* by anyone who runs `verify()`. It does not stop someone with full database write
access from rewriting the whole chain *and* the head row consistently; for that, copy
`head()` somewhere the database user cannot write (a later hardening step).

Writes are serialised by locking the head row (`SELECT ... FOR UPDATE` on PostgreSQL), so the
gateway and the approver API, which are separate processes, extend one chain without forks.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from dataclasses import asdict, dataclass, replace
from typing import Any

from sqlalchemy import BigInteger, Engine, Float, Integer, String, Text, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from core.db import Base
from gateway.mcp_gateway.audit import AuditEvent
from monitoring.audit.redact import sanitize_args

GENESIS_HASH = "0" * 64
_VERIFY_BATCH = 500


class AuditRow(Base):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    timestamp: Mapped[float] = mapped_column(Float(53), index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    method: Mapped[str] = mapped_column(String(32))
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision: Mapped[str] = mapped_column(String(32))
    reason_code: Mapped[str] = mapped_column(String(64))
    enforcement_action: Mapped[str] = mapped_column(String(32))
    anomaly_score: Mapped[float | None] = mapped_column(Float(53), nullable=True)
    event_json: Mapped[str] = mapped_column(Text)  # the whole event, canonical JSON
    prev_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64))


class AuditHeadRow(Base):
    __tablename__ = "audit_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # always 1
    last_seq: Mapped[int] = mapped_column(BigInteger)
    last_hash: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(BigInteger)


@dataclass(frozen=True)
class StoredEvent:
    seq: int
    prev_hash: str
    record_hash: str
    event: AuditEvent


@dataclass(frozen=True)
class AuditHead:
    last_seq: int
    last_hash: str
    count: int


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


def canonical_json(event: AuditEvent) -> str:
    return json.dumps(asdict(event), sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, seq: int, event_json: str) -> str:
    return hashlib.sha256(f"{prev_hash}|{seq}|{event_json}".encode()).hexdigest()


class AuditStore:
    """Implements the `AuditSink` protocol (`record`, `check`) on a hash-chained table."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._lock = threading.Lock()  # in-process; across processes the head-row lock does it

    def create_tables(self) -> None:
        Base.metadata.create_all(self._engine, tables=[AuditRow.__table__, AuditHeadRow.__table__])
        with Session(self._engine) as session:
            try:
                with session.begin():
                    if session.get(AuditHeadRow, 1) is None:
                        session.add(AuditHeadRow(id=1, last_seq=0, last_hash=GENESIS_HASH, count=0))
            except IntegrityError:
                pass  # another process created the head row first

    # ---- AuditSink

    def check(self) -> None:
        """Raises if the store cannot be written to right now."""
        with Session(self._engine) as session:
            session.execute(text("SELECT 1"))
            if session.get(AuditHeadRow, 1) is None:
                raise RuntimeError("the audit store is not initialised")

    def record(self, event: AuditEvent) -> StoredEvent:
        # Second line of defence: whatever the caller put in these fields is redacted again.
        event = replace(
            event,
            sanitized_args=sanitize_args(event.sanitized_args),
            extra=sanitize_args(event.extra),
        )
        event_json = canonical_json(event)
        with self._lock, Session(self._engine) as session, session.begin():
            head = session.execute(
                select(AuditHeadRow).where(AuditHeadRow.id == 1).with_for_update()
            ).scalar_one()
            seq = head.last_seq + 1
            prev_hash = head.last_hash
            record_hash = compute_hash(prev_hash, seq, event_json)
            session.add(
                AuditRow(
                    seq=seq,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    method=event.method,
                    agent_id=event.agent_id,
                    tool=event.tool,
                    decision=event.decision,
                    reason_code=event.reason_code,
                    enforcement_action=event.enforcement_action or "",
                    anomaly_score=event.anomaly_score,
                    event_json=event_json,
                    prev_hash=prev_hash,
                    record_hash=record_hash,
                )
            )
            head.last_seq = seq
            head.last_hash = record_hash
            head.count = head.count + 1
        return StoredEvent(seq, prev_hash, record_hash, event)

    # ---- reading

    def head(self) -> AuditHead:
        with Session(self._engine) as session:
            row = session.get(AuditHeadRow, 1)
            if row is None:
                raise RuntimeError("the audit store is not initialised")
            return AuditHead(row.last_seq, row.last_hash, row.count)

    def count(self) -> int:
        with Session(self._engine) as session:
            return session.scalar(select(func.count()).select_from(AuditRow)) or 0

    def events(
        self,
        *,
        after_seq: int = 0,
        limit: int | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> list[StoredEvent]:
        query = select(AuditRow).where(AuditRow.seq > after_seq).order_by(AuditRow.seq)
        if agent_id is not None:
            query = query.where(AuditRow.agent_id == agent_id)
        if correlation_id is not None:
            query = query.where(AuditRow.correlation_id == correlation_id)
        if limit is not None:
            query = query.limit(limit)
        with Session(self._engine) as session:
            return [_stored(row) for row in session.scalars(query)]

    def get_by_seq(self, seq: int) -> StoredEvent | None:
        with Session(self._engine) as session:
            row = session.get(AuditRow, seq)
            return _stored(row) if row is not None else None

    def get_by_correlation(self, correlation_id: str) -> list[StoredEvent]:
        return self.events(correlation_id=correlation_id)

    # ---- verification

    def _iter_rows(self) -> Iterator[AuditRow]:
        last = 0
        while True:
            with Session(self._engine) as session:
                batch = list(
                    session.scalars(
                        select(AuditRow)
                        .where(AuditRow.seq > last)
                        .order_by(AuditRow.seq)
                        .limit(_VERIFY_BATCH)
                    )
                )
            if not batch:
                return
            yield from batch
            last = batch[-1].seq

    def verify(self) -> VerifyResult:
        """Walk the whole chain. Detects an edited record, a deleted or inserted record, a
        reordered chain and records cut off the end."""
        prev_hash = GENESIS_HASH
        expected_seq = 1
        checked = 0
        for row in self._iter_rows():
            if row.seq != expected_seq:
                return VerifyResult(False, checked, expected_seq, "a record is missing")
            if row.prev_hash != prev_hash:
                return VerifyResult(
                    False, checked, row.seq, "the link to the previous record broke"
                )
            if compute_hash(row.prev_hash, row.seq, row.event_json) != row.record_hash:
                return VerifyResult(False, checked, row.seq, "the record was changed")
            mismatch = _column_mismatch(row)
            if mismatch is not None:
                return VerifyResult(False, checked, row.seq, mismatch)
            prev_hash = row.record_hash
            expected_seq += 1
            checked += 1
        head = self.head()
        if head.last_seq != checked or head.last_hash != prev_hash or head.count != checked:
            return VerifyResult(
                False, checked, checked + 1, "the log is shorter than, or differs from, its head"
            )
        return VerifyResult(True, checked)


def _stored(row: AuditRow) -> StoredEvent:
    return StoredEvent(
        row.seq, row.prev_hash, row.record_hash, AuditEvent.from_dict(json.loads(row.event_json))
    )


def _column_mismatch(row: AuditRow) -> str | None:
    """The indexed columns are copies of fields inside the hashed JSON; they must agree."""
    data: dict[str, Any] = json.loads(row.event_json)
    pairs = {
        "timestamp": row.timestamp,
        "correlation_id": row.correlation_id,
        "method": row.method,
        "agent_id": row.agent_id,
        "tool": row.tool,
        "decision": row.decision,
        "reason_code": row.reason_code,
        "enforcement_action": row.enforcement_action,
        "anomaly_score": row.anomaly_score,
    }
    for name, column in pairs.items():
        if data.get(name) != column:
            return f"column {name} no longer matches the record"
    return None
