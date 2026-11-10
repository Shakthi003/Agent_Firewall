"""Persistent alerts and the sink that ties audit + monitoring together (Stage 5).

`MonitoredAuditSink` is what the gateway and approver API are given as their `AuditSink`:

    event -> BehaviourMonitor (anomaly_score) -> AuditStore (hash chain) -> AlertStore

The score is stamped onto the event BEFORE it is stored, so it sits in the hash-chained record.
Monitoring is best-effort and strictly secondary: if the monitor or the alert store fails, the
audit event is still written. Only a failure of the audit store itself is an audit failure.

Alerts are derived data (they can be recomputed from the audit log), so they are not chained.
Each one points at the correlation IDs of the audit events that caused it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import Any

from sqlalchemy import Engine, Float, Integer, String, Text, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from core.db import Base
from gateway.mcp_gateway.audit import AuditEvent
from monitoring.audit.store import AuditStore, StoredEvent
from monitoring.detection.rules import Alert, BehaviourMonitor

logger = logging.getLogger("agent_firewall.monitoring")


class AlertRow(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float(53), index=True)
    rule: Mapped[str] = mapped_column(String(32), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    score: Mapped[float] = mapped_column(Float(53))
    severity: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[str] = mapped_column(Text)  # correlation IDs of the audit events
    audit_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AlertStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def create_tables(self) -> None:
        Base.metadata.create_all(self._engine, tables=[AlertRow.__table__])

    def add(self, alert: Alert, *, audit_seq: int | None = None) -> None:
        with Session(self._engine) as session, session.begin():
            session.add(
                AlertRow(
                    timestamp=alert.timestamp,
                    rule=alert.rule,
                    agent_id=alert.agent_id,
                    score=alert.score,
                    severity=alert.severity,
                    detail=alert.detail,
                    evidence_json=json.dumps(list(alert.evidence)),
                    audit_seq=audit_seq,
                )
            )

    def list_recent(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Newest first, with the row ID and audit sequence, for the dashboard."""
        query = select(AlertRow).order_by(AlertRow.id.desc()).limit(limit)
        with Session(self._engine) as session:
            return [
                {
                    "id": row.id,
                    "timestamp": row.timestamp,
                    "rule": row.rule,
                    "agent_id": row.agent_id,
                    "score": row.score,
                    "severity": row.severity,
                    "detail": row.detail,
                    "evidence": json.loads(row.evidence_json),
                    "audit_seq": row.audit_seq,
                }
                for row in session.scalars(query)
            ]

    def count(self) -> int:
        with Session(self._engine) as session:
            return session.scalar(select(func.count()).select_from(AlertRow)) or 0

    def list_alerts(self, *, agent_id: str | None = None, rule: str | None = None) -> list[Alert]:
        query = select(AlertRow).order_by(AlertRow.id)
        if agent_id is not None:
            query = query.where(AlertRow.agent_id == agent_id)
        if rule is not None:
            query = query.where(AlertRow.rule == rule)
        with Session(self._engine) as session:
            return [
                Alert(
                    rule=row.rule,  # type: ignore[arg-type]
                    agent_id=row.agent_id,
                    timestamp=row.timestamp,
                    score=row.score,
                    severity=row.severity,  # type: ignore[arg-type]
                    detail=row.detail,
                    evidence=tuple(json.loads(row.evidence_json)),
                )
                for row in session.scalars(query)
            ]


class MonitoredAuditSink:
    """Implements `AuditSink`: scores, stores in the chain, then saves alerts."""

    def __init__(
        self,
        store: AuditStore,
        alerts: AlertStore | None = None,
        monitor: BehaviourMonitor | None = None,
    ) -> None:
        self.store = store
        self.alerts = alerts
        self._monitor = monitor

    def check(self) -> None:
        self.store.check()

    def record(self, event: AuditEvent) -> StoredEvent:
        found: tuple[Alert, ...] = ()
        if self._monitor is not None:
            try:
                result = self._monitor.observe(event)
                found = result.alerts
                event = replace(event, anomaly_score=result.score)
            except Exception:
                logger.exception("behaviour monitor failed; the event is still recorded")
        stored = self.store.record(event)  # an audit failure propagates: that one matters
        if self.alerts is not None:
            for alert in found:
                try:
                    self.alerts.add(alert, audit_seq=stored.seq)
                except Exception:
                    logger.exception("could not save an alert (rule %s)", alert.rule)
        return stored
