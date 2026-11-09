"""Stage 5 unit tests: redaction (AC-32) and the hash-chained store (AC-33, AC-34, AC-35)."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest
from sqlalchemy import text

from core.db import make_engine
from gateway.mcp_gateway.audit import AuditEvent, enforcement_for
from monitoring.audit.redact import REDACTED, REDACTED_KEY, sanitize_args
from monitoring.audit.store import (
    GENESIS_HASH,
    AuditRow,
    AuditStore,
    canonical_json,
    compute_hash,
)

# Obviously fake canaries: if any of these appears in stored data, redaction failed.
CANARY_KEY = "afk_CANARYKEY0123456789abcdefghijklmnop"
CANARY_PASSWORD = "canary-password-123"  # noqa: S105  # secret-scan: ignore
CANARY_ACCOUNT = "123456789012"
CANARY_TOKEN = "canary-token-xyz"  # noqa: S105  # secret-scan: ignore


# ------------------------------------------------------------------ AC-32: redaction


def test_secret_named_fields_are_redacted() -> None:
    out = sanitize_args(
        {"password": CANARY_PASSWORD, "api_token": CANARY_TOKEN, "SECRET": "x", "signing_key": "k"}
    )
    assert set(out.values()) == {REDACTED}


def test_account_numbers_keep_only_the_last_four_digits() -> None:
    assert sanitize_args({"account_number": CANARY_ACCOUNT}) == {"account_number": "****9012"}
    assert sanitize_args({"account_number": 99887766}) == {"account_number": "****7766"}
    assert sanitize_args({"iban": "GB82WEST12345698765432"}) == {"iban": "****5432"}


def test_key_like_strings_are_redacted_wherever_they_appear() -> None:
    out = sanitize_args(
        {"note": f"use {CANARY_KEY} please", "header": "Bearer abc.def.ghi", "other": 1}
    )
    assert CANARY_KEY not in json.dumps(out)
    assert REDACTED_KEY in out["note"]
    assert "abc.def.ghi" not in out["header"]


def test_long_digit_strings_are_shortened_even_in_innocent_fields() -> None:
    out = sanitize_args({"reference": f"payment to {CANARY_ACCOUNT}"})
    assert CANARY_ACCOUNT not in json.dumps(out)
    assert out["reference"].endswith("****9012")


def test_long_free_text_is_replaced_by_its_length() -> None:
    out = sanitize_args({"comment": "word " * 40})
    assert out["comment"] == "[text:200 chars]"


def test_ids_limits_and_amounts_survive_because_detections_need_them() -> None:
    args = {"invoice_id": "INV-0005", "limit": 5000, "amount": 12.5, "env": "prod", "ok": True}
    assert sanitize_args(args) == args


def test_nested_values_are_redacted_too() -> None:
    out = sanitize_args(
        {"outer": {"password": CANARY_PASSWORD, "items": [{"token": CANARY_TOKEN}]}}
    )
    assert CANARY_PASSWORD not in json.dumps(out)
    assert CANARY_TOKEN not in json.dumps(out)


def test_secret_named_fields_are_redacted_at_any_depth() -> None:
    deep: dict[str, Any] = {"a": {"b": {"c": {"password": CANARY_PASSWORD}}}}
    assert CANARY_PASSWORD not in json.dumps(sanitize_args(deep))


def test_structures_nested_past_the_limit_are_cut_off() -> None:
    deep: dict[str, Any] = {"a": {"b": {"c": {"d": {"e": CANARY_PASSWORD}}}}}
    out = sanitize_args(deep)
    assert CANARY_PASSWORD not in json.dumps(out)
    assert "[nested]" in json.dumps(out)


def test_redaction_is_idempotent() -> None:
    once = sanitize_args(
        {"account_number": CANARY_ACCOUNT, "password": "p", "note": f"{CANARY_KEY} " + "x" * 80}
    )
    assert sanitize_args(once) == once


# ------------------------------------------------------------------ the chain


def event(n: int, **kw: Any) -> AuditEvent:
    base: dict[str, Any] = {
        "timestamp": 1_700_000_000.0 + n,
        "correlation_id": f"c{n:04d}",
        "method": "tools/call",
        "decision": "ALLOW",
        "reason_code": "ALLOWED_BY_POLICY",
        "agent_id": "finance-agent",
        "role": "finance",
        "tool": "get_invoice",
        "sanitized_args": {"invoice_id": f"INV-{n:04d}"},
    }
    base.update(kw)
    return AuditEvent(**base)


@pytest.fixture
def store() -> AuditStore:
    s = AuditStore(make_engine("sqlite://"))
    s.create_tables()
    return s


def filled(store: AuditStore, n: int = 10) -> AuditStore:
    for i in range(1, n + 1):
        store.record(event(i))
    return store


def test_an_empty_log_verifies(store: AuditStore) -> None:
    result = store.verify()
    assert result.ok and result.checked == 0
    assert store.head().last_hash == GENESIS_HASH


def test_each_record_stores_the_previous_records_hash(store: AuditStore) -> None:
    first, second, third = (store.record(event(i)) for i in (1, 2, 3))
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.record_hash
    assert third.prev_hash == second.record_hash
    assert first.record_hash == compute_hash(GENESIS_HASH, 1, canonical_json(first.event))
    assert store.head().last_hash == third.record_hash


def test_an_untouched_log_verifies(store: AuditStore) -> None:
    result = filled(store, 25).verify()
    assert result.ok
    assert result.checked == 25
    assert store.head().count == 25


def test_stored_events_round_trip(store: AuditStore) -> None:
    original = event(1, arg_names=("invoice_id",), spoofed_fields=("agent_name",))
    store.record(original)
    assert store.events()[0].event == original


def test_the_store_redacts_again_as_a_second_line_of_defence(store: AuditStore) -> None:
    store.record(
        event(1, sanitized_args={"password": CANARY_PASSWORD, "account_number": CANARY_ACCOUNT})
    )
    assert store.events()[0].event.sanitized_args == {
        "password": REDACTED,
        "account_number": "****9012",
    }
    assert store.verify().ok


def test_two_stores_on_one_database_extend_one_chain() -> None:
    """The gateway and the approver API are separate processes with their own `AuditStore`."""
    engine = make_engine("sqlite://")
    a, b = AuditStore(engine), AuditStore(engine)
    a.create_tables()
    b.create_tables()  # must not reset the head
    a.record(event(1))
    b.record(event(2))
    a.record(event(3))
    assert a.verify().ok and b.verify().ok
    assert b.head().count == 3


def test_check_passes_on_a_working_store(store: AuditStore) -> None:
    store.check()


def test_check_fails_when_the_store_is_not_initialised() -> None:
    with pytest.raises(Exception):  # noqa: B017, PT011  # tables missing or head missing
        AuditStore(make_engine("sqlite://")).check()


# ------------------------------------------------------------------ AC-34: tamper tests


def tamper(store: AuditStore, sql: str, **params: object) -> None:
    with store._engine.begin() as conn:  # noqa: SLF001  # the attacker's direct DB access
        conn.execute(text(sql), params)


def test_editing_a_past_record_is_detected(store: AuditStore) -> None:
    filled(store)
    row = store.get_by_seq(4)
    assert row is not None
    forged = replace(row.event, reason_code="FORGED")
    tamper(store, "UPDATE audit_events SET event_json = :j WHERE seq = 4", j=canonical_json(forged))
    result = store.verify()
    assert not result.ok
    assert result.first_bad_seq == 4
    assert result.reason == "the record was changed"


def test_editing_an_indexed_column_alone_is_detected(store: AuditStore) -> None:
    filled(store)
    tamper(store, "UPDATE audit_events SET decision = 'BLOCK', reason_code = 'X' WHERE seq = 6")
    result = store.verify()
    assert not result.ok and result.first_bad_seq == 6


def test_a_recomputed_record_hash_still_breaks_the_next_link(store: AuditStore) -> None:
    filled(store)
    row = store.get_by_seq(5)
    assert row is not None
    forged = canonical_json(replace(row.event, reason_code="FORGED"))
    tamper(
        store,
        "UPDATE audit_events SET event_json = :j, reason_code = 'FORGED', record_hash = :h "
        "WHERE seq = 5",
        j=forged,
        h=compute_hash(row.prev_hash, 5, forged),
    )
    result = store.verify()
    assert not result.ok
    assert result.first_bad_seq == 6
    assert result.reason == "the link to the previous record broke"


def test_deleting_a_record_in_the_middle_is_detected(store: AuditStore) -> None:
    filled(store)
    tamper(store, "DELETE FROM audit_events WHERE seq = 5")
    result = store.verify()
    assert not result.ok and result.first_bad_seq == 5
    assert result.reason == "a record is missing"


def test_deleting_the_first_record_is_detected(store: AuditStore) -> None:
    filled(store)
    tamper(store, "DELETE FROM audit_events WHERE seq = 1")
    assert not store.verify().ok


def test_deleting_the_newest_records_is_detected_by_the_head(store: AuditStore) -> None:
    filled(store)
    tamper(store, "DELETE FROM audit_events WHERE seq > 7")
    result = store.verify()
    assert not result.ok
    assert result.checked == 7
    assert "head" in (result.reason or "")


def test_inserting_a_forged_record_is_detected(store: AuditStore) -> None:
    filled(store)
    last = store.get_by_seq(10)
    assert last is not None
    forged = canonical_json(event(99, reason_code="FORGED"))
    tamper(
        store,
        "INSERT INTO audit_events (seq, timestamp, correlation_id, method, agent_id, tool, "
        "decision, reason_code, enforcement_action, anomaly_score, event_json, prev_hash, "
        "record_hash) VALUES (11, 1, 'c99', 'tools/call', 'finance-agent', 'get_invoice', "
        "'ALLOW', 'FORGED', 'forwarded', NULL, :j, :p, :h)",
        j=forged,
        p=last.record_hash,
        h=compute_hash(last.record_hash, 11, forged),
    )
    assert not store.verify().ok  # the head still says 10 records


def test_swapping_two_records_is_detected(store: AuditStore) -> None:
    filled(store)
    tamper(store, "UPDATE audit_events SET seq = 100 WHERE seq = 3")
    tamper(store, "UPDATE audit_events SET seq = 3 WHERE seq = 4")
    tamper(store, "UPDATE audit_events SET seq = 4 WHERE seq = 100")
    assert not store.verify().ok


def test_a_rewound_head_is_detected(store: AuditStore) -> None:
    filled(store)
    tamper(store, "UPDATE audit_head SET count = 3 WHERE id = 1")
    assert not store.verify().ok


# ------------------------------------------------------------------ AC-35: separate fields


def test_decision_enforcement_and_score_are_separate_columns_and_fields() -> None:
    columns = {c.name for c in AuditRow.__table__.columns}
    assert {"decision", "enforcement_action", "anomaly_score"} <= columns
    fields = set(AuditEvent.__dataclass_fields__)
    assert {"decision", "enforcement_action", "anomaly_score"} <= fields


@pytest.mark.parametrize(
    ("method", "decision", "expected"),
    [
        ("tools/call", "ALLOW", "forwarded"),
        ("tools/call", "BLOCK", "blocked"),
        ("tools/call", "REQUIRE_APPROVAL", "paused"),
        ("tools/list", "ALLOW", "listed"),
        ("approval/decide", "APPROVED", "recorded"),
        ("approval/decide", "BLOCK", "blocked"),
    ],
)
def test_enforcement_action_is_derived_from_method_and_decision(
    method: str, decision: str, expected: str
) -> None:
    assert enforcement_for(method, decision) == expected


def test_a_high_score_is_stored_next_to_an_unchanged_decision(store: AuditStore) -> None:
    stored = store.record(event(1, decision="ALLOW", anomaly_score=0.95))
    row = store.get_by_seq(stored.seq)
    assert row is not None
    assert (row.event.decision, row.event.enforcement_action, row.event.anomaly_score) == (
        "ALLOW",
        "forwarded",
        0.95,
    )


def test_the_score_is_inside_the_hashed_record(store: AuditStore) -> None:
    filled(store, 3)
    row = store.get_by_seq(2)
    assert row is not None
    forged = canonical_json(replace(row.event, anomaly_score=0.0))
    tamper(
        store,
        "UPDATE audit_events SET anomaly_score = 0.0, event_json = :j WHERE seq = 2",
        j=forged,
    )
    result = store.verify()
    assert not result.ok and result.first_bad_seq == 2
