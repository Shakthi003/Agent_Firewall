"""Tests for the agent registry and API keys (gateway/identity/registry.py)."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from core.db import make_engine
from gateway.identity.registry import (
    DEFAULT_TTL_DAYS,
    KEY_PREFIX,
    AgentExistsError,
    AgentRegistry,
    UnknownAgentError,
    hash_key,
)

DAY = 86_400


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def registry(clock: Clock) -> AgentRegistry:
    reg = AgentRegistry(make_engine("sqlite://"), clock=clock)
    reg.create_tables()
    return reg


def test_register_returns_a_key_once_and_it_authenticates(registry: AgentRegistry) -> None:
    issued = registry.register_agent("finance-agent", "finance")
    assert issued.key.startswith(KEY_PREFIX)
    assert issued.key_version == 1

    result = registry.authenticate(issued.key)

    assert result.failure is None
    assert result.identity is not None
    assert result.identity.agent_id == "finance-agent"
    assert result.identity.role == "finance"
    assert result.identity.key_version == 1


def test_the_key_is_never_stored_only_its_hash(registry: AgentRegistry) -> None:
    issued = registry.register_agent("finance-agent", "finance")
    with registry._engine.connect() as conn:  # noqa: SLF001
        rows = conn.execute(text("SELECT * FROM agents")).all()
    flat = " ".join(str(v) for row in rows for v in row)
    assert issued.key not in flat
    assert hash_key(issued.key) in flat
    assert issued.key not in repr(issued)


def test_keys_are_unique_and_long(registry: AgentRegistry) -> None:
    a = registry.register_agent("agent-a", "finance")
    b = registry.register_agent("agent-b", "finance")
    assert a.key != b.key
    assert len(a.key) >= 40


def test_missing_credential(registry: AgentRegistry) -> None:
    assert registry.authenticate(None).failure == "missing"
    assert registry.authenticate("").failure == "missing"


def test_malformed_credential(registry: AgentRegistry) -> None:
    assert registry.authenticate("not-a-key").failure == "malformed"
    assert registry.authenticate(KEY_PREFIX + "x" * 500).failure == "malformed"


def test_unknown_key(registry: AgentRegistry) -> None:
    registry.register_agent("finance-agent", "finance")
    assert registry.authenticate(KEY_PREFIX + "A" * 43).failure == "unknown"


def test_a_key_expires(registry: AgentRegistry, clock: Clock) -> None:
    issued = registry.register_agent("finance-agent", "finance", ttl_days=2)
    clock.now += DAY
    assert registry.authenticate(issued.key).failure is None
    clock.now += DAY  # exactly at the expiry time
    result = registry.authenticate(issued.key)
    assert result.identity is None
    assert result.failure == "expired"


def test_default_lifetime(registry: AgentRegistry, clock: Clock) -> None:
    issued = registry.register_agent("finance-agent", "finance")
    assert issued.expires_at == int(clock.now) + DEFAULT_TTL_DAYS * DAY


def test_disabling_takes_effect_on_the_next_request(registry: AgentRegistry) -> None:
    issued = registry.register_agent("it-ops-agent", "it_ops")
    assert registry.authenticate(issued.key).identity is not None

    registry.set_status("it-ops-agent", "disabled")
    result = registry.authenticate(issued.key)
    assert result.identity is None
    assert result.failure == "disabled"

    registry.set_status("it-ops-agent", "active")
    assert registry.authenticate(issued.key).identity is not None


def test_rotation_replaces_the_key_and_raises_the_version(registry: AgentRegistry) -> None:
    old = registry.register_agent("developer-agent", "developer")
    new = registry.rotate_key("developer-agent")

    assert new.key_version == 2
    assert new.key != old.key
    assert registry.authenticate(old.key).failure == "unknown"
    result = registry.authenticate(new.key)
    assert result.identity is not None
    assert result.identity.key_version == 2


def test_rotating_a_disabled_agent_keeps_it_disabled(registry: AgentRegistry) -> None:
    registry.register_agent("developer-agent", "developer")
    registry.set_status("developer-agent", "disabled")
    new = registry.rotate_key("developer-agent")
    assert registry.authenticate(new.key).failure == "disabled"


def test_duplicate_registration_is_refused(registry: AgentRegistry) -> None:
    registry.register_agent("finance-agent", "finance")
    with pytest.raises(AgentExistsError):
        registry.register_agent("finance-agent", "finance")


def test_unknown_agent_errors(registry: AgentRegistry) -> None:
    with pytest.raises(UnknownAgentError):
        registry.rotate_key("ghost")
    with pytest.raises(UnknownAgentError):
        registry.set_status("ghost", "disabled")


@pytest.mark.parametrize("agent_id", ["", "A", "Finance", "x", "has space", "-lead", "a" * 80])
def test_bad_agent_ids_are_refused(registry: AgentRegistry, agent_id: str) -> None:
    with pytest.raises(ValueError, match="Invalid agent id"):
        registry.register_agent(agent_id, "finance")


def test_unknown_role_is_refused(registry: AgentRegistry) -> None:
    with pytest.raises(ValueError, match="Unknown role"):
        registry.register_agent("root-agent", "admin")


def test_ttl_must_be_positive(registry: AgentRegistry) -> None:
    with pytest.raises(ValueError, match="ttl_days"):
        registry.register_agent("finance-agent", "finance", ttl_days=0)


def test_get_and_list_agents_never_expose_the_hash(registry: AgentRegistry) -> None:
    registry.register_agent("b-agent", "finance")
    registry.register_agent("a-agent", "developer")
    record = registry.get_agent("a-agent")
    assert record is not None
    assert (record.role, record.status, record.key_version) == ("developer", "active", 1)
    assert [r.agent_id for r in registry.list_agents()] == ["a-agent", "b-agent"]
    assert registry.get_agent("ghost") is None
    assert not hasattr(record, "key_hash")
