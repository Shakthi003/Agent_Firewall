"""Tests for the approved tool registry (gateway/mcp_gateway/tools.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp.client import Client

from agents.business.developer import DEVELOPER_TOOLS
from agents.business.finance import FINANCE_TOOLS
from agents.business.it_ops import IT_OPS_TOOLS
from core.seed_generator import generate_all
from gateway.mcp_gateway.tools import (
    DEFAULT_REGISTRY_FILE,
    RegistryError,
    ToolEntry,
    ToolRegistry,
)
from mcp_servers.company_data.server import create_server as create_company_data
from mcp_servers.developer_tools.server import create_server as create_developer_tools
from mcp_servers.operations.server import create_server as create_operations

OWNERS = {
    "Finance System Owner",
    "HR System Owner",
    "IT Operations Lead",
    "Engineering Lead",
    "Security Team",
}


@pytest.fixture(scope="module")
def registry() -> ToolRegistry:
    return ToolRegistry.load()


def test_registry_has_the_22_tools_of_the_permission_matrix(registry: ToolRegistry) -> None:
    assert len(registry.names()) == 22
    assert len(registry.tools_for_server("company_data")) == 9
    assert len(registry.tools_for_server("operations")) == 6
    assert len(registry.tools_for_server("developer_tools")) == 7


def test_every_tool_has_one_of_the_five_owners(registry: ToolRegistry) -> None:
    for name in registry.names():
        entry = registry.get(name)
        assert entry is not None
        assert entry.owner in OWNERS, name


async def test_registry_matches_what_the_downstream_servers_really_offer(
    registry: ToolRegistry,
) -> None:
    company, operations, developer = generate_all()
    servers = {
        "company_data": create_company_data(company),
        "operations": create_operations(operations),
        "developer_tools": create_developer_tools(developer),
    }
    for server_name, server in servers.items():
        async with Client(server) as client:
            offered = {t.name for t in (await client.list_tools()).tools}
        assert offered == set(registry.tools_for_server(server_name)), server_name


def test_grants_match_the_agents_tool_lists(registry: ToolRegistry) -> None:
    assert set(registry.tools_for_role("finance")) == set(FINANCE_TOOLS)
    assert set(registry.tools_for_role("it_ops")) == set(IT_OPS_TOOLS)
    assert set(registry.tools_for_role("developer")) == set(DEVELOPER_TOOLS)


def test_hidden_from_everyone_tools(registry: ToolRegistry) -> None:
    for tool in ("get_employee_record", "read_payroll", "read_env_secrets"):
        assert registry.is_registered(tool)
        for role in ("finance", "it_ops", "developer"):
            assert not registry.is_granted(tool, role), (tool, role)


def test_the_only_shared_tool_is_get_service_status(registry: ToolRegistry) -> None:
    shared = set(registry.tools_for_role("it_ops")) & set(registry.tools_for_role("developer"))
    assert shared == {"get_service_status"}
    assert not set(registry.tools_for_role("finance")) & set(registry.tools_for_role("it_ops"))
    assert not set(registry.tools_for_role("finance")) & set(registry.tools_for_role("developer"))


def test_attack_demo_tools_are_visible_to_it_ops(registry: ToolRegistry) -> None:
    assert registry.is_granted("delete_resource", "it_ops")
    assert registry.is_granted("disable_monitoring", "it_ops")


def test_unknown_tool_and_unknown_role(registry: ToolRegistry) -> None:
    assert registry.get("format_disk") is None
    assert not registry.is_registered("format_disk")
    assert not registry.is_granted("format_disk", "finance")
    assert not registry.is_granted("get_invoice", "admin")


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "registry.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(RegistryError, match="not found"):
        ToolRegistry.load(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    "body",
    [
        "version: 1\ntools: {}\n",
        "version: 2\ntools: {a: {server: operations, owner: X, sensitivity: L, roles: []}}\n",
        "version: 1\ntools: {a: {server: nowhere, owner: X, sensitivity: L, roles: []}}\n",
        "version: 1\ntools: {a: {server: operations, owner: '', sensitivity: L, roles: []}}\n",
        "version: 1\ntools: {a: {server: operations, owner: X, sensitivity: Z, roles: []}}\n",
        "version: 1\ntools: {a: {server: operations, owner: X, sensitivity: L, roles: [admin]}}\n",
        "version: 1\ntools: {a: {server: operations, owner: X, sensitivity: L, roles: [], x: 1}}\n",
        "version: 1\ntools: {a: {server: operations, owner: X, sensitivity: L}}\n",
        "not: [valid",
        "- just a list",
    ],
)
def test_bad_files_are_rejected(tmp_path: Path, body: str) -> None:
    with pytest.raises(RegistryError):
        ToolRegistry.load(_write(tmp_path, body))


def test_an_empty_registry_is_refused() -> None:
    with pytest.raises(RegistryError, match="empty"):
        ToolRegistry({})


def test_entries_are_immutable() -> None:
    entry = ToolEntry(server="operations", owner="X", sensitivity="L", roles=("it_ops",))
    with pytest.raises(ValueError, match="frozen"):
        entry.owner = "Y"  # type: ignore[misc]


def test_default_registry_file_exists() -> None:
    assert DEFAULT_REGISTRY_FILE.is_file()
