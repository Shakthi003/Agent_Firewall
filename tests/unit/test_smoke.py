"""Smoke test: the package layout imports and the test runner works."""

import importlib

import pytest

PACKAGES = [
    "apps.api",
    "agents.business",
    "agents.security",
    "gateway.mcp_gateway",
    "gateway.identity",
    "gateway.policy",
    "mcp_servers.company_data",
    "mcp_servers.operations",
    "mcp_servers.developer_tools",
    "monitoring.audit",
    "monitoring.detection",
    "workflows.investigation",
    "core",
]


@pytest.mark.parametrize("name", PACKAGES)
def test_package_imports(name: str) -> None:
    assert importlib.import_module(name) is not None
