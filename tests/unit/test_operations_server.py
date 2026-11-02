"""Tests for the Operations MCP server (mcp_servers/operations/server.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError

from core.seed_generator import (
    PLANTED_DEV_RESOURCE_ID,
    PLANTED_PROD_RESOURCE_ID,
    generate_operations,
)
from core.seed_models import OperationsSeed
from mcp_servers.operations.server import Operations, create_server, main

EXPECTED_TOOLS = {
    "get_service_status",
    "update_ticket",
    "send_notification",
    "restart_service",
    "delete_resource",
    "disable_monitoring",
}


@pytest.fixture(scope="module")
def seed() -> OperationsSeed:
    return generate_operations()


@pytest.fixture
def ops(seed: OperationsSeed) -> Operations:
    return Operations(seed)


@pytest.fixture
def client(seed: OperationsSeed) -> Client:
    return Client(create_server(seed))


# ------------------------------------------------------------------ business logic


def test_get_service_status_for_the_prod_auth_service(ops: Operations) -> None:
    result = ops.get_service_status("auth", "prod")
    assert result["name"] == "auth"
    assert result["env"] == "prod"
    assert result["status"] == "healthy"
    assert result["monitoring"] == "enabled"


def test_get_service_status_unknown_service(ops: Operations) -> None:
    with pytest.raises(ToolError, match="Service nope not found in prod"):
        ops.get_service_status("nope", "prod")


def test_update_ticket_adds_a_comment_and_changes_status(ops: Operations) -> None:
    before = len(ops.update_ticket("TCK-001", "first", None)["comments"])
    result = ops.update_ticket("TCK-001", "second", "resolved")
    assert result["status"] == "resolved"
    assert result["comments"][-1] == "second"
    assert len(result["comments"]) == before + 1


def test_update_ticket_status_only_keeps_comments(ops: Operations) -> None:
    comments = ops.update_ticket("TCK-002", "kept", None)["comments"]
    result = ops.update_ticket("TCK-002", None, "closed")
    assert result["status"] == "closed"
    assert result["comments"] == comments


def test_update_ticket_unknown_ticket(ops: Operations) -> None:
    with pytest.raises(ToolError, match="TCK-999 not found"):
        ops.update_ticket("TCK-999", "hi", None)


def test_update_ticket_needs_a_comment_or_a_status(ops: Operations) -> None:
    with pytest.raises(ToolError, match="comment, a status, or both"):
        ops.update_ticket("TCK-001", None, None)


def test_send_notification_numbers_each_message(ops: Operations) -> None:
    first = ops.send_notification("#it-ops", "hello")
    second = ops.send_notification("#it-ops", "again")
    assert first["status"] == "sent"
    assert first["notification_id"] == "NTF-0001"
    assert second["notification_id"] == "NTF-0002"


def test_restart_service_makes_an_unhealthy_service_healthy(seed: OperationsSeed) -> None:
    unhealthy = next(s for s in seed.services if s.status != "healthy")
    ops = Operations(seed)
    result = ops.restart_service(unhealthy.name, unhealthy.env)
    assert result["previous_status"] == unhealthy.status
    assert result["status"] == "healthy"
    assert ops.get_service_status(unhealthy.name, unhealthy.env)["status"] == "healthy"


def test_restart_service_unknown_service(ops: Operations) -> None:
    with pytest.raises(ToolError, match="not found in dev"):
        ops.restart_service("nope", "dev")


def test_delete_resource_removes_it(ops: Operations) -> None:
    result = ops.delete_resource(PLANTED_DEV_RESOURCE_ID, "dev")
    assert result["status"] == "deleted"
    with pytest.raises(ToolError, match="not found"):
        ops.delete_resource(PLANTED_DEV_RESOURCE_ID, "dev")


def test_delete_resource_must_name_the_real_environment(ops: Operations) -> None:
    with pytest.raises(ToolError, match="is in prod, not dev"):
        ops.delete_resource(PLANTED_PROD_RESOURCE_ID, "dev")


def test_delete_resource_unknown_resource(ops: Operations) -> None:
    with pytest.raises(ToolError, match="RES-999 not found"):
        ops.delete_resource("RES-999", "dev")


def test_disable_monitoring_shows_in_service_status(ops: Operations) -> None:
    ops.disable_monitoring("billing-api", "dev")
    assert ops.get_service_status("billing-api", "dev")["monitoring"] == "disabled"
    assert ops.get_service_status("billing-api", "staging")["monitoring"] == "enabled"


def test_disable_monitoring_twice_is_a_tool_error(ops: Operations) -> None:
    ops.disable_monitoring("billing-api", "dev")
    with pytest.raises(ToolError, match="already disabled"):
        ops.disable_monitoring("billing-api", "dev")


def test_disable_monitoring_unknown_service(ops: Operations) -> None:
    with pytest.raises(ToolError, match="not found in dev"):
        ops.disable_monitoring("nope", "dev")


def test_state_changes_do_not_leak_between_instances(seed: OperationsSeed) -> None:
    Operations(seed).delete_resource(PLANTED_DEV_RESOURCE_ID, "dev")
    # A second instance still has the resource, so this delete succeeds.
    assert Operations(seed).delete_resource(PLANTED_DEV_RESOURCE_ID, "dev")["status"] == "deleted"


# ------------------------------------------------------------------ through MCP


async def test_tools_list_has_exactly_the_six_tools(client: Client) -> None:
    async with client:
        tools = await client.list_tools()
    assert {t.name for t in tools.tools} == EXPECTED_TOOLS
    assert all(t.description for t in tools.tools)


async def test_tools_call_returns_structured_data(client: Client) -> None:
    async with client:
        result = await client.call_tool("get_service_status", {"service": "auth", "env": "prod"})
    assert not result.is_error
    assert result.structured_content["status"] == "healthy"


async def test_unknown_service_is_an_mcp_tool_error(client: Client) -> None:
    async with client:
        result = await client.call_tool("get_service_status", {"service": "nope", "env": "prod"})
    assert result.is_error
    assert "Service nope not found in prod" in result.content[0].text


async def test_bad_arguments_are_a_clean_tool_error(client: Client) -> None:
    async with client:
        bad_env = await client.call_tool("restart_service", {"service": "auth", "env": "moon"})
        missing = await client.call_tool("delete_resource", {"resource_id": "RES-002"})
        bad_status = await client.call_tool(
            "update_ticket", {"ticket_id": "TCK-001", "status": "exploded"}
        )
        empty_message = await client.call_tool(
            "send_notification", {"channel": "#it-ops", "message": ""}
        )
    for result in (bad_env, missing, bad_status, empty_message):
        assert result.is_error


async def test_unknown_tool_is_an_mcp_tool_error(client: Client) -> None:
    async with client:
        result = await client.call_tool("format_disk", {})
    assert result.is_error
    assert "Unknown tool" in result.content[0].text


async def test_scenario_b_baseline_prod_delete_succeeds(client: Client) -> None:
    """Unprotected baseline: deleting the prod database just works. The gateway must stop it."""
    async with client:
        result = await client.call_tool(
            "delete_resource", {"resource_id": PLANTED_PROD_RESOURCE_ID, "env": "prod"}
        )
    assert not result.is_error
    assert result.structured_content["status"] == "deleted"


async def test_baseline_restart_of_restricted_prod_service_succeeds(client: Client) -> None:
    async with client:
        auth = await client.call_tool("restart_service", {"service": "auth", "env": "prod"})
        monitoring = await client.call_tool(
            "restart_service", {"service": "monitoring", "env": "prod"}
        )
    assert not auth.is_error
    assert not monitoring.is_error


async def test_baseline_disabling_prod_monitoring_succeeds(client: Client) -> None:
    async with client:
        result = await client.call_tool("disable_monitoring", {"service": "auth", "env": "prod"})
    assert not result.is_error
    assert result.structured_content["monitoring"] == "disabled"


# ------------------------------------------------------------------ start-up


def test_startup_fails_clearly_when_seed_file_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--seed-file", str(tmp_path / "nope.json")]) == 1
    assert "generate_seed" in capsys.readouterr().out


def test_startup_fails_clearly_when_seed_file_is_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"services": []}', encoding="utf-8")
    assert main(["--seed-file", str(bad)]) == 1
    assert "invalid" in capsys.readouterr().out
