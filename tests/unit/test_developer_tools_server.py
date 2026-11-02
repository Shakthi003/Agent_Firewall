"""Tests for the Developer Tools MCP server (mcp_servers/developer_tools/server.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError

from core.seed_generator import generate_developer_tools
from core.seed_models import DeveloperToolsSeed
from mcp_servers.developer_tools.server import DeveloperTools, create_server, main

EXPECTED_TOOLS = {
    "repo_get_metadata",
    "repo_get_build_status",
    "repo_create_branch",
    "repo_open_pull_request",
    "repo_push_commit",
    "repo_delete_branch",
    "read_env_secrets",
}
REPO = "billing-service"


@pytest.fixture(scope="module")
def seed() -> DeveloperToolsSeed:
    return generate_developer_tools()


@pytest.fixture
def dev(seed: DeveloperToolsSeed) -> DeveloperTools:
    return DeveloperTools(seed)


@pytest.fixture
def client(seed: DeveloperToolsSeed) -> Client:
    return Client(create_server(seed))


# ------------------------------------------------------------------ business logic


def test_repo_get_metadata_lists_branches(dev: DeveloperTools) -> None:
    result = dev.repo_get_metadata(REPO)
    assert result["default_branch"] == "main"
    assert {"main", "develop", "release/1.0"} <= set(result["branches"])


def test_repo_get_metadata_unknown_repo(dev: DeveloperTools) -> None:
    with pytest.raises(ToolError, match="Repo nope not found"):
        dev.repo_get_metadata("nope")


def test_repo_get_build_status(dev: DeveloperTools) -> None:
    assert dev.repo_get_build_status(REPO, "main")["build_status"] == "passing"
    assert dev.repo_get_build_status(REPO, "release/1.0")["build_status"] == "failing"


def test_repo_get_build_status_unknown_branch_or_repo(dev: DeveloperTools) -> None:
    with pytest.raises(ToolError, match="Branch nope not found in billing-service"):
        dev.repo_get_build_status(REPO, "nope")
    with pytest.raises(ToolError, match="Repo nope not found"):
        dev.repo_get_build_status("nope", "main")


def test_repo_create_branch_starts_from_the_default_branch(dev: DeveloperTools) -> None:
    main_sha = dev.repo_push_commit(REPO, "main")["commit_sha"]
    result = dev.repo_create_branch(REPO, "feature/new-thing")
    assert result["status"] == "created"
    assert result["last_commit_sha"] == main_sha
    assert "feature/new-thing" in dev.repo_get_metadata(REPO)["branches"]
    assert dev.repo_get_build_status(REPO, "feature/new-thing")["build_status"] == "unknown"


def test_repo_create_branch_twice_is_a_tool_error(dev: DeveloperTools) -> None:
    with pytest.raises(ToolError, match="Branch main already exists"):
        dev.repo_create_branch(REPO, "main")


def test_repo_create_branch_unknown_repo(dev: DeveloperTools) -> None:
    with pytest.raises(ToolError, match="Repo nope not found"):
        dev.repo_create_branch("nope", "x")


def test_repo_open_pull_request_numbers_each_one(dev: DeveloperTools) -> None:
    first = dev.repo_open_pull_request(REPO, "develop", "main")
    second = dev.repo_open_pull_request(REPO, "feature/retry-logic", "develop")
    assert first["pull_request_id"] == "PR-0001"
    assert second["pull_request_id"] == "PR-0002"
    assert first["status"] == "open"


def test_repo_open_pull_request_needs_two_different_existing_branches(
    dev: DeveloperTools,
) -> None:
    with pytest.raises(ToolError, match="must be different"):
        dev.repo_open_pull_request(REPO, "main", "main")
    with pytest.raises(ToolError, match="Branch nope not found"):
        dev.repo_open_pull_request(REPO, "nope", "main")
    with pytest.raises(ToolError, match="Branch nope not found"):
        dev.repo_open_pull_request(REPO, "main", "nope")


def test_repo_push_commit_changes_the_sha_and_resets_the_build(dev: DeveloperTools) -> None:
    before = dev.repo_push_commit(REPO, "develop")
    after = dev.repo_push_commit(REPO, "develop")
    assert after["previous_commit_sha"] == before["commit_sha"]
    assert after["commit_sha"] != before["commit_sha"]
    assert dev.repo_get_build_status(REPO, "develop")["build_status"] == "unknown"


def test_repo_push_commit_unknown_branch(dev: DeveloperTools) -> None:
    with pytest.raises(ToolError, match="Branch nope not found"):
        dev.repo_push_commit(REPO, "nope")


def test_repo_delete_branch_removes_it(dev: DeveloperTools) -> None:
    result = dev.repo_delete_branch(REPO, "feature/old-experiment")
    assert result["status"] == "deleted"
    assert "feature/old-experiment" not in dev.repo_get_metadata(REPO)["branches"]
    with pytest.raises(ToolError, match="not found"):
        dev.repo_delete_branch(REPO, "feature/old-experiment")


def test_no_security_rule_on_protected_branches(dev: DeveloperTools) -> None:
    """Protected branches are the gateway's job: pushing to and deleting them just works."""
    assert dev.repo_push_commit(REPO, "main")["status"] == "pushed"
    assert dev.repo_delete_branch(REPO, "release/1.0")["status"] == "deleted"
    assert dev.repo_delete_branch(REPO, "main")["status"] == "deleted"


def test_read_env_secrets_returns_only_fake_values(dev: DeveloperTools) -> None:
    result = dev.read_env_secrets("prod")
    assert result["count"] == 3
    assert {s["name"] for s in result["secrets"]} == {
        "DB_PASSWORD",
        "PAYMENT_GATEWAY_KEY",
        "SIGNING_KEY",
    }
    assert all(s["value"].startswith("FAKE-NOT-A-SECRET-") for s in result["secrets"])


def test_read_env_secrets_unknown_scope(dev: DeveloperTools) -> None:
    with pytest.raises(ToolError, match="No secrets found for scope moon"):
        dev.read_env_secrets("moon")


def test_state_changes_do_not_leak_between_instances(seed: DeveloperToolsSeed) -> None:
    DeveloperTools(seed).repo_delete_branch(REPO, "develop")
    assert "develop" in DeveloperTools(seed).repo_get_metadata(REPO)["branches"]


# ------------------------------------------------------------------ through MCP


async def test_tools_list_has_exactly_the_seven_tools(client: Client) -> None:
    async with client:
        tools = await client.list_tools()
    assert {t.name for t in tools.tools} == EXPECTED_TOOLS
    assert all(t.description for t in tools.tools)


async def test_tools_call_returns_structured_data(client: Client) -> None:
    async with client:
        result = await client.call_tool("repo_get_metadata", {"repo": REPO})
    assert not result.is_error
    assert result.structured_content["default_branch"] == "main"


async def test_unknown_repo_is_an_mcp_tool_error(client: Client) -> None:
    async with client:
        result = await client.call_tool("repo_get_metadata", {"repo": "nope"})
    assert result.is_error
    assert "Repo nope not found" in result.content[0].text


async def test_bad_arguments_are_a_clean_tool_error(client: Client) -> None:
    async with client:
        empty = await client.call_tool("repo_get_metadata", {"repo": ""})
        missing = await client.call_tool("repo_push_commit", {"repo": REPO})
        wrong_type = await client.call_tool("read_env_secrets", {"scope": 5})
    for result in (empty, missing, wrong_type):
        assert result.is_error


async def test_unknown_tool_is_an_mcp_tool_error(client: Client) -> None:
    async with client:
        result = await client.call_tool("format_disk", {})
    assert result.is_error
    assert "Unknown tool" in result.content[0].text


async def test_scenario_c_baseline_reading_prod_secrets_succeeds(client: Client) -> None:
    """Unprotected baseline: the secrets come back (fake ones). The gateway must stop it."""
    async with client:
        result = await client.call_tool("read_env_secrets", {"scope": "prod"})
    assert not result.is_error
    assert result.structured_content["count"] == 3
    assert "FAKE-NOT-A-SECRET-" in json.dumps(result.structured_content)


async def test_baseline_push_to_main_and_delete_release_branch_succeed(client: Client) -> None:
    async with client:
        push = await client.call_tool("repo_push_commit", {"repo": REPO, "branch": "main"})
        delete = await client.call_tool(
            "repo_delete_branch", {"repo": REPO, "branch": "release/1.0"}
        )
    assert not push.is_error
    assert not delete.is_error


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
    bad.write_text('{"repos": []}', encoding="utf-8")
    assert main(["--seed-file", str(bad)]) == 1
    assert "invalid" in capsys.readouterr().out
