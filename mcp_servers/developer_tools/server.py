"""Developer Tools MCP server (Stage 1, slice 5).

A mock source-code host plus a secrets store: repositories, branches, pull requests and
environment secrets. Seven tools, matching `docs/permission-matrix.md`. No live GitHub and no
real secrets: every secret value in the seed starts with `FAKE-NOT-A-SECRET-`.

This server is deliberately UNPROTECTED. It enforces business rules a real system would
(a repo or branch must exist, a new branch needs a new name, a pull request needs two
different branches) but none of the security rules: pushing to or deleting `main` and
`release/*`, and reading production secrets, all just work. Those belong to the gateway,
and the unprotected baseline (slice 7) shows what happens without it.

All state is held in memory and starts fresh from the seed file, so changes reset on restart.
"""

import hashlib
from pathlib import Path
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from core.seed_models import Branch, DeveloperToolsSeed, Repo
from mcp_servers.runner import serve

NonEmpty = Annotated[str, Field(min_length=1)]

DEFAULT_PORT = 9003
DEFAULT_SEED_FILE = "data/seed/developer_tools.json"


def _sha(*parts: object) -> str:
    """A deterministic 7-character commit id."""
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()[:7]


class DeveloperTools:
    """In-memory state and business logic. Raises `ToolError` for anticipated failures."""

    def __init__(self, seed: DeveloperToolsSeed) -> None:
        # Copies, so two servers built from the same seed never share state.
        self._repos: dict[str, Repo] = {r.name: r for r in seed.repos}
        self._branches: dict[str, dict[str, Branch]] = {
            r.name: {b.name: b for b in r.branches} for r in seed.repos
        }
        self._secrets = list(seed.secrets)
        self._pull_requests: list[dict[str, Any]] = []
        self._commit_count = 0

    # ---- read-only

    def repo_get_metadata(self, repo: str) -> dict[str, Any]:
        found = self._repo(repo)
        return {
            "name": found.name,
            "description": found.description,
            "default_branch": found.default_branch,
            "branches": list(self._branches[repo]),
        }

    def repo_get_build_status(self, repo: str, branch: str) -> dict[str, Any]:
        found = self._branch(repo, branch)
        return {"repo": repo, "branch": branch, "build_status": found.build_status}

    # ---- branches, pull requests, commits

    def repo_create_branch(self, repo: str, branch: str) -> dict[str, Any]:
        self._repo(repo)
        if branch in self._branches[repo]:
            raise ToolError(f"Branch {branch} already exists in {repo}")
        # A new branch starts from the default branch's latest commit.
        base = self._branches[repo].get(self._repos[repo].default_branch)
        sha = base.last_commit_sha if base else _sha(repo, branch)
        self._branches[repo][branch] = Branch(
            name=branch, build_status="unknown", last_commit_sha=sha
        )
        return {"repo": repo, "branch": branch, "last_commit_sha": sha, "status": "created"}

    def repo_open_pull_request(self, repo: str, source: str, target: str) -> dict[str, Any]:
        self._branch(repo, source)
        self._branch(repo, target)
        if source == target:
            raise ToolError("Source and target branches must be different")
        pull_request = {
            "pull_request_id": f"PR-{len(self._pull_requests) + 1:04d}",
            "repo": repo,
            "source": source,
            "target": target,
            "status": "open",
        }
        self._pull_requests.append(pull_request)
        return dict(pull_request)

    def repo_push_commit(self, repo: str, branch: str) -> dict[str, Any]:
        found = self._branch(repo, branch)
        self._commit_count += 1
        sha = _sha(repo, branch, self._commit_count)
        # A fresh commit has not been built yet.
        self._branches[repo][branch] = found.model_copy(
            update={"last_commit_sha": sha, "build_status": "unknown"}
        )
        return {
            "repo": repo,
            "branch": branch,
            "previous_commit_sha": found.last_commit_sha,
            "commit_sha": sha,
            "status": "pushed",
        }

    def repo_delete_branch(self, repo: str, branch: str) -> dict[str, Any]:
        self._branch(repo, branch)
        del self._branches[repo][branch]
        return {"repo": repo, "branch": branch, "status": "deleted"}

    # ---- secrets

    def read_env_secrets(self, scope: str) -> dict[str, Any]:
        matching = [s for s in self._secrets if s.scope == scope]
        if not matching:
            raise ToolError(f"No secrets found for scope {scope}")
        return {
            "scope": scope,
            "count": len(matching),
            "secrets": [{"name": s.name, "value": s.value} for s in matching],
        }

    # ---- helpers

    def _repo(self, repo: str) -> Repo:
        found = self._repos.get(repo)
        if found is None:
            raise ToolError(f"Repo {repo} not found")
        return found

    def _branch(self, repo: str, branch: str) -> Branch:
        self._repo(repo)
        found = self._branches[repo].get(branch)
        if found is None:
            raise ToolError(f"Branch {branch} not found in {repo}")
        return found


def create_server(seed: DeveloperToolsSeed) -> MCPServer:
    data = DeveloperTools(seed)
    server = MCPServer("developer-tools")

    @server.tool()
    def repo_get_metadata(repo: NonEmpty) -> dict[str, Any]:
        """Read the description, default branch and branch list of a repository."""
        return data.repo_get_metadata(repo)

    @server.tool()
    def repo_get_build_status(repo: NonEmpty, branch: NonEmpty) -> dict[str, Any]:
        """Read the latest build status of one branch."""
        return data.repo_get_build_status(repo, branch)

    @server.tool()
    def repo_create_branch(repo: NonEmpty, branch: NonEmpty) -> dict[str, Any]:
        """Create a new branch from the default branch (mock)."""
        return data.repo_create_branch(repo, branch)

    @server.tool()
    def repo_open_pull_request(
        repo: NonEmpty, source: NonEmpty, target: NonEmpty
    ) -> dict[str, Any]:
        """Open a pull request from one branch into another (mock)."""
        return data.repo_open_pull_request(repo, source, target)

    @server.tool()
    def repo_push_commit(repo: NonEmpty, branch: NonEmpty) -> dict[str, Any]:
        """Push a new commit to a branch (mock)."""
        return data.repo_push_commit(repo, branch)

    @server.tool()
    def repo_delete_branch(repo: NonEmpty, branch: NonEmpty) -> dict[str, Any]:
        """Delete a branch (mock)."""
        return data.repo_delete_branch(repo, branch)

    @server.tool()
    def read_env_secrets(scope: NonEmpty) -> dict[str, Any]:
        """Read the environment secrets of one scope: dev, staging or prod (fake values only)."""
        return data.read_env_secrets(scope)

    return server


def main(argv: list[str] | None = None) -> int:
    return serve(
        description="Developer Tools MCP server (mock, unprotected)",
        model=DeveloperToolsSeed,
        create_server=create_server,
        default_seed_file=Path(DEFAULT_SEED_FILE),
        default_port=DEFAULT_PORT,
        argv=argv,
    )
