"""AC-11: from inside an agent container, every downstream MCP server is unreachable.

This starts the real Docker Compose stack under a separate project name (so it never touches a
developer's running stack), runs probes from inside the containers, and tears the stack down.
Skipped when Docker is not available.
Run with: uv run pytest tests/integration/test_network_isolation.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "infra" / "docker-compose.yml"
PROJECT = "agent-firewall-nettest"
DOWNSTREAM = {"company-data": 9001, "operations": 9002, "developer-tools": 9003}

PROBE = """
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    socket.create_connection((host, port), timeout=3).close()
except OSError as exc:
    print("UNREACHABLE", type(exc).__name__)
    sys.exit(0)
print("REACHABLE")
"""


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        timeout=30,
        check=False,
    )
    return result.returncode == 0


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available")


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        # Throwaway values: this stack is private to the test and thrown away afterwards.
        "POSTGRES_PASSWORD": "nettest-only-password",
        "APPROVER_PASSWORD": "nettest-only-approver",  # secret-scan: ignore
        "POSTGRES_PORT": "55432",
    }
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=600,
        check=check,
    )


def _probe(service: str, host: str, port: int) -> str:
    result = _compose("exec", "-T", service, "python", "-c", PROBE, host, str(port))
    return result.stdout.strip()


def _container_ip(service: str, network: str) -> str:
    container = _compose("ps", "-q", service).stdout.strip()
    inspect = subprocess.run(
        ["docker", "inspect", container],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    networks = json.loads(inspect.stdout)[0]["NetworkSettings"]["Networks"]
    return networks[f"{PROJECT}_{network}"]["IPAddress"]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    _compose("--profile", "baseline", "up", "-d", "--build", "--wait")
    try:
        yield
    finally:
        _compose("--profile", "baseline", "down", "-v", "--remove-orphans", check=False)


def test_agent_can_reach_the_gateway(stack: None) -> None:
    assert _probe("agent", "gateway", 8080) == "REACHABLE"


@pytest.mark.parametrize(("name", "port"), DOWNSTREAM.items())
def test_agent_cannot_reach_downstream_by_name(stack: None, name: str, port: int) -> None:
    assert _probe("agent", name, port).startswith("UNREACHABLE")


@pytest.mark.parametrize(("name", "port"), DOWNSTREAM.items())
def test_agent_cannot_reach_downstream_by_ip(stack: None, name: str, port: int) -> None:
    """Knowing the address is not enough: there is no route from agent_net."""
    ip = _container_ip(name, "internal_net")
    assert _probe("agent", ip, port).startswith("UNREACHABLE")


def test_agent_cannot_reach_postgres(stack: None) -> None:
    assert _probe("agent", "postgres", 5432).startswith("UNREACHABLE")


def test_agent_cannot_reach_the_approver_api(stack: None) -> None:
    """Approvals are for humans: an agent must have no route to the approve endpoint."""
    assert _probe("agent", "approver-api", 8000).startswith("UNREACHABLE")
    ip = _container_ip("approver-api", "internal_net")
    assert _probe("agent", ip, 8000).startswith("UNREACHABLE")


def test_the_approver_api_publishes_no_port_by_default(stack: None) -> None:
    """A published port is reachable from other networks by container IP, so none is published."""
    published = _compose("port", "approver-api", "8000", check=False).stdout.strip()
    assert published == "", f"approver-api publishes port 8000 to the host: {published}"


def test_downstream_ports_are_not_published_to_the_host(stack: None) -> None:
    for name, port in DOWNSTREAM.items():
        published = _compose("port", name, str(port), check=False).stdout.strip()
        assert published == "", f"{name} publishes port {port} to the host: {published}"


def test_baseline_agent_does_reach_downstream_directly(stack: None) -> None:
    """The unprotected baseline profile really is unprotected, so the comparison is honest."""
    assert _probe("agent-baseline", "company-data", 9001) == "REACHABLE"
