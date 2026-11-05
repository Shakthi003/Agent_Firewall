"""Pytest fixtures for the gateway tests (Stage 2)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from tests.gateway_harness import GatewayHarness, running_gateway


@pytest.fixture
async def gw() -> AsyncIterator[GatewayHarness]:
    async with running_gateway() as harness:
        yield harness
