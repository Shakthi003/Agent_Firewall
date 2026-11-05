"""Approved tool registry (Stage 2).

Loads `tool_registry.yaml` and answers three questions for the gateway:
is this tool approved at all, which server runs it, and which roles may see it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, get_args

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from gateway.identity.registry import ROLES

ServerName = Literal["company_data", "operations", "developer_tools"]
SERVERS: tuple[str, ...] = get_args(ServerName)
Sensitivity = Literal["L", "M", "H", "C"]

DEFAULT_REGISTRY_FILE = Path(__file__).with_name("tool_registry.yaml")


class RegistryError(Exception):
    """The registry file is missing, malformed or inconsistent."""


class ToolEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    server: ServerName
    owner: str = Field(min_length=1)
    sensitivity: Sensitivity
    roles: tuple[str, ...]

    @field_validator("roles")
    @classmethod
    def _known_roles(cls, roles: tuple[str, ...]) -> tuple[str, ...]:
        unknown = [r for r in roles if r not in ROLES]
        if unknown:
            raise ValueError(f"unknown role(s) {unknown}; expected a subset of {ROLES}")
        return roles


class _RegistryFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    tools: dict[str, ToolEntry]


class ToolRegistry:
    def __init__(self, tools: dict[str, ToolEntry]) -> None:
        if not tools:
            raise RegistryError("The tool registry is empty")
        self._tools = dict(tools)

    @classmethod
    def load(cls, path: Path = DEFAULT_REGISTRY_FILE) -> ToolRegistry:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            parsed = _RegistryFile.model_validate(raw)
        except FileNotFoundError as exc:
            raise RegistryError(f"Tool registry file not found: {path}") from exc
        except (yaml.YAMLError, ValueError) as exc:
            raise RegistryError(f"Tool registry {path} is invalid: {exc}") from exc
        return cls(parsed.tools)

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def get(self, tool: str) -> ToolEntry | None:
        return self._tools.get(tool)

    def is_registered(self, tool: str) -> bool:
        return tool in self._tools

    def is_granted(self, tool: str, role: str) -> bool:
        entry = self._tools.get(tool)
        return entry is not None and role in entry.roles

    def tools_for_role(self, role: str) -> list[str]:
        return [name for name, entry in self._tools.items() if role in entry.roles]

    def tools_for_server(self, server: str) -> list[str]:
        return [name for name, entry in self._tools.items() if entry.server == server]
