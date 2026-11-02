"""Generic tool-calling loop for the business agents (Stage 1).

The loop lists the tools on an MCP server, offers the agent's allowed tools to the model, runs
the tool calls the model asks for, and feeds the results back until the model gives a final
answer. Every call is recorded. The same loop works against a downstream server directly
(the unprotected baseline) and, later, against the gateway.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any

from mcp.client import Client

from core.llm import ChatModel, Message, ToolCall, ToolResult, ToolSpec

DEFAULT_MAX_STEPS = 10


class AgentStepLimitError(Exception):
    """The model kept asking for tools and never gave a final answer."""


@dataclass(frozen=True)
class CallRecord:
    name: str
    args: dict[str, Any]
    result: dict[str, Any]
    is_error: bool


@dataclass
class AgentRun:
    final_text: str
    calls: list[CallRecord] = field(default_factory=list)
    steps: int = 0


async def run_agent(
    *,
    model: ChatModel,
    system_prompt: str,
    client: Client,
    allowed_tools: Collection[str],
    task: str,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> AgentRun:
    """Run one task. `client` must already be connected (inside `async with`)."""
    listed = (await client.list_tools()).tools
    specs = [
        ToolSpec(name=t.name, description=t.description or "", parameters=t.input_schema)
        for t in listed
        if t.name in allowed_tools
    ]
    offered = {s.name for s in specs}

    messages: list[Message] = [Message(role="user", text=task)]
    run = AgentRun(final_text="")
    for step in range(1, max_steps + 1):
        reply = await model.generate(system_prompt, messages, specs)
        messages.append(reply)
        run.steps = step
        if not reply.tool_calls:
            run.final_text = reply.text
            return run
        results = [await _execute(client, call, offered, run) for call in reply.tool_calls]
        messages.append(Message(role="tool", tool_results=tuple(results)))
    raise AgentStepLimitError(f"No final answer after {max_steps} steps")


async def _execute(client: Client, call: ToolCall, offered: set[str], run: AgentRun) -> ToolResult:
    if call.name not in offered:
        content: dict[str, Any] = {"error": f"Tool {call.name} is not available to this agent"}
        is_error = True
    else:
        result = await client.call_tool(call.name, call.args)
        is_error = result.is_error
        content = _result_content(result)
    run.calls.append(CallRecord(call.name, call.args, content, is_error))
    return ToolResult(name=call.name, content=content)


def _result_content(result: Any) -> dict[str, Any]:
    text = result.content[0].text if result.content else ""
    if result.is_error:
        return {"error": text}
    if isinstance(result.structured_content, dict):
        return result.structured_content
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"text": text}
    return parsed if isinstance(parsed, dict) else {"result": parsed}
