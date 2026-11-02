"""Tests for the model interface (core/llm.py): retry wrapper and Gemini message mapping."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from google.genai import errors, types

from core.llm import (
    GeminiModel,
    Message,
    ModelError,
    ToolCall,
    ToolResult,
    ToolSpec,
    _from_response,
    _to_content,
    retry_with_backoff,
)


def api_error(code: int) -> errors.APIError:
    return errors.APIError(code, {"error": {"message": "x", "status": "X"}})


class Flaky:
    """Fails with the given codes in order, then succeeds."""

    def __init__(self, codes: list[int]) -> None:
        self.codes = list(codes)
        self.calls = 0

    async def __call__(self) -> str:
        self.calls += 1
        if self.codes:
            raise api_error(self.codes.pop(0))
        return "ok"


class Sleeps:
    def __init__(self) -> None:
        self.waits: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)


async def test_retry_waits_longer_each_time_then_succeeds() -> None:
    flaky, sleeps = Flaky([429, 503, 429]), Sleeps()
    result = await retry_with_backoff(flaky, max_retries=5, backoff_seconds=2.0, sleep=sleeps)
    assert result == "ok"
    assert flaky.calls == 4
    assert sleeps.waits == [2.0, 4.0, 8.0]


async def test_retry_gives_up_after_max_retries() -> None:
    flaky, sleeps = Flaky([429] * 10), Sleeps()
    with pytest.raises(errors.APIError):
        await retry_with_backoff(flaky, max_retries=2, backoff_seconds=1.0, sleep=sleeps)
    assert flaky.calls == 3
    assert sleeps.waits == [1.0, 2.0]


async def test_retry_does_not_retry_client_errors() -> None:
    flaky, sleeps = Flaky([400]), Sleeps()
    with pytest.raises(errors.APIError):
        await retry_with_backoff(flaky, max_retries=5, backoff_seconds=1.0, sleep=sleeps)
    assert flaky.calls == 1
    assert sleeps.waits == []


def test_user_and_tool_messages_map_to_gemini_contents() -> None:
    user = _to_content(Message(role="user", text="hi"))
    assert user.role == "user"
    assert user.parts[0].text == "hi"
    tool = _to_content(
        Message(role="tool", tool_results=(ToolResult(name="get_invoice", content={"a": 1}),))
    )
    assert tool.role == "user"
    assert tool.parts[0].function_response.name == "get_invoice"
    assert tool.parts[0].function_response.response == {"a": 1}


def test_model_message_without_raw_is_rebuilt_from_text_and_calls() -> None:
    content = _to_content(
        Message(role="model", text="ok", tool_calls=(ToolCall(name="t", args={"x": 1}),))
    )
    assert content.role == "model"
    assert content.parts[0].text == "ok"
    assert content.parts[1].function_call.name == "t"


def test_response_with_tool_call_is_parsed_and_raw_is_kept() -> None:
    content = types.Content(
        role="model",
        parts=[
            types.Part(text="thinking", thought=True),
            types.Part(function_call=types.FunctionCall(name="get_invoice", args={"id": "A"})),
        ],
    )
    reply = _from_response(SimpleNamespace(candidates=[SimpleNamespace(content=content)]))
    assert reply.tool_calls == (ToolCall(name="get_invoice", args={"id": "A"}),)
    assert reply.text == ""  # thought text is not part of the answer
    assert reply.raw is content


def test_empty_response_is_a_model_error() -> None:
    with pytest.raises(ModelError, match="no content"):
        _from_response(SimpleNamespace(candidates=[]))


async def test_gemini_model_sends_tools_and_returns_the_reply() -> None:
    seen: dict[str, Any] = {}

    async def generate_content(**kwargs: Any) -> Any:
        seen.update(kwargs)
        content = types.Content(role="model", parts=[types.Part(text="done")])
        return SimpleNamespace(candidates=[SimpleNamespace(content=content)])

    fake_client = SimpleNamespace(
        aio=SimpleNamespace(models=SimpleNamespace(generate_content=generate_content))
    )
    model = GeminiModel(api_key="x", model="m", client=fake_client)  # secret-scan: ignore
    spec = ToolSpec(name="get_invoice", description="d", parameters={"type": "object"})
    reply = await model.generate("be nice", [Message(role="user", text="hi")], [spec])

    assert reply.text == "done"
    assert seen["model"] == "m"
    assert seen["config"].system_instruction == "be nice"
    assert seen["config"].tools[0].function_declarations[0].name == "get_invoice"
    assert seen["config"].automatic_function_calling.disable is True
