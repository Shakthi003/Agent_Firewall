"""Model interface and Gemini implementation (Stage 1).

The business agents talk to `ChatModel`, a small provider-neutral interface, so the LLM can be
swapped. `GeminiModel` implements it with the Gemini free tier and retries rate-limit and
server errors with exponential backoff.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, TypeVar

from google import genai
from google.genai import errors, types

from core.config import Settings, get_settings

T = TypeVar("T")

RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class ModelError(Exception):
    """The model could not produce a usable reply."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema of the arguments


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    name: str
    content: dict[str, Any]


@dataclass(frozen=True)
class Message:
    """One turn of the conversation.

    `raw` holds the provider's original object for a model turn. It is replayed unchanged,
    because Gemini 3 needs its own reply (including internal thought signatures) sent back.
    """

    role: Literal["user", "model", "tool"]
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()
    raw: Any = None


class ChatModel(Protocol):
    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message: ...


async def retry_with_backoff(
    call: Callable[[], Awaitable[T]],
    *,
    max_retries: int,
    backoff_seconds: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Run `call`, retrying rate-limit and server errors; wait backoff * 2**attempt each time."""
    attempt = 0
    while True:
        try:
            return await call()
        except errors.APIError as exc:
            if exc.code not in RETRYABLE_STATUS_CODES or attempt >= max_retries:
                raise
            await sleep(backoff_seconds * 2**attempt)
            attempt += 1


class GeminiModel:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        max_retries: int = 5,
        backoff_seconds: float = 2.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        client: Any = None,
    ) -> None:
        self._client = client or genai.Client(api_key=api_key)
        self._model = model
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._sleep = sleep

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> GeminiModel:
        settings = settings or get_settings()
        return cls(
            api_key=settings.require_gemini_key(),  # secret-scan: ignore
            model=settings.gemini_model,
            max_retries=settings.llm_max_retries,
            backoff_seconds=settings.llm_backoff_seconds,
        )

    async def generate(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolSpec]
    ) -> Message:
        config = types.GenerateContentConfig(
            system_instruction=system,
            tools=[types.Tool(function_declarations=[_declaration(t) for t in tools])]
            if tools
            else None,
            # The agent loop runs the tools itself, so every call can be recorded.
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        contents = [_to_content(m) for m in messages]
        response = await retry_with_backoff(
            lambda: self._client.aio.models.generate_content(
                model=self._model, contents=contents, config=config
            ),
            max_retries=self._max_retries,
            backoff_seconds=self._backoff_seconds,
            sleep=self._sleep,
        )
        return _from_response(response)


def _declaration(tool: ToolSpec) -> types.FunctionDeclaration:
    return types.FunctionDeclaration(
        name=tool.name, description=tool.description, parameters_json_schema=tool.parameters
    )


def _to_content(message: Message) -> types.Content:
    if message.role == "user":
        return types.Content(role="user", parts=[types.Part(text=message.text)])
    if message.role == "tool":
        return types.Content(
            role="user",
            parts=[
                types.Part.from_function_response(name=r.name, response=r.content)
                for r in message.tool_results
            ],
        )
    if message.raw is not None:
        return message.raw
    parts = [types.Part(text=message.text)] if message.text else []
    parts += [
        types.Part(function_call=types.FunctionCall(name=c.name, args=c.args))
        for c in message.tool_calls
    ]
    return types.Content(role="model", parts=parts)


def _from_response(response: Any) -> Message:
    if not response.candidates or response.candidates[0].content is None:
        raise ModelError("The model returned no content (it may have been blocked)")
    content = response.candidates[0].content
    parts = content.parts or []
    text = "".join(p.text for p in parts if p.text and not p.thought)
    calls = tuple(
        ToolCall(name=p.function_call.name, args=dict(p.function_call.args or {}))
        for p in parts
        if p.function_call is not None
    )
    return Message(role="model", text=text, tool_calls=calls, raw=content)
