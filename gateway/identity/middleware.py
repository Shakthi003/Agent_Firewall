"""Identity middleware: turns the `Authorization: Bearer <key>` header into a verified identity.

A pure ASGI middleware in front of the MCP endpoint. For every HTTP request it verifies the key
against the registry and stores the RESULT in the server-side ASGI scope (`scope["agent_auth"]`).
Nothing the agent sends in an MCP payload can write to the scope, so identity can only come
from the credential.

It never rejects at the HTTP layer: a missing or bad key is recorded as a failed `AuthResult`,
and the gateway's handlers turn that into the safe, audited `UNREGISTERED_AGENT` denial. If this
middleware is not installed, handlers find no `AuthResult` and deny (fail closed).
"""

from __future__ import annotations

import anyio
from starlette.types import ASGIApp, Receive, Scope, Send

from gateway.identity.registry import AgentRegistry, AuthResult

SCOPE_KEY = "agent_auth"


def bearer_token(scope: Scope) -> str | None:
    """The bearer token from a single `Authorization` header, or None."""
    values = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
    if len(values) != 1:
        return None
    scheme, _, token = values[0].decode("latin-1").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


class IdentityMiddleware:
    def __init__(self, app: ASGIApp, registry: AgentRegistry) -> None:
        self.app = app
        self.registry = registry

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            token = bearer_token(scope)  # secret-scan: ignore (a function call, not a literal)
            # The registry uses a blocking database driver, so keep it off the event loop.
            scope[SCOPE_KEY] = await anyio.to_thread.run_sync(self.registry.authenticate, token)
        await self.app(scope, receive, send)


def auth_result(scope: Scope) -> AuthResult:
    """The verified result for this request; a failed one if the middleware did not run."""
    found = scope.get(SCOPE_KEY)
    return found if isinstance(found, AuthResult) else AuthResult(failure="missing")
