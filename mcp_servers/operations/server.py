"""Operations MCP server (Stage 1, slice 4).

A mock IT-operations system: service health, tickets, notifications, infrastructure resources.
Six tools, matching `docs/permission-matrix.md`.

This server is deliberately UNPROTECTED. It enforces business rules a real system would
(a service, ticket or resource must exist; a delete must name the resource's real environment)
but none of the security rules: restarting a restricted prod service, deleting a prod resource
and turning off monitoring all just work. Those belong to the gateway, and the unprotected
baseline (slice 7) shows what happens without it.

All state is held in memory and starts fresh from the seed file, so changes reset on restart.
"""

from pathlib import Path
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field

from core.seed_models import Env, OperationsSeed, Service, TicketStatus
from mcp_servers.runner import serve

NonEmpty = Annotated[str, Field(min_length=1)]

DEFAULT_PORT = 9002
DEFAULT_SEED_FILE = "data/seed/operations.json"


def _dump(record: BaseModel) -> dict[str, Any]:
    return record.model_dump(mode="json")


class Operations:
    """In-memory state and business logic. Raises `ToolError` for anticipated failures."""

    def __init__(self, seed: OperationsSeed) -> None:
        # Copies, so two servers built from the same seed never share state.
        self._services = {(s.name, s.env): s for s in seed.services}
        self._resources = {r.resource_id: r for r in seed.resources}
        self._tickets = {t.ticket_id: t for t in seed.tickets}
        self._monitoring_disabled: set[tuple[str, str]] = set()
        self._notifications: list[dict[str, str]] = []

    # ---- read-only

    def get_service_status(self, service: str, env: Env) -> dict[str, Any]:
        found = self._service(service, env)
        return self._service_view(found)

    # ---- tickets and notifications

    def update_ticket(
        self, ticket_id: str, comment: str | None, status: TicketStatus | None
    ) -> dict[str, Any]:
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise ToolError(f"Ticket {ticket_id} not found")
        if comment is None and status is None:
            raise ToolError("Give a comment, a status, or both")
        update: dict[str, Any] = {}
        if comment is not None:
            update["comments"] = [*ticket.comments, comment]
        if status is not None:
            update["status"] = status
        ticket = ticket.model_copy(update=update)
        self._tickets[ticket_id] = ticket
        return _dump(ticket)

    def send_notification(self, channel: str, message: str) -> dict[str, Any]:
        notification_id = f"NTF-{len(self._notifications) + 1:04d}"
        self._notifications.append(
            {"notification_id": notification_id, "channel": channel, "message": message}
        )
        return {"notification_id": notification_id, "channel": channel, "status": "sent"}

    # ---- actions on services and resources

    def restart_service(self, service: str, env: Env) -> dict[str, Any]:
        found = self._service(service, env)
        self._services[(service, env)] = found.model_copy(update={"status": "healthy"})
        return {
            "service": service,
            "env": env,
            "previous_status": found.status,
            "status": "healthy",
            "action": "restarted",
        }

    def delete_resource(self, resource_id: str, env: Env) -> dict[str, Any]:
        resource = self._resources.get(resource_id)
        if resource is None:
            raise ToolError(f"Resource {resource_id} not found")
        if resource.env != env:
            raise ToolError(f"Resource {resource_id} is in {resource.env}, not {env}")
        del self._resources[resource_id]
        return {"resource_id": resource_id, "env": env, "name": resource.name, "status": "deleted"}

    def disable_monitoring(self, service: str, env: Env) -> dict[str, Any]:
        self._service(service, env)
        if (service, env) in self._monitoring_disabled:
            raise ToolError(f"Monitoring for {service} in {env} is already disabled")
        self._monitoring_disabled.add((service, env))
        return {"service": service, "env": env, "monitoring": "disabled"}

    # ---- helpers

    def _service(self, service: str, env: str) -> Service:
        found = self._services.get((service, env))
        if found is None:
            raise ToolError(f"Service {service} not found in {env}")
        return found

    def _service_view(self, service: Service) -> dict[str, Any]:
        view = _dump(service)
        disabled = (service.name, service.env) in self._monitoring_disabled
        view["monitoring"] = "disabled" if disabled else "enabled"
        return view


def create_server(seed: OperationsSeed) -> MCPServer:
    data = Operations(seed)
    server = MCPServer("operations")

    @server.tool()
    def get_service_status(service: str, env: Env) -> dict[str, Any]:
        """Read the health, version and monitoring state of one service in one environment."""
        return data.get_service_status(service, env)

    @server.tool()
    def update_ticket(
        ticket_id: str, comment: str | None = None, status: TicketStatus | None = None
    ) -> dict[str, Any]:
        """Add a comment to an IT ticket, change its status, or both."""
        return data.update_ticket(ticket_id, comment, status)

    @server.tool()
    def send_notification(channel: NonEmpty, message: NonEmpty) -> dict[str, Any]:
        """Send a mock notification to a channel (nothing is really sent)."""
        return data.send_notification(channel, message)

    @server.tool()
    def restart_service(service: str, env: Env) -> dict[str, Any]:
        """Restart a service in one environment (mock)."""
        return data.restart_service(service, env)

    @server.tool()
    def delete_resource(resource_id: str, env: Env) -> dict[str, Any]:
        """Delete an infrastructure resource (mock). `env` must be the resource's environment."""
        return data.delete_resource(resource_id, env)

    @server.tool()
    def disable_monitoring(service: str, env: Env) -> dict[str, Any]:
        """Turn monitoring off for a service in one environment (mock)."""
        return data.disable_monitoring(service, env)

    return server


def main(argv: list[str] | None = None) -> int:
    return serve(
        description="Operations MCP server (mock, unprotected)",
        model=OperationsSeed,
        create_server=create_server,
        default_seed_file=Path(DEFAULT_SEED_FILE),
        default_port=DEFAULT_PORT,
        argv=argv,
    )
