# One image for the gateway, the mock MCP servers and the demo agent (Stage 2).
# The command is chosen per service in infra/docker-compose.yml.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

RUN pip install --no-cache-dir uv

WORKDIR /app

# Dependencies first so this layer is cached until the lock file changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY core ./core
COPY agents ./agents
COPY gateway ./gateway
COPY mcp_servers ./mcp_servers
COPY scripts ./scripts
COPY data/seed ./data/seed

# No secrets are baked in: keys and passwords arrive as environment variables at run time.
RUN useradd --system --no-create-home appuser
USER appuser

CMD ["python", "-m", "gateway.mcp_gateway"]
