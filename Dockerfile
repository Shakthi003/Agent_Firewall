# One image for the gateway, the approver API, the mock MCP servers and the demo agent.
# The command is chosen per service in infra/docker-compose.yml.

# Stage 7: build the React dashboard. Only the compiled files are copied into the final image.
FROM node:20-slim AS dashboard
WORKDIR /dashboard
COPY apps/dashboard/package.json apps/dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/dashboard ./
RUN npm run build

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
COPY apps ./apps
COPY --from=dashboard /dashboard/dist ./apps/dashboard/dist
COPY agents ./agents
COPY gateway ./gateway
COPY monitoring ./monitoring
COPY workflows ./workflows
COPY policies ./policies
COPY mcp_servers ./mcp_servers
COPY scripts ./scripts
COPY data/seed ./data/seed

# No secrets are baked in: keys and passwords arrive as environment variables at run time.
RUN useradd --system --no-create-home appuser
USER appuser

CMD ["python", "-m", "gateway.mcp_gateway"]
