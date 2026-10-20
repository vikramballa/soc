# syntax=docker/dockerfile:1.7
# SentinelX — single image containing the API, background worker and the built web UI.

# ---- web UI ---------------------------------------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web ./
RUN npm run build

# ---- python dependencies --------------------------------------------------------------------
FROM python:3.12-slim AS py
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app/apps/api
COPY apps/api/pyproject.toml apps/api/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY apps/api ./
RUN uv sync --frozen --no-dev

# ---- runtime --------------------------------------------------------------------------------
FROM python:3.12-slim
RUN groupadd --system sentinelx && useradd --system --gid sentinelx --home /app sentinelx \
 && apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /app && chown sentinelx:sentinelx /app
WORKDIR /app
COPY --from=py --chown=sentinelx:sentinelx /app/apps/api /app/apps/api
COPY --from=web --chown=sentinelx:sentinelx /src/apps/web/dist /app/apps/web/dist
COPY --chown=sentinelx:sentinelx security /app/security
ENV PATH="/app/apps/api/.venv/bin:$PATH" PYTHONPATH=/app/apps/api/src PYTHONUNBUFFERED=1 \
    LOG_JSON=true APP_ENV=production
USER sentinelx
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 CMD curl -fsS http://127.0.0.1:8000/ready || exit 1
# migrate + bootstrap (idempotent), then serve API + UI with the embedded worker
CMD ["sh", "-c", "sentinelx init && exec sentinelx serve --host 0.0.0.0 --port 8000"]
