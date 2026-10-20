#!/usr/bin/env bash
# Development mode: API with auto-reload on :8000 + Vite dev server with hot reload on :5173.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
trap 'kill 0' EXIT
(cd "$ROOT/apps/api" && PYTHONPATH=src uv run --no-sync python -m sentinelx.cli serve --reload) &
(cd "$ROOT/apps/web" && npm run dev) &
wait
