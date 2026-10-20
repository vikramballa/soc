#!/usr/bin/env bash
# Start SentinelX (API + web UI + background worker in one process) on http://localhost:8000
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/apps/api"
HOST="${SENTINELX_HOST:-127.0.0.1}"
PORT="${SENTINELX_PORT:-8000}"
echo "SentinelX → http://$HOST:$PORT   (Ctrl+C to stop)"
exec env PYTHONPATH=src uv run --no-sync python -m sentinelx.cli serve --host "$HOST" --port "$PORT"
