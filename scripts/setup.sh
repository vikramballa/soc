#!/usr/bin/env bash
# SentinelX native setup for macOS and Linux (Windows: use Docker — see README).
#   ./scripts/setup.sh            # install + initialise
#   ./scripts/setup.sh --demo     # also build the synthetic Demo Lab
# Environment overrides: PGHOST PGPORT PGUSER (a PostgreSQL superuser used ONLY to create the app role/db)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="$ROOT/apps/api"
WEB="$ROOT/apps/web"
DEMO=""
[[ "${1:-}" == "--demo" ]] && DEMO="--demo"

say()  { printf "\033[1;34m▸\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
fail() { printf "\033[1;31m✗ %s\033[0m\n" "$*" >&2; exit 1; }

say "Checking prerequisites"
command -v uv >/dev/null   || fail "uv is required: curl -LsSf https://astral.sh/uv/install.sh | sh"
command -v node >/dev/null || fail "Node.js 20+ is required: https://nodejs.org"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
(( NODE_MAJOR >= 20 )) || fail "Node.js 20+ is required (found $(node -v))"
command -v psql >/dev/null || fail "PostgreSQL client (psql) is required. macOS: brew install postgresql@17 && brew services start postgresql@17 · Debian/Ubuntu: sudo apt install postgresql"
ok "uv, node $(node -v), psql found"

PGHOST="${PGHOST:-127.0.0.1}"; PGPORT="${PGPORT:-5432}"; PGUSER="${PGUSER:-$(id -un)}"
export PGHOST PGPORT

if [[ ! -f "$ROOT/.env" ]]; then
  say "Creating database role and database on $PGHOST:$PGPORT (as $PGUSER)"
  pg_isready -q -h "$PGHOST" -p "$PGPORT" || fail "PostgreSQL is not reachable on $PGHOST:$PGPORT (set PGHOST/PGPORT)"
  DBPW="$(openssl rand -hex 16)"
  psql -U "$PGUSER" -d postgres -v ON_ERROR_STOP=1 -q <<SQL || fail "could not create role/database — run as a PostgreSQL superuser (PGUSER=...)"
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinelx') THEN
    CREATE ROLE sentinelx LOGIN PASSWORD '$DBPW' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
  ELSE
    ALTER ROLE sentinelx PASSWORD '$DBPW';
  END IF;
END \$\$;
SQL
  psql -U "$PGUSER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='sentinelx'" | grep -q 1 \
    || psql -U "$PGUSER" -d postgres -q -c "CREATE DATABASE sentinelx OWNER sentinelx"
  cp "$ROOT/.env.example" "$ROOT/.env"
  sed -i.bak \
    -e "s|^APP_SECRET=.*|APP_SECRET=$(openssl rand -hex 32)|" \
    -e "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://sentinelx:$DBPW@$PGHOST:$PGPORT/sentinelx|" \
    -e "s|^LOG_JSON=.*|LOG_JSON=false|" \
    "$ROOT/.env" && rm -f "$ROOT/.env.bak"
  chmod 600 "$ROOT/.env"
  ok ".env written (secrets generated)"
else
  ok ".env already exists — keeping it"
fi

say "Installing backend (Python 3.12 via uv)"
(cd "$API" && uv sync --python 3.12 --quiet)
# macOS can mark uv's .pth files hidden, which Python 3.12 ignores — clear the flag
if [[ "$(uname)" == "Darwin" ]]; then chflags nohidden "$API"/.venv/lib/python3.*/site-packages/*.pth 2>/dev/null || true; fi
ok "backend installed"

say "Building web UI"
(cd "$WEB" && npm ci --no-audit --no-fund --silent && npm run build --silent)
ok "web UI built"

say "Initialising database, MITRE ATT&CK, detection rules${DEMO:+ and Demo Lab}"
(cd "$API" && PYTHONPATH=src uv run --no-sync python -m sentinelx.cli init $DEMO)

if command -v ollama >/dev/null; then
  MODEL="$(grep -E '^OLLAMA_MODEL=' "$ROOT/.env" | cut -d= -f2)"
  MODELS="$(ollama list 2>/dev/null || true)"   # capture first: grep -q + pipefail would SIGPIPE ollama
  if grep -q "^${MODEL} " <<<"$MODELS"; then ok "Ollama model $MODEL is installed (AI analyst ready)"
  else say "Optional: enable the AI analyst with:  ollama pull ${MODEL:-qwen3:4b-instruct}"; fi
else
  say "Optional: install Ollama (https://ollama.com) for the local AI analyst"
fi

ok "Setup complete. Start SentinelX with:  ./scripts/start.sh   → http://localhost:8000"
