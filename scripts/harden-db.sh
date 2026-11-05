#!/usr/bin/env bash
# Split an existing SentinelX database into a schema-owner role and a least-privileged runtime role
# (ADR-013). Afterwards the application role owns nothing, so even a fully compromised API process
# cannot disable the audit-log triggers or row-level security.
#
#   PGUSER=<postgres superuser> ./scripts/harden-db.sh            # databases: sentinelx (+ sentinelx_test if present)
#   DBS="sentinelx" PGUSER=postgres ./scripts/harden-db.sh
#
# It creates role sentinelx_owner (LOGIN, random password), hands it every object owned by the runtime
# role, grants the runtime role data access only, and adds DATABASE_OWNER_URL to .env.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/.env"
say()  { printf "\033[1;34m▸\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
fail() { printf "\033[1;31m✗ %s\033[0m\n" "$*" >&2; exit 1; }

[[ -f "$ENV_FILE" ]] || fail ".env not found - run scripts/setup.sh first"
DB_URL="$(grep -E '^DATABASE_URL=' "$ENV_FILE" | cut -d= -f2-)"
[[ -n "$DB_URL" ]] || fail "DATABASE_URL missing in .env"
if grep -qE '^DATABASE_OWNER_URL=.+' "$ENV_FILE"; then ok "DATABASE_OWNER_URL already set - nothing to do"; exit 0; fi

# postgresql+asyncpg://user[:pw]@host:port/db
rest="${DB_URL#*://}"; creds="${rest%%@*}"; hostpart="${rest#*@}"
APP_ROLE="${creds%%:*}"
HOSTPORT="${hostpart%%/*}"; PGHOST="${HOSTPORT%%:*}"; PGPORT="${HOSTPORT##*:}"
[[ "$PGPORT" == "$PGHOST" ]] && PGPORT=5432
export PGHOST PGPORT
OWNER_ROLE="${OWNER_ROLE:-sentinelx_owner}"
PGUSER="${PGUSER:-$(id -un)}"
DBS="${DBS:-sentinelx sentinelx_test}"
OWNER_PW="$(openssl rand -hex 16)"

say "Creating owner role $OWNER_ROLE on $PGHOST:$PGPORT (as $PGUSER); runtime role is $APP_ROLE"
psql -U "$PGUSER" -d postgres -v ON_ERROR_STOP=1 -q <<SQL || fail "needs a PostgreSQL superuser (PGUSER=...)"
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$OWNER_ROLE') THEN
    CREATE ROLE $OWNER_ROLE LOGIN PASSWORD '$OWNER_PW' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
  ELSE
    ALTER ROLE $OWNER_ROLE PASSWORD '$OWNER_PW';
  END IF;
END \$\$;
ALTER ROLE $APP_ROLE NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
SQL

for db in $DBS; do
  psql -U "$PGUSER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1 || continue
  say "Handing ownership of '$db' to $OWNER_ROLE"
  psql -U "$PGUSER" -d "$db" -v ON_ERROR_STOP=1 -q <<SQL
REASSIGN OWNED BY $APP_ROLE TO $OWNER_ROLE;
ALTER DATABASE $db OWNER TO $OWNER_ROLE;
ALTER SCHEMA public OWNER TO $OWNER_ROLE;
GRANT CONNECT ON DATABASE $db TO $APP_ROLE;
SQL
done

OWNER_URL="postgresql+asyncpg://$OWNER_ROLE:$OWNER_PW@$PGHOST:$PGPORT/${DB_URL##*/}"
printf '\n# Schema owner used only for migrations (ADR-013); the app connects with DATABASE_URL\nDATABASE_OWNER_URL=%s\n' "$OWNER_URL" >> "$ENV_FILE"
chmod 600 "$ENV_FILE"
ok "DATABASE_OWNER_URL added to .env"

say "Applying runtime grants"
(cd "$ROOT/apps/api" && PYTHONPATH=src uv run --no-sync python -m sentinelx.cli migrate)
ok "Done. Check with: cd apps/api && PYTHONPATH=src uv run --no-sync python -m sentinelx.cli doctor"
