#!/bin/sh
# Creates the least-privileged application role. The app must NOT connect as a superuser:
# superusers bypass PostgreSQL row-level security, which SentinelX uses for tenant isolation.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE sentinelx LOGIN PASSWORD '${SENTINELX_DB_PASSWORD}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
CREATE DATABASE sentinelx OWNER sentinelx;
SQL
