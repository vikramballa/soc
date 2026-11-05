#!/bin/sh
# Creates the database roles (ADR-013). The app must NOT connect as a superuser (superusers bypass
# PostgreSQL row-level security) and must not own the schema (owners can disable triggers and RLS):
#   sentinelx_owner - owns the database, used only by migrations (DATABASE_OWNER_URL)
#   sentinelx       - runtime role, data access only (DATABASE_URL); grants applied by `sentinelx init`
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE sentinelx_owner LOGIN PASSWORD '${SENTINELX_OWNER_DB_PASSWORD}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
CREATE ROLE sentinelx LOGIN PASSWORD '${SENTINELX_DB_PASSWORD}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
CREATE DATABASE sentinelx OWNER sentinelx_owner;
GRANT CONNECT ON DATABASE sentinelx TO sentinelx;
SQL
