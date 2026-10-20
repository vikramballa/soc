# ADR-010: Multi-tenancy with row-level security

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
MSSPs need strict isolation; mistakes in one query must not leak data.

## Decision
Every tenant table has `tenant_id`, FORCE RLS policies keyed on a transaction-local `app.tenant_id`, explicit filters in every query, a non-superuser DB role, tenant header honoured only for SUPER_ADMIN, per-tenant ingest tokens, rule toggles and settings. A small set of system paths (login, job routing) use an explicit bypass flag.

## Consequences
Defense in depth verified by tests; slight overhead per transaction.
