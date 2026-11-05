# ADR-013: Least-privilege database roles and a tamper-evident audit trail

- **Status:** Accepted
- **Date:** 2026-11-05

## Context
Tenant isolation (ADR-010) and the append-only audit log are enforced inside PostgreSQL: row-level
security policies and `audit_logs` triggers. Until now the application connected as the role that
also *owned* the schema, because it ran the migrations. A table owner can run
`ALTER TABLE ... DISABLE TRIGGER`, `NO FORCE ROW LEVEL SECURITY` or `DROP POLICY`. An intruder with
code execution in the API process, or a SQL injection, would therefore inherit the power to switch
off the very controls that are supposed to survive such a compromise, and to rewrite the audit trail
that would show it.

## Decision
1. **Two roles.** `sentinelx_owner` owns the database and is used only for migrations
   (`DATABASE_OWNER_URL`). The runtime role in `DATABASE_URL` owns nothing. After every migration
   `sentinelx migrate/init` grants it `SELECT/INSERT/UPDATE/DELETE` on the tables (with default
   privileges for future tables), `SELECT/INSERT` only on `audit_logs`, read-only access to
   `alembic_version` and `audit_chain_head`, and no `TRUNCATE`, `TRIGGER` or `CREATE`
   (`persistence/grants.py`).
2. **Hash-chained audit log.** A `BEFORE INSERT` trigger (`SECURITY DEFINER`, owned by the owner role)
   gives each audit row a gap-free sequence number and `row_hash = sha256(prev_hash | seq | fields)`.
   The trigger serializes appends through a single-row `audit_chain_head`. `sentinelx audit-verify`,
   `sentinelx doctor`, `GET /admin/audit-chain` and an hourly worker job recompute every hash *in
   Python*, independently of the database function. A broken chain becomes a critical platform
   incident in every organization.
3. **External anchor.** The verifier prints the head sequence and hash. Recording it outside SentinelX
   (in a ticket or WORM storage) also detects a wholesale rewrite by someone who holds the owner
   credentials.

Fresh installs (`scripts/setup.sh`, Docker Compose, CI) create both roles. Existing installs convert
in place with `scripts/harden-db.sh` (`REASSIGN OWNED`, then the grants). The single-role mode still
works so upgrades don't break. `sentinelx doctor` fails it in production, and the API logs a warning
at startup.

## Consequences
- A compromised application can still read and write tenant data (it has to, in order to work), but
  it can no longer disable RLS or the audit triggers, truncate tables, or edit or delete audit
  records without the hash chain noticing.
- `app.rls_bypass` remains a session setting the runtime role can set. That is accepted: queries are
  built only through SQLAlchemy, and the bypass is needed for login and worker routing. Moving
  system sessions to a third role is a possible future step.
- Audit inserts are serialized through one row lock. The audit rate is low (human actions), so this is
  negligible.
- Operators have one more secret (the owner password). It is needed only while migrating, and can
  live outside the running container.
