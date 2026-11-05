"""Least-privilege runtime role (ADR-013).

Migrations run as a schema *owner* role; the API and worker connect as a *runtime* role that owns
nothing. Ownership is what allows ``ALTER TABLE ... DISABLE TRIGGER`` or ``NO FORCE ROW LEVEL SECURITY``,
so a runtime role without it cannot switch off the append-only audit log or tenant isolation even if
the application process is fully compromised.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from sentinelx.config import get_settings

# Tables the runtime role may read but never change.
READ_ONLY_TABLES = ("alembic_version", "audit_chain_head")
# Tables the runtime role may append to and read, but never update or delete.
APPEND_ONLY_TABLES = ("audit_logs",)


def runtime_role() -> str | None:
    return make_url(get_settings().database_url).username


def owner_role() -> str | None:
    s = get_settings()
    return make_url(s.database_owner_url).username if s.database_owner_url else None


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


async def grant_runtime_privileges(conn: AsyncConnection, role: str) -> None:
    r = _ident(role)
    for stmt in (
        f"GRANT USAGE ON SCHEMA public TO {r}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {r}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {r}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {r}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {r}",
        f"REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM {r}",
        f"REVOKE CREATE ON SCHEMA public FROM {r}",
    ):
        await conn.execute(text(stmt))
    for table in READ_ONLY_TABLES:
        await conn.execute(text(f"REVOKE INSERT, UPDATE, DELETE ON {table} FROM {r}"))
    for table in APPEND_ONLY_TABLES:
        await conn.execute(text(f"REVOKE UPDATE, DELETE ON {table} FROM {r}"))


async def apply_runtime_grants() -> dict[str, Any]:
    """Grant the runtime role exactly what it needs. No-op when only one role is configured."""
    s = get_settings()
    runtime, owner = runtime_role(), owner_role()
    if not s.database_owner_url or not runtime or runtime == owner:
        return {"applied": False, "reason": "single-role installation (DATABASE_OWNER_URL not set)"}
    engine = create_async_engine(s.database_owner_url)
    try:
        async with engine.begin() as conn:
            await grant_runtime_privileges(conn, runtime)
    finally:
        await engine.dispose()
    return {"applied": True, "runtime_role": runtime, "owner_role": owner}


async def privilege_report(conn: AsyncConnection) -> dict[str, Any]:
    """What the *current* connection could do to the security controls (used by ``sentinelx doctor``)."""
    row = (
        await conn.execute(
            text(
                "SELECT r.rolsuper, r.rolbypassrls, "
                "(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                " WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relowner = r.oid) AS owned, "
                "has_table_privilege(current_user, 'audit_logs', 'UPDATE') AS audit_update, "
                "has_table_privilege(current_user, 'audit_logs', 'DELETE') AS audit_delete "
                "FROM pg_roles r WHERE r.rolname = current_user"
            )
        )
    ).one()
    return {
        "superuser": bool(row[0]),
        "bypass_rls": bool(row[1]),
        "owned_tables": int(row[2]),
        "audit_update": bool(row[3]),
        "audit_delete": bool(row[4]),
    }
