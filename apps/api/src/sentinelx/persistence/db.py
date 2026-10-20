"""Database engine and tenant-scoped sessions.

Tenant isolation is enforced twice:
1. Application layer - every query is built with an explicit ``tenant_id`` filter.
2. PostgreSQL row-level security - each transaction sets ``app.tenant_id``; policies reject rows of
   any other tenant even if an application filter is forgotten (defense in depth, ADR-010).

``system_session`` sets ``app.rls_bypass`` for the few code paths that legitimately operate
before a tenant is known (login, session lookup, worker job routing, migrations/seed).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from sentinelx.config import get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        s = get_settings()
        _engine = create_async_engine(
            s.database_url,
            pool_size=s.database_pool_size,
            max_overflow=s.database_pool_size,
            pool_pre_ping=True,
            connect_args={"server_settings": {"application_name": "sentinelx", "timezone": "UTC"}},
        )
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


async def set_tenant(session: AsyncSession, tenant_id: uuid.UUID | str) -> None:
    await session.execute(
        text("SELECT set_config('app.tenant_id', :t, true), set_config('app.rls_bypass', 'off', true)"),
        {"t": str(tenant_id)},
    )


async def set_bypass(session: AsyncSession) -> None:
    await session.execute(text("SELECT set_config('app.rls_bypass', 'on', true)"))


@asynccontextmanager
async def tenant_session(tenant_id: uuid.UUID | str) -> AsyncIterator[AsyncSession]:
    """One transaction bound to a single tenant. Commits on success, rolls back on error."""
    async with sessionmaker()() as session, session.begin():
        await set_tenant(session, tenant_id)
        yield session


@asynccontextmanager
async def system_session() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as session, session.begin():
        await set_bypass(session)
        yield session
