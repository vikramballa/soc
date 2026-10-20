from __future__ import annotations

import uuid

from sqlalchemy import select, update

from sentinelx.jobs.queue import enqueue
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import Job


async def test_once_dedup_blocks_while_active_or_done(tenant: uuid.UUID) -> None:
    key = f"test-once:{uuid.uuid4()}"
    async with system_session() as s:
        await enqueue(s, "noop", tenant_id=tenant, dedup_key=key, once=True)
    async with system_session() as s:
        await enqueue(s, "noop", tenant_id=tenant, dedup_key=key, once=True)
        rows = (await s.execute(select(Job).where(Job.dedup_key == key))).scalars().all()
    assert len(rows) == 1  # second enqueue was a no-op while the first is still queued


async def test_once_dedup_allows_retry_after_failure(tenant: uuid.UUID) -> None:
    key = f"test-once-retry:{uuid.uuid4()}"
    async with system_session() as s:
        await enqueue(s, "noop", tenant_id=tenant, dedup_key=key, once=True)
        await s.execute(update(Job).where(Job.dedup_key == key).values(status="failed"))
    async with system_session() as s:
        await enqueue(s, "noop", tenant_id=tenant, dedup_key=key, once=True)
        rows = (await s.execute(select(Job).where(Job.dedup_key == key))).scalars().all()
    assert len(rows) == 2  # a failed prior attempt does not block a retry for the same key


async def test_once_dedup_blocks_after_success(tenant: uuid.UUID) -> None:
    key = f"test-once-done:{uuid.uuid4()}"
    async with system_session() as s:
        await enqueue(s, "noop", tenant_id=tenant, dedup_key=key, once=True)
        await s.execute(update(Job).where(Job.dedup_key == key).values(status="done"))
    async with system_session() as s:
        await enqueue(s, "noop", tenant_id=tenant, dedup_key=key, once=True)
        rows = (await s.execute(select(Job).where(Job.dedup_key == key))).scalars().all()
    assert len(rows) == 1  # already succeeded this window; don't re-run
