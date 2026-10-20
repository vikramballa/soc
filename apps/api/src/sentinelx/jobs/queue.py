"""PostgreSQL job queue: FOR UPDATE SKIP LOCKED claiming + LISTEN/NOTIFY wake-ups (ADR-003)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.persistence.models import Job


async def enqueue(
    session: AsyncSession,
    kind: str,
    payload: dict[str, Any] | None = None,
    *,
    tenant_id: uuid.UUID | str | None = None,
    dedup_key: str | None = None,
    delay_seconds: float = 0,
    max_attempts: int = 3,
    once: bool = False,
) -> None:
    """Queue a job. ``dedup_key`` collapses duplicates while queued/running; with ``once`` a job with the
    same key is skipped only while it's still active or already succeeded (used for per-hour / per-day
    schedules) - a *failed* prior attempt does not block retrying the same key, so one bad run can't
    silently kill a recurring maintenance/training job for its whole window."""
    if once and dedup_key:
        exists = (
            await session.execute(
                select(Job.id).where(Job.dedup_key == dedup_key, Job.status.in_(("queued", "running", "done"))).limit(1)
            )
        ).first()
        if exists:
            return
    values: dict[str, Any] = {
        "kind": kind,
        "payload": payload or {},
        "tenant_id": uuid.UUID(str(tenant_id)) if tenant_id else None,
        "dedup_key": dedup_key,
        "max_attempts": max_attempts,
        "status": "queued",
        "attempts": 0,
    }
    if delay_seconds:
        values["run_after"] = datetime.now(UTC) + timedelta(seconds=delay_seconds)
    stmt = pg_insert(Job).values(**values)
    if dedup_key:
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["dedup_key"], index_where=text("status IN ('queued','running')")
        )
    await session.execute(stmt)


CLAIM_SQL = text(
    """
    UPDATE jobs SET status = 'running', locked_by = :worker, locked_at = now(), attempts = attempts + 1
    WHERE id = (
        SELECT id FROM jobs
        WHERE status = 'queued' AND run_after <= now() AND kind = ANY(:kinds)
        ORDER BY id
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    RETURNING id, tenant_id, kind, payload, attempts, max_attempts
    """
)
