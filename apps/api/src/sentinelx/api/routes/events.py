"""Event search (bounded time ranges + keyset pagination)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, get_db, require
from sentinelx.api.schemas import EventDetail, EventOut
from sentinelx.persistence.models import AlertEvent, SecurityEvent
from sentinelx.security.rbac import Perm

router = APIRouter(prefix="/events", tags=["events"])
MAX_RANGE = timedelta(days=31)


def _range(start: datetime | None, end: datetime | None, hours: int) -> tuple[datetime, datetime]:
    end = end or datetime.now(UTC)
    start = start or end - timedelta(hours=hours)
    if end - start > MAX_RANGE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Time range is limited to 31 days")
    return start, end


@router.get("")
async def search_events(
    principal: Principal = Depends(require(Perm.EVENT_READ)),
    db: AsyncSession = Depends(get_db),
    start: datetime | None = None,
    end: datetime | None = None,
    hours: int = Query(24, ge=1, le=744),
    source: str | None = None,
    event_type: str | None = None,
    outcome: str | None = None,
    host: str | None = None,
    user: str | None = None,
    ip: str | None = Query(None, max_length=64),
    q: str | None = Query(None, max_length=200, description="Free text in summary, command line, domain, url"),
    cursor: str | None = Query(None, description="Opaque keyset cursor from a previous page"),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    t0, t1 = _range(start, end, hours)
    conds = [
        SecurityEvent.tenant_id == principal.tenant_id,
        SecurityEvent.timestamp >= t0,
        SecurityEvent.timestamp <= t1,
    ]
    if source:
        conds.append(SecurityEvent.source_type.in_(source.split(",")))
    if event_type:
        conds.append(SecurityEvent.event_type.in_(event_type.split(",")))
    if outcome:
        conds.append(SecurityEvent.outcome == outcome)
    if host:
        conds.append(SecurityEvent.hostname == host)
    if user:
        conds.append(SecurityEvent.username == user.lower())
    if ip:
        conds.append(or_(SecurityEvent.src_ip == ip, SecurityEvent.dest_ip == ip))
    if q:
        like = f"%{q}%"
        conds.append(
            or_(
                SecurityEvent.summary.ilike(like),
                SecurityEvent.process_command_line.ilike(like),
                SecurityEvent.domain.ilike(like),
                SecurityEvent.url.ilike(like),
                SecurityEvent.rule_name.ilike(like),
            )
        )
    page_conds = list(conds)
    if cursor:
        try:
            ts_s, id_s = cursor.split("|", 1)
            cts, cid = datetime.fromisoformat(ts_s), uuid.UUID(id_s)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor") from e
        page_conds.append(
            or_(SecurityEvent.timestamp < cts, and_(SecurityEvent.timestamp == cts, SecurityEvent.id < cid))
        )
    rows = (
        (
            await db.execute(
                select(SecurityEvent)
                .where(*page_conds)
                .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
                .limit(limit + 1)
            )
        )
        .scalars()
        .all()
    )
    more = len(rows) > limit
    rows = rows[:limit]
    # bounded count (capped for speed on large tenants)
    total = (
        await db.execute(
            select(func.count()).select_from(select(SecurityEvent.id).where(*conds).limit(10001).subquery())
        )
    ).scalar_one()
    next_cursor = f"{rows[-1].timestamp.isoformat()}|{rows[-1].id}" if more and rows else None
    return {
        "items": [EventOut.model_validate(r).model_dump() for r in rows],
        "total": total,
        "total_capped": total > 10000,
        "next_cursor": next_cursor,
        "start": t0,
        "end": t1,
    }


@router.get("/histogram")
async def histogram(
    principal: Principal = Depends(require(Perm.EVENT_READ)),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(24, ge=1, le=744),
    host: str | None = None,
) -> dict[str, Any]:
    t1 = datetime.now(UTC)
    t0 = t1 - timedelta(hours=hours)
    bucket = "hour" if hours > 6 else "minute"
    params: dict[str, Any] = {"t": principal.tenant_id, "t0": t0, "t1": t1}
    host_sql = ""
    if host:
        host_sql = "AND hostname = :host"
        params["host"] = host
    rows = (
        await db.execute(
            text(
                f"SELECT date_trunc('{bucket}', timestamp) AS b, source_type, count(*) FROM security_events "
                f"WHERE tenant_id = :t AND timestamp BETWEEN :t0 AND :t1 {host_sql} GROUP BY b, source_type ORDER BY b"
            ),
            params,
        )
    ).all()
    return {"bucket": bucket, "points": [{"t": b, "source": s, "count": n} for b, s, n in rows]}


@router.get("/{event_id}", response_model=EventDetail)
async def get_event(
    event_id: uuid.UUID, principal: Principal = Depends(require(Perm.EVENT_READ)), db: AsyncSession = Depends(get_db)
) -> EventDetail:
    ev = await db.get(SecurityEvent, event_id)
    if ev is None or ev.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found (it may have aged out of retention)")
    return EventDetail.model_validate(ev)


@router.get("/{event_id}/alerts")
async def event_alerts(
    event_id: uuid.UUID, principal: Principal = Depends(require(Perm.EVENT_READ)), db: AsyncSession = Depends(get_db)
) -> list[str]:
    rows = await db.execute(
        select(AlertEvent.alert_id).where(AlertEvent.event_id == event_id, AlertEvent.tenant_id == principal.tenant_id)
    )
    return [str(r) for r in rows.scalars().all()]
