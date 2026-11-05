"""Telemetry health: which agents and sensors are sending, which went quiet, planned-maintenance mutes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, client_ip, get_db, require, require_fresh
from sentinelx.config import get_settings
from sentinelx.hunting.service import silence_threshold_seconds
from sentinelx.persistence.models import TelemetrySource
from sentinelx.security.rbac import Perm
from sentinelx.services import selfmon
from sentinelx.services.audit import audit

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


class MuteIn(BaseModel):
    minutes: int = Field(ge=15, le=7 * 24 * 60)
    reason: str = Field(min_length=3, max_length=300)


def _status(src: TelemetrySource, now: datetime) -> str:
    if src.muted_until is not None and src.muted_until > now:
        return "muted"
    if src.silent_since is not None:
        return "silent"
    s = get_settings()
    if src.event_count < s.silence_min_events or src.last_seen - src.first_seen < timedelta(
        hours=s.silence_min_history_hours
    ):
        return "learning"
    if (now - src.last_seen).total_seconds() > silence_threshold_seconds(src.avg_gap_seconds):
        return "overdue"  # past its threshold; the next hunt run raises the alert
    return "healthy"


def _out(src: TelemetrySource, now: datetime) -> dict[str, Any]:
    return {
        "id": str(src.id),
        "source_type": src.source_type,
        "sender": src.hostname,
        "status": _status(src, now),
        "first_seen": src.first_seen,
        "last_seen": src.last_seen,
        "last_event_at": src.last_event_at,
        "events": src.event_count,
        "usual_gap_seconds": round(src.avg_gap_seconds, 1) if src.avg_gap_seconds is not None else None,
        "alert_after_minutes": round(silence_threshold_seconds(src.avg_gap_seconds) / 60),
        "quiet_minutes": max(0, int((now - src.last_seen).total_seconds() // 60)),
        "silent_since": src.silent_since,
        "muted_until": src.muted_until,
        "mute_reason": src.mute_reason,
    }


@router.get("/sources")
async def list_sources(
    principal: Principal = Depends(require(Perm.RULE_READ)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    now = datetime.now(UTC)
    rows = (
        (
            await db.execute(
                select(TelemetrySource)
                .where(TelemetrySource.tenant_id == principal.tenant_id)
                .order_by(TelemetrySource.source_type, TelemetrySource.hostname)
            )
        )
        .scalars()
        .all()
    )
    items = [_out(r, now) for r in rows]
    order = {"silent": 0, "overdue": 1, "muted": 2, "learning": 3, "healthy": 4}
    items.sort(key=lambda x: (order[x["status"]], x["source_type"], x["sender"]))
    counts: dict[str, int] = {}
    for it in items:
        counts[it["status"]] = counts.get(it["status"], 0) + 1
    return {"items": items, "counts": counts}


async def _get(db: AsyncSession, principal: Principal, source_id: uuid.UUID) -> TelemetrySource:
    src = await db.get(TelemetrySource, source_id)
    if src is None or src.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source not found")
    return src


@router.post("/sources/{source_id}/mute")
async def mute_source(
    source_id: uuid.UUID,
    body: MuteIn,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.RULE_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Planned maintenance: no silence alert for this sender until the mute ends."""
    now = datetime.now(UTC)
    src = await _get(db, principal, source_id)
    src.muted_until = now + timedelta(minutes=body.minutes)
    src.mute_reason = body.reason
    ip = client_ip(request)
    await audit(
        db,
        action="telemetry.mute",
        resource_type="telemetry_source",
        resource_id=src.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"sender": src.hostname, "minutes": body.minutes, "reason": body.reason},
        source_ip=ip,
    )
    # muting is also what an intruder would do before stopping an agent
    await selfmon.emit(
        db,
        principal.tenant_id,
        "telemetry.mute",
        f"{principal.email} muted silence alerts for {src.hostname} for {body.minutes} min: {body.reason}",
        actor=principal.email,
        src_ip=ip,
        details={"sender": src.hostname, "minutes": body.minutes},
    )
    return _out(src, now)


@router.delete("/sources/{source_id}/mute")
async def unmute_source(
    source_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Perm.RULE_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    src = await _get(db, principal, source_id)
    src.muted_until, src.mute_reason = None, None
    await audit(
        db,
        action="telemetry.unmute",
        resource_type="telemetry_source",
        resource_id=src.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )
    return _out(src, datetime.now(UTC))


@router.delete("/sources/{source_id}", status_code=204)
async def forget_source(
    source_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.RULE_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> None:
    """For decommissioned senders. It reappears automatically if it ever sends again."""
    src = await _get(db, principal, source_id)
    sender = src.hostname
    await db.delete(src)
    ip = client_ip(request)
    await audit(
        db,
        action="telemetry.forget",
        resource_type="telemetry_source",
        resource_id=source_id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"sender": sender},
        source_ip=ip,
    )
    await selfmon.emit(
        db,
        principal.tenant_id,
        "telemetry.forget",
        f"{principal.email} removed telemetry sender {sender} from monitoring",
        actor=principal.email,
        src_ip=ip,
        details={"sender": sender},
    )
