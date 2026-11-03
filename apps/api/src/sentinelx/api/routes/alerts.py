"""Alerts."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, client_ip, get_db, require
from sentinelx.api.schemas import AlertOut, EventOut, Page
from sentinelx.export.ocsf import detection_finding
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import Alert, AlertEvent, SecurityEvent
from sentinelx.security.rbac import Perm
from sentinelx.services.audit import audit

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertPatch(BaseModel):
    status: Literal["open", "acknowledged", "closed"]


@router.get("", response_model=Page[AlertOut])
async def list_alerts(
    principal: Principal = Depends(require(Perm.ALERT_READ)),
    db: AsyncSession = Depends(get_db),
    status_: str | None = Query(None, alias="status"),
    level: str | None = None,
    source: str | None = None,
    q: str | None = Query(None, max_length=200),
    host: str | None = None,
    rule_uid: str | None = None,
    incident_id: uuid.UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[AlertOut]:
    stmt = select(Alert).where(Alert.tenant_id == principal.tenant_id)
    if status_:
        stmt = stmt.where(Alert.status == status_)
    if level:
        stmt = stmt.where(Alert.level.in_(level.split(",")))
    if source:
        stmt = stmt.where(Alert.source.in_(source.split(",")))
    if host:
        stmt = stmt.where(Alert.hostname == host)
    if rule_uid:
        stmt = stmt.where(Alert.rule_uid == rule_uid)
    if incident_id:
        stmt = stmt.where(Alert.incident_id == incident_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                Alert.title.ilike(like),
                Alert.hostname.ilike(like),
                Alert.username.ilike(like),
                Alert.src_ip.ilike(like),
                Alert.domain.ilike(like),
            )
        )
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(Alert.last_event_at.desc()).limit(limit).offset(offset))).scalars().all()
    return Page(items=[AlertOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: uuid.UUID, principal: Principal = Depends(require(Perm.ALERT_READ)), db: AsyncSession = Depends(get_db)
) -> AlertOut:
    a = await db.get(Alert, alert_id)
    if a is None or a.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return AlertOut.model_validate(a)


@router.get("/{alert_id}/events", response_model=list[EventOut])
async def alert_events(
    alert_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.ALERT_READ)),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
) -> list[EventOut]:
    a = await db.get(Alert, alert_id)
    if a is None or a.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    rows = (
        (
            await db.execute(
                select(SecurityEvent)
                .join(AlertEvent, AlertEvent.event_id == SecurityEvent.id)
                .where(AlertEvent.alert_id == alert_id, SecurityEvent.tenant_id == principal.tenant_id)
                .order_by(SecurityEvent.timestamp)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [EventOut.model_validate(r) for r in rows]


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: uuid.UUID,
    body: AlertPatch,
    request: Request,
    principal: Principal = Depends(require(Perm.INCIDENT_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> AlertOut:
    a = await db.get(Alert, alert_id)
    if a is None or a.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    old = a.status
    a.status = body.status
    await audit(
        db,
        action="alert.update",
        resource_type="alert",
        resource_id=a.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"status": [old, body.status]},
        source_ip=client_ip(request),
    )
    return AlertOut.model_validate(a)


@router.get("/stats/by-rule")
async def by_rule(
    principal: Principal = Depends(require(Perm.ALERT_READ)), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(
                Alert.rule_uid, Alert.title, func.count(), func.sum(Alert.event_count), func.max(Alert.last_event_at)
            )
            .where(Alert.tenant_id == principal.tenant_id)
            .group_by(Alert.rule_uid, Alert.title)
            .order_by(func.count().desc())
            .limit(50)
        )
    ).all()
    return [
        {"rule_uid": r, "title": t, "alerts": n, "events": int(e or 0), "last_seen": last} for r, t, n, e, last in rows
    ]


@router.get("/export/ocsf")
async def export_ocsf(
    request: Request,
    principal: Principal = Depends(require(Perm.REPORT_GENERATE)),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(5000, ge=1, le=20000),
) -> Response:
    """Alerts seen in the last ``hours`` as OCSF Detection Findings (class 2004), one JSON object per line
    (NDJSON) - the shape SIEM, data-lake and SOAR pipelines ingest directly."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = (
        (
            await db.execute(
                select(Alert)
                .where(Alert.tenant_id == principal.tenant_id, Alert.last_event_at >= since)
                .order_by(Alert.last_event_at)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    await audit(
        db,
        action="alert.export",
        resource_type="alert",
        resource_id=None,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"format": "ocsf", "hours": hours, "count": len(rows)},
        source_ip=client_ip(request),
    )
    catalog = get_catalog()
    body = "".join(json.dumps(jsonable_encoder(detection_finding(a, catalog))) + "\n" for a in rows)
    return Response(
        body,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="sentinelx-alerts-{hours}h-ocsf.ndjson"'},
    )
