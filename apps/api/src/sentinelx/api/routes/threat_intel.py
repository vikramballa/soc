"""Threat intelligence: lookups, watchlist, feed import."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, client_ip, get_db, require
from sentinelx.api.schemas import FeedImportIn, IndicatorIn, IndicatorOut, Page, TiResultOut
from sentinelx.config import get_settings
from sentinelx.persistence.models import Indicator, SecurityEvent, ThreatIntelResult
from sentinelx.security.rbac import Perm
from sentinelx.services.audit import audit
from sentinelx.threat_intel.service import (
    classify_indicator,
    enrich,
    import_indicators,
    normalize_indicator,
    parse_feed,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.get("/lookup/{indicator:path}")
async def lookup(
    indicator: str,
    request: Request,
    principal: Principal = Depends(require(Perm.THREATINTEL_READ)),
    db: AsyncSession = Depends(get_db),
    refresh: bool = False,
) -> dict[str, Any]:
    itype = classify_indicator(indicator)
    if itype is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Enter an IP address, domain, file hash or URL")
    value = normalize_indicator(itype, indicator)
    await enrich(db, principal.tenant_id, [(itype, value)], local_only=False, force=refresh)
    results = (
        (
            await db.execute(
                select(ThreatIntelResult).where(
                    ThreatIntelResult.tenant_id == principal.tenant_id, ThreatIntelResult.value == value
                )
            )
        )
        .scalars()
        .all()
    )
    since = datetime.now(UTC) - timedelta(days=30)
    field_conds = {
        "ip": or_(SecurityEvent.src_ip == value, SecurityEvent.dest_ip == value),
        "domain": SecurityEvent.domain == value,
        "hash": SecurityEvent.file_hash == value,
        "url": SecurityEvent.url == value,
    }[itype]
    seen = (
        await db.execute(
            select(
                func.count(),
                func.min(SecurityEvent.timestamp),
                func.max(SecurityEvent.timestamp),
                func.array_agg(func.distinct(SecurityEvent.hostname)),
            ).where(SecurityEvent.tenant_id == principal.tenant_id, SecurityEvent.timestamp >= since, field_conds)
        )
    ).one()
    await audit(
        db,
        action="threatintel.lookup",
        resource_type="indicator",
        resource_id=value[:120],
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )
    verdicts = [r.verdict for r in results]
    overall = (
        "malicious"
        if "malicious" in verdicts
        else "suspicious"
        if "suspicious" in verdicts
        else "no_match"
        if not results or all(v == "unknown" for v in verdicts)
        else verdicts[0]
    )
    return {
        "indicator": value,
        "type": itype,
        "overall": overall,
        "results": [TiResultOut.model_validate(r).model_dump() for r in results],
        "sightings": {
            "events_30d": seen[0],
            "first_seen": seen[1],
            "last_seen": seen[2],
            "hosts": [h for h in (seen[3] or []) if h],
        },
        "providers": ["local"] + (["misp"] if get_settings().misp_url else []),
    }


@router.get("/indicators", response_model=Page[IndicatorOut])
async def list_indicators(
    principal: Principal = Depends(require(Perm.THREATINTEL_READ)),
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    source: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[IndicatorOut]:
    stmt = select(Indicator).where(Indicator.tenant_id == principal.tenant_id)
    if q:
        stmt = stmt.where(or_(Indicator.value.ilike(f"%{q}%"), Indicator.description.ilike(f"%{q}%")))
    if source:
        stmt = stmt.where(Indicator.source == source)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(Indicator.created_at.desc()).limit(limit).offset(offset))).scalars().all()
    return Page(items=[IndicatorOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/sources")
async def sources(
    principal: Principal = Depends(require(Perm.THREATINTEL_READ)), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(Indicator.source, func.count(), func.max(Indicator.last_seen))
            .where(Indicator.tenant_id == principal.tenant_id)
            .group_by(Indicator.source)
        )
    ).all()
    return [{"source": s, "indicators": n, "updated": u} for s, n, u in rows]


@router.post("/indicators", response_model=IndicatorOut, status_code=201)
async def add_indicator(
    body: IndicatorIn,
    request: Request,
    principal: Principal = Depends(require(Perm.THREATINTEL_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> IndicatorOut:
    itype = body.type or classify_indicator(body.value)
    if itype is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Not a valid IP, domain, hash or URL")
    try:
        value = normalize_indicator(itype, body.value)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Invalid {itype}") from e
    await import_indicators(
        db,
        principal.tenant_id,
        [
            {
                "type": itype,
                "value": value,
                "source": "analyst-watchlist",
                "confidence": body.confidence,
                "verdict": body.verdict,
                "tags": body.tags,
                "description": body.description,
                "reference": None,
            }
        ],
        expires_days=body.expires_days,
    )
    await audit(
        db,
        action="threatintel.indicator_add",
        resource_type="indicator",
        resource_id=value[:120],
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"type": itype, "verdict": body.verdict},
        source_ip=client_ip(request),
    )
    row = (
        await db.execute(
            select(Indicator).where(
                Indicator.tenant_id == principal.tenant_id,
                Indicator.value == value,
                Indicator.source == "analyst-watchlist",
            )
        )
    ).scalar_one()
    return IndicatorOut.model_validate(row)


@router.delete("/indicators/{indicator_id}", status_code=204)
async def delete_indicator(
    indicator_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Perm.THREATINTEL_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> None:
    res = await db.execute(
        delete(Indicator)
        .where(Indicator.id == indicator_id, Indicator.tenant_id == principal.tenant_id)
        .returning(Indicator.value)
    )
    value = res.scalar_one_or_none()
    if value is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Indicator not found")
    await audit(
        db,
        action="threatintel.indicator_delete",
        resource_type="indicator",
        resource_id=value[:120],
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )


@router.post("/feeds/import")
async def import_feed(
    body: FeedImportIn,
    request: Request,
    principal: Principal = Depends(require(Perm.THREATINTEL_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        items = parse_feed(body.content, body.format, body.source, body.default_confidence)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Could not parse feed: {e}") from e
    n = await import_indicators(db, principal.tenant_id, items, expires_days=body.expires_days)
    await audit(
        db,
        action="threatintel.feed_import",
        resource_type="feed",
        resource_id=body.source,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"imported": n, "format": body.format},
        source_ip=client_ip(request),
    )
    return {"imported": n, "skipped": max(0, len(body.content.splitlines()) - n) if body.format == "txt" else None}
