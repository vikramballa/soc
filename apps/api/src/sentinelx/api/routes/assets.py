"""Assets (hosts) and identities (monitored user accounts)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, client_ip, get_db, require
from sentinelx.api.schemas import AssetOut, AssetPatch, IdentityOut, IdentityPatch, IncidentSummary, Page
from sentinelx.persistence.models import Asset, Identity, Incident, IncidentEntity, SecurityEvent
from sentinelx.security.rbac import Perm
from sentinelx.services.audit import audit

router = APIRouter(tags=["assets"])


@router.get("/assets", response_model=Page[AssetOut])
async def list_assets(
    principal: Principal = Depends(require(Perm.ASSET_READ)),
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    sort: str = Query("risk", pattern="^(risk|name|seen)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[AssetOut]:
    stmt = select(Asset).where(Asset.tenant_id == principal.tenant_id)
    if q:
        stmt = stmt.where(
            or_(
                Asset.hostname.ilike(f"%{q}%"),
                Asset.owner.ilike(f"%{q}%"),
                func.array_to_string(Asset.ip_addresses, ",").ilike(f"%{q}%"),
            )
        )
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    order = {
        "risk": (Asset.risk_score.desc(), Asset.criticality.desc()),
        "name": (Asset.hostname,),
        "seen": (Asset.last_seen.desc().nulls_last(),),
    }[sort]
    rows = (await db.execute(stmt.order_by(*order).limit(limit).offset(offset))).scalars().all()
    return Page(items=[AssetOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: uuid.UUID, principal: Principal = Depends(require(Perm.ASSET_READ)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    a = await db.get(Asset, asset_id)
    if a is None or a.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    incs = (
        (
            await db.execute(
                select(Incident)
                .join(IncidentEntity, IncidentEntity.incident_id == Incident.id)
                .where(
                    IncidentEntity.tenant_id == principal.tenant_id,
                    IncidentEntity.kind == "host",
                    IncidentEntity.value == a.hostname,
                    Incident.promoted.is_(True),
                    Incident.status != "merged",
                )
                .order_by(Incident.created_at.desc())
                .limit(20)
            )
        )
        .scalars()
        .all()
    )
    by_type = (
        await db.execute(
            select(SecurityEvent.event_type, func.count())
            .where(SecurityEvent.tenant_id == principal.tenant_id, SecurityEvent.hostname == a.hostname)
            .group_by(SecurityEvent.event_type)
        )
    ).all()
    return {
        "asset": AssetOut.model_validate(a).model_dump(),
        "incidents": [IncidentSummary.model_validate(i).model_dump() for i in incs],
        "event_counts": {t: n for t, n in by_type},
    }


@router.patch("/assets/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetPatch,
    request: Request,
    principal: Principal = Depends(require(Perm.ASSET_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> AssetOut:
    a = await db.get(Asset, asset_id)
    if a is None or a.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(a, k, v)
    await audit(
        db,
        action="asset.update",
        resource_type="asset",
        resource_id=a.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details=changes,
        source_ip=client_ip(request),
    )
    return AssetOut.model_validate(a)


@router.get("/identities", response_model=Page[IdentityOut])
async def list_identities(
    principal: Principal = Depends(require(Perm.ASSET_READ)),
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[IdentityOut]:
    stmt = select(Identity).where(Identity.tenant_id == principal.tenant_id)
    if q:
        stmt = stmt.where(or_(Identity.username.ilike(f"%{q}%"), Identity.department.ilike(f"%{q}%")))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        (await db.execute(stmt.order_by(Identity.risk_score.desc(), Identity.username).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return Page(items=[IdentityOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.patch("/identities/{identity_id}", response_model=IdentityOut)
async def update_identity(
    identity_id: uuid.UUID,
    body: IdentityPatch,
    request: Request,
    principal: Principal = Depends(require(Perm.ASSET_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> IdentityOut:
    i = await db.get(Identity, identity_id)
    if i is None or i.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Identity not found")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(i, k, v)
    await audit(
        db,
        action="identity.update",
        resource_type="identity",
        resource_id=i.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details=changes,
        source_ip=client_ip(request),
    )
    return IdentityOut.model_validate(i)
