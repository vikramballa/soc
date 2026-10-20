"""MITRE ATT&CK view: matrix with observed techniques (evidence-backed only)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, get_db, require
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import Alert, DetectionRule, Incident
from sentinelx.security.rbac import Perm

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/matrix")
async def matrix(
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
    days: int = Query(30, ge=1, le=365),
) -> dict[str, Any]:
    cat = get_catalog()
    # observed = techniques on promoted incidents; evidence = events on alerts mapping to the technique
    inc_rows = (
        await db.execute(
            select(func.unnest(Incident.mitre_techniques).label("t"), func.count(), func.max(Incident.last_event_at))
            .where(
                Incident.tenant_id == principal.tenant_id,
                Incident.promoted.is_(True),
                Incident.status != "merged",
                Incident.last_event_at >= func.now() - func.make_interval(0, 0, 0, days),
            )
            .group_by("t")
        )
    ).all()
    ev_rows = (
        await db.execute(
            select(func.unnest(Alert.mitre_techniques).label("t"), func.sum(Alert.event_count))
            .where(
                Alert.tenant_id == principal.tenant_id,
                Alert.last_event_at >= func.now() - func.make_interval(0, 0, 0, days),
            )
            .group_by("t")
        )
    ).all()
    covered = {
        t
        for row in (
            await db.execute(select(DetectionRule.mitre_techniques).where(DetectionRule.enabled.is_(True)))
        ).scalars()
        for t in row
    }
    observed = {t: {"incidents": n, "last_observed": last} for t, n, last in inc_rows}
    evidence = {t: int(n or 0) for t, n in ev_rows}
    tactics = []
    for tac in cat.tactics:
        techs = []
        for t in cat.techniques.values():
            if tac.shortname in t.tactics and not t.is_subtechnique:
                subs = [s for s in cat.techniques.values() if s.parent_id == t.id]
                obs_ids = [x for x in [t.id, *[s.id for s in subs]] if x in observed]
                techs.append(
                    {
                        "id": t.id,
                        "name": t.name,
                        "observed": bool(obs_ids),
                        "incidents": sum(observed[x]["incidents"] for x in obs_ids),
                        "evidence": sum(evidence.get(x, 0) for x in [t.id, *[s.id for s in subs]]),
                        "last_observed": max((observed[x]["last_observed"] for x in obs_ids), default=None),
                        "covered": t.id in covered or any(s.id in covered for s in subs),
                        "observed_subtechniques": [x for x in obs_ids if x != t.id],
                    }
                )
        techs.sort(key=lambda x: (not x["observed"], not x["covered"], x["name"]))
        tactics.append({"id": tac.id, "shortname": tac.shortname, "name": tac.name, "techniques": techs})
    return {
        "attack_version": cat.version,
        "days": days,
        "tactics": tactics,
        "observed_total": len(observed),
        "covered_total": len(covered),
    }


@router.get("/techniques/{technique_id}")
async def technique(
    technique_id: str, principal: Principal = Depends(require(Perm.INCIDENT_READ)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    cat = get_catalog()
    t = cat.get(technique_id)
    if t is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown ATT&CK technique")
    incs = (
        (
            await db.execute(
                select(Incident)
                .where(
                    Incident.tenant_id == principal.tenant_id,
                    Incident.promoted.is_(True),
                    Incident.status != "merged",
                    Incident.mitre_techniques.any(t.id),
                )
                .order_by(Incident.last_event_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    rules = (
        await db.execute(
            select(DetectionRule.rule_uid, DetectionRule.title, DetectionRule.enabled).where(
                DetectionRule.mitre_techniques.any(t.id)
            )
        )
    ).all()
    return {
        "technique": {
            "id": t.id,
            "name": t.name,
            "tactics": list(t.tactics),
            "description": t.description,
            "detection": t.detection,
            "url": t.url,
            "platforms": list(t.platforms),
            "parent_id": t.parent_id,
        },
        "incidents": [
            {
                "id": str(i.id),
                "number": i.number,
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
                "last_event_at": i.last_event_at,
            }
            for i in incs
        ],
        "rules": [{"rule_uid": u, "title": ti, "enabled": en} for u, ti, en in rules],
    }


@router.get("/techniques")
async def techniques(
    principal: Principal = Depends(require(Perm.RULE_READ)), q: str | None = Query(None, max_length=100)
) -> list[dict[str, Any]]:
    cat = get_catalog()
    out = []
    for t in cat.techniques.values():
        if q and q.lower() not in t.name.lower() and q.upper() not in t.id:
            continue
        out.append({"id": t.id, "name": t.name, "tactics": list(t.tactics), "is_subtechnique": t.is_subtechnique})
    return out[:200]
