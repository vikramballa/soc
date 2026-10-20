"""Detection rules: list, inspect (YAML + versions), enable/disable, test against recent events, sync."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, client_ip, get_db, require
from sentinelx.api.schemas import RuleDetail, RuleOut, RulePatch
from sentinelx.config import get_settings
from sentinelx.detection.engine import (
    CUSTOM_PREFIX,
    event_to_dict,
    get_rules,
    refresh_custom_rules,
    sync_rules_to_db,
)
from sentinelx.detection.sigma.rules import content_hash, load_rules
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import Alert, DetectionRule, RuleVersion, SecurityEvent, Tenant
from sentinelx.security.rbac import Perm
from sentinelx.services.audit import audit

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("")
async def list_rules(
    principal: Principal = Depends(require(Perm.RULE_READ)),
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    kind: str | None = None,
) -> dict[str, Any]:
    stmt = select(DetectionRule)
    if q:
        stmt = stmt.where(
            or_(
                DetectionRule.title.ilike(f"%{q}%"),
                DetectionRule.description.ilike(f"%{q}%"),
                func.array_to_string(DetectionRule.mitre_techniques, ",").ilike(f"%{q}%"),
            )
        )
    if kind:
        stmt = stmt.where(DetectionRule.kind == kind)
    rules = (
        (await db.execute(stmt.order_by(DetectionRule.kind, DetectionRule.severity.desc(), DetectionRule.title)))
        .scalars()
        .all()
    )
    since = datetime.now(UTC) - timedelta(days=7)
    hits = dict(
        (
            await db.execute(
                select(Alert.rule_uid, func.count())
                .where(Alert.tenant_id == principal.tenant_id, Alert.created_at >= since)
                .group_by(Alert.rule_uid)
            )
        ).all()
    )
    rejected = [{"path": p, "error": e} for p, e in get_rules().ruleset.errors]
    disabled = await _tenant_disabled(db, principal)
    return {
        "items": [
            {
                **RuleOut.model_validate(r).model_dump(),
                "enabled": r.enabled and r.rule_uid not in disabled,
                "globally_enabled": r.enabled,
                "alerts_7d": hits.get(r.rule_uid, 0),
                "custom": r.source_path is None and r.kind in ("sigma", "correlation"),
            }
            for r in rules
        ],
        "rejected": rejected,
    }


async def _tenant_disabled(db: AsyncSession, principal: Principal) -> set[str]:
    t = await db.get(Tenant, principal.tenant_id)
    return set(((t.settings or {}) if t else {}).get("disabled_rules", []))


@router.get("/{rule_uid}")
async def get_rule(
    rule_uid: str, principal: Principal = Depends(require(Perm.RULE_READ)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    r = (await db.execute(select(DetectionRule).where(DetectionRule.rule_uid == rule_uid))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    versions = (
        (await db.execute(select(RuleVersion).where(RuleVersion.rule_id == r.id).order_by(RuleVersion.version.desc())))
        .scalars()
        .all()
    )
    recent = (
        (
            await db.execute(
                select(Alert)
                .where(Alert.tenant_id == principal.tenant_id, Alert.rule_uid == rule_uid)
                .order_by(Alert.last_event_at.desc())
                .limit(10)
            )
        )
        .scalars()
        .all()
    )
    disabled = await _tenant_disabled(db, principal)
    return {
        "rule": {
            **RuleDetail.model_validate(r).model_dump(),
            "enabled": r.enabled and r.rule_uid not in disabled,
            "globally_enabled": r.enabled,
        },
        "versions": [
            {"version": v.version, "created_at": v.created_at, "created_by": v.created_by, "sha256": v.content_sha256}
            for v in versions
        ],
        "recent_alerts": [
            {
                "id": str(a.id),
                "title": a.title,
                "hostname": a.hostname,
                "last_event_at": a.last_event_at,
                "incident_id": str(a.incident_id) if a.incident_id else None,
            }
            for a in recent
        ],
    }


@router.patch("/{rule_uid}")
async def toggle_rule(
    rule_uid: str,
    body: RulePatch,
    request: Request,
    principal: Principal = Depends(require(Perm.RULE_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Enable/disable a rule for the current organization only (the shared rule catalogue is untouched)."""
    r = (await db.execute(select(DetectionRule).where(DetectionRule.rule_uid == rule_uid))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    t = await db.get(Tenant, principal.tenant_id)
    assert t is not None
    disabled = set((t.settings or {}).get("disabled_rules", []))
    if body.enabled:
        disabled.discard(rule_uid)
    else:
        disabled.add(rule_uid)
    t.settings = {**(t.settings or {}), "disabled_rules": sorted(disabled)}
    await audit(
        db,
        action="rule.enable" if body.enabled else "rule.disable",
        resource_type="detection_rule",
        resource_id=rule_uid,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )
    return {
        **RuleOut.model_validate(r).model_dump(),
        "enabled": r.enabled and body.enabled,
        "globally_enabled": r.enabled,
    }


@router.post("/sync")
async def sync(request: Request, principal: Principal = Depends(require(Perm.PLATFORM_MANAGE))) -> dict[str, Any]:
    """Reload the versioned rules repository (installation-wide -> SUPER_ADMIN only)."""
    async with system_session() as s:
        result = await sync_rules_to_db(s, actor=principal.email)
        await audit(
            s,
            action="rule.sync",
            resource_type="detection_rule",
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=principal.tenant_id,
            details=result,
            source_ip=client_ip(request),
        )
    return result


class RuleIn(BaseModel):
    content: str = Field(min_length=20, max_length=50_000, description="One Sigma rule or correlation rule (YAML)")


async def _validate_custom(db: AsyncSession, content: str, editing: str | None = None) -> dict[str, Any]:
    """Compile the rule together with every existing rule so correlation references resolve."""
    try:
        docs = [d for d in yaml.safe_load_all(content) if d]
    except yaml.YAMLError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Invalid YAML: {e}") from e
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Provide exactly one rule document")
    doc = docs[0]
    uid = str(doc.get("id") or "")
    if not uid:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "The rule needs an 'id' (a UUID)")
    existing = (await db.execute(select(DetectionRule).where(DetectionRule.rule_uid == uid))).scalar_one_or_none()
    if existing is not None and uid != editing:
        raise HTTPException(status.HTTP_409_CONFLICT, f"A rule with id {uid} already exists")
    others = [
        (f"{CUSTOM_PREFIX}{u}", c)
        for u, c in (
            await db.execute(
                select(DetectionRule.rule_uid, DetectionRule.content).where(
                    DetectionRule.source_path.is_(None),
                    DetectionRule.kind.in_(["sigma", "correlation"]),
                    DetectionRule.rule_uid != uid,
                )
            )
        ).all()
    ]
    label = f"{CUSTOM_PREFIX}{uid}"
    rs = load_rules(get_settings().sigma_rules_dir, [*others, (label, content)])
    errs = [e for p, e in rs.errors if p.startswith(label)]
    if errs:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Rule rejected: " + "; ".join(errs))
    item = next((r for r in [*rs.rules, *rs.correlations] if r.uid == uid), None)
    if item is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Rule could not be compiled")
    return {
        "uid": uid,
        "item": item,
        "kind": "correlation" if "correlation" in doc else "sigma",
        "existing": existing,
    }


@router.post("", status_code=201)
async def create_rule(
    body: RuleIn,
    request: Request,
    principal: Principal = Depends(require(Perm.PLATFORM_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Add a custom Sigma rule (installation-wide; validated by the same compiler as repository rules)."""
    v = await _validate_custom(db, body.content)
    item = v["item"]
    sha = content_hash(body.content)
    row = DetectionRule(
        id=uuid.uuid4(),
        rule_uid=v["uid"],
        name=item.name,
        title=item.title,
        description=item.description,
        kind=v["kind"],
        status=item.status,
        level=item.level,
        severity=item.severity,
        tags=item.tags,
        mitre_techniques=item.techniques,
        content=body.content,
        content_sha256=sha,
        version=1,
        enabled=True,
        generates_alerts=getattr(item, "generate", True),
        source_path=None,
        falsepositives=item.falsepositives,
    )
    db.add(row)
    await db.flush()
    db.add(
        RuleVersion(
            id=uuid.uuid4(),
            rule_id=row.id,
            version=1,
            content=body.content,
            content_sha256=sha,
            created_by=principal.email,
        )
    )
    await audit(
        db,
        action="rule.create",
        resource_type="detection_rule",
        resource_id=v["uid"],
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"title": item.title},
        source_ip=client_ip(request),
    )
    return {"rule_uid": v["uid"], "title": item.title, "version": 1}


@router.put("/{rule_uid}")
async def update_rule(
    rule_uid: str,
    body: RuleIn,
    request: Request,
    principal: Principal = Depends(require(Perm.PLATFORM_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    v = await _validate_custom(db, body.content, editing=rule_uid)
    row = v["existing"]
    if row is None or row.source_path is not None or v["uid"] != rule_uid:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Only custom rules can be edited here (repository rules are edited in security/sigma-rules)",
        )
    item = v["item"]
    sha = content_hash(body.content)
    if sha != row.content_sha256:
        row.version += 1
        row.title, row.description, row.status, row.level = item.title, item.description, item.status, item.level
        row.severity, row.tags, row.mitre_techniques = item.severity, item.tags, item.techniques
        row.content, row.content_sha256, row.falsepositives = body.content, sha, item.falsepositives
        row.updated_at = func.now()
        db.add(
            RuleVersion(
                id=uuid.uuid4(),
                rule_id=row.id,
                version=row.version,
                content=body.content,
                content_sha256=sha,
                created_by=principal.email,
            )
        )
        await audit(
            db,
            action="rule.update",
            resource_type="detection_rule",
            resource_id=rule_uid,
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=principal.tenant_id,
            details={"version": row.version},
            source_ip=client_ip(request),
        )
    return {"rule_uid": rule_uid, "version": row.version}


@router.delete("/{rule_uid}", status_code=204)
async def delete_rule(
    rule_uid: str,
    request: Request,
    principal: Principal = Depends(require(Perm.PLATFORM_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = (await db.execute(select(DetectionRule).where(DetectionRule.rule_uid == rule_uid))).scalar_one_or_none()
    if row is None or row.source_path is not None or row.kind not in ("sigma", "correlation"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only custom rules can be deleted")
    await db.delete(row)
    await audit(
        db,
        action="rule.delete",
        resource_type="detection_rule",
        resource_id=rule_uid,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )


@router.post("/{rule_uid}/test")
async def test_rule(
    rule_uid: str,
    principal: Principal = Depends(require(Perm.RULE_READ)),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(24, ge=1, le=168),
) -> dict[str, Any]:
    """Dry-run a Sigma rule against recent stored events (bounded) - useful when tuning noise."""
    compiled = await refresh_custom_rules(db)
    rule = next((r for r in compiled.ruleset.rules if r.uid == rule_uid), None)
    if rule is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only single-event Sigma rules can be dry-run")
    since = datetime.now(UTC) - timedelta(hours=hours)
    stmt = select(SecurityEvent).where(SecurityEvent.tenant_id == principal.tenant_id, SecurityEvent.timestamp >= since)
    if rule.event_types:
        stmt = stmt.where(SecurityEvent.event_type.in_(rule.event_types))
    rows = (await db.execute(stmt.order_by(SecurityEvent.timestamp.desc()).limit(20000))).scalars().all()
    matches = [r for r in rows if rule.matches(event_to_dict(r))]
    hosts: dict[str, int] = {}
    for m in matches:
        hosts[m.hostname or m.src_ip or "-"] = hosts.get(m.hostname or m.src_ip or "-", 0) + 1
    return {
        "evaluated": len(rows),
        "matched": len(matches),
        "by_host": hosts,
        "samples": [{"id": str(m.id), "timestamp": m.timestamp, "summary": m.summary} for m in matches[:10]],
    }
