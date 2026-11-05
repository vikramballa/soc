"""Administration: users, organization settings, ingest tokens, integrations, audit log, demo data."""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, client_ip, get_db, require, require_fresh
from sentinelx.api.routes.analytics import ai_status, worker_status
from sentinelx.api.schemas import AuditOut, Page, UserIn, UserOut, UserPatch
from sentinelx.config import get_settings
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import (
    AuditLog,
    IngestionSource,
    IngestToken,
    QuarantinedEvent,
    Session,
    Tenant,
    User,
)
from sentinelx.security.oidc import oidc_enabled
from sentinelx.security.passwords import hash_password, new_token, password_problems, token_hash
from sentinelx.security.rbac import ROLE_DESCRIPTIONS, ROLE_PERMISSIONS, Perm, can_assign, can_manage
from sentinelx.services import selfmon
from sentinelx.services.audit import audit

router = APIRouter(prefix="/admin", tags=["admin"])


class TenantSettingsIn(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=200)
    correlation_window_minutes: int | None = Field(None, ge=5, le=1440)
    correlation_ignore: list[str] | None = Field(None, max_length=200)
    event_retention_days: int | None = Field(None, ge=1, le=3650)


class TokenIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    # empty = any source / any address (kept for compatibility); scoping is strongly recommended
    allowed_sources: list[str] = Field(default_factory=list, max_length=8)
    allowed_cidrs: list[str] = Field(default_factory=list, max_length=50)


class TenantIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")


@router.get("/roles")
async def roles(principal: Principal = Depends(require(Perm.ADMIN_MANAGE))) -> list[dict[str, Any]]:
    return [
        {"role": r.value, "description": ROLE_DESCRIPTIONS[r], "permissions": sorted(p.value for p in perms)}
        for r, perms in ROLE_PERMISSIONS.items()
    ]


@router.get("/users", response_model=list[UserOut])
async def list_users(
    principal: Principal = Depends(require(Perm.ADMIN_MANAGE)), db: AsyncSession = Depends(get_db)
) -> list[UserOut]:
    rows = (
        (await db.execute(select(User).where(User.tenant_id == principal.tenant_id).order_by(User.created_at)))
        .scalars()
        .all()
    )
    return [UserOut.model_validate(u) for u in rows]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserIn,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.ADMIN_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    if not can_assign(principal.role, body.role):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only grant roles below your own")
    problems = password_problems(body.password)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Password " + "; ".join(problems))
    email = body.email.lower()
    async with system_session() as s:
        if (await s.execute(select(User.id).where(User.email == email))).first():
            raise HTTPException(status.HTTP_409_CONFLICT, "A user with this email already exists")
    user = User(
        id=uuid.uuid4(),
        tenant_id=principal.tenant_id,
        email=email,
        display_name=body.display_name,
        role=body.role,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    await db.flush()
    await audit(
        db,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"email": email, "role": body.role},
        source_ip=client_ip(request),
    )
    await selfmon.emit(
        db,
        principal.tenant_id,
        "user.create",
        f"{principal.email} created SentinelX user {email} with role {body.role}",
        actor=principal.email,
        src_ip=client_ip(request),
        details={"target_user": email, "role": body.role},
    )
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserPatch,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.ADMIN_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id != principal.user_id and not can_manage(principal.role, user.role):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only manage users with a lower role than yours")
    changes = body.model_dump(exclude_unset=True)
    if user.id == principal.user_id and (changes.get("is_active") is False or "role" in changes):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot change your own role or deactivate yourself")
    if "role" in changes and not can_assign(principal.role, changes["role"]):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only grant roles below your own")
    if user.auth_provider == "oidc" and "role" in changes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Single sign-on users get their role from Keycloak")
    for k, v in changes.items():
        setattr(user, k, v)
    if changes.get("is_active") is False:
        await db.execute(
            update(Session)
            .where(Session.user_id == user.id, Session.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
    await audit(
        db,
        action="user.update",
        resource_type="user",
        resource_id=user.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details=changes,
        source_ip=client_ip(request),
    )
    await selfmon.emit(
        db,
        principal.tenant_id,
        "user.update",
        f"{principal.email} changed SentinelX user {user.email}: {', '.join(sorted(changes)) or 'no fields'}",
        actor=principal.email,
        src_ip=client_ip(request),
        details={"target_user": user.email, "role": changes.get("role"), "is_active": changes.get("is_active")},
    )
    return UserOut.model_validate(user)


@router.get("/settings")
async def get_tenant_settings(
    principal: Principal = Depends(require(Perm.ADMIN_MANAGE)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    s = get_settings()
    t = await db.get(Tenant, principal.tenant_id)
    assert t is not None
    ts = t.settings or {}
    return {
        "name": t.name,
        "slug": t.slug,
        "demo": bool(ts.get("demo")),
        "correlation_window_minutes": ts.get("correlation_window_minutes", s.correlation_window_minutes),
        "correlation_ignore": ts.get("correlation_ignore", []),
        "event_retention_days": ts.get("event_retention_days", s.event_retention_days),
        "disabled_rules": ts.get("disabled_rules", []),
        "ai_model": ts.get("ai_model", s.ollama_model),
        "defaults": {
            "incident_promote_risk": s.incident_promote_risk,
            "incident_promote_severity": s.incident_promote_severity,
            "ml_alone_can_promote": s.ml_alone_can_promote,
        },
    }


@router.put("/settings")
async def update_tenant_settings(
    body: TenantSettingsIn,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.ADMIN_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    t = await db.get(Tenant, principal.tenant_id)
    assert t is not None
    changes = body.model_dump(exclude_unset=True)
    if "correlation_ignore" in changes:
        for item in changes["correlation_ignore"] or []:
            if not re.match(r"^(host|user|ip|domain|hash):.+$", item):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, f"'{item}' must look like kind:value (e.g. ip:10.0.0.2)"
                )
    if "name" in changes:
        t.name = changes.pop("name")
    t.settings = {**(t.settings or {}), **changes}
    await audit(
        db,
        action="tenant.settings",
        resource_type="tenant",
        resource_id=t.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=t.id,
        details=body.model_dump(exclude_unset=True),
        source_ip=client_ip(request),
    )
    await selfmon.emit(
        db,
        principal.tenant_id,
        "tenant.settings",
        f"{principal.email} changed organization settings: {', '.join(sorted(body.model_dump(exclude_unset=True)))}",
        actor=principal.email,
        src_ip=client_ip(request),
        details={
            "changed": sorted(body.model_dump(exclude_unset=True)),
            "event_retention_days": changes.get("event_retention_days"),
            "correlation_ignore_count": len(changes.get("correlation_ignore") or []),
        },
    )
    return await get_tenant_settings(principal, db)


@router.get("/ingest-tokens")
async def list_tokens(
    principal: Principal = Depends(require(Perm.ADMIN_MANAGE)), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(IngestToken)
                .where(IngestToken.tenant_id == principal.tenant_id)
                .order_by(IngestToken.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "prefix": t.prefix,
            "created_at": t.created_at,
            "last_used_at": t.last_used_at,
            "last_used_ip": t.last_used_ip,
            "allowed_sources": t.allowed_sources or [],
            "allowed_cidrs": t.allowed_cidrs or [],
            "revoked": t.revoked_at is not None,
        }
        for t in rows
    ]


@router.post("/ingest-tokens", status_code=201)
async def create_token(
    body: TokenIn,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.ADMIN_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    from sentinelx.ingestion.pipeline import TOKEN_SOURCES

    bad = [x for x in body.allowed_sources if x not in TOKEN_SOURCES]
    if bad:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown source(s) {bad}; use {', '.join(TOKEN_SOURCES)}"
        )
    cidrs: list[str] = []
    for c in body.allowed_cidrs:
        try:
            cidrs.append(str(ipaddress.ip_network(c.strip(), strict=False)))
        except ValueError as e:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"'{c}' is not an IP address or network") from e
    raw = "sxi_" + new_token(30)
    tok = IngestToken(
        id=uuid.uuid4(),
        tenant_id=principal.tenant_id,
        name=body.name,
        prefix=raw[:10],
        token_hash=token_hash(raw),
        allowed_sources=sorted(set(body.allowed_sources)),
        allowed_cidrs=cidrs,
        known_ips=[],
    )
    db.add(tok)
    await audit(
        db,
        action="ingest_token.create",
        resource_type="ingest_token",
        resource_id=tok.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"name": body.name, "allowed_sources": tok.allowed_sources, "allowed_cidrs": cidrs},
        source_ip=client_ip(request),
    )
    await selfmon.emit(
        db,
        principal.tenant_id,
        "ingest_token.create",
        f"{principal.email} created ingest token {body.name}"
        + ("" if tok.allowed_sources or cidrs else " with no source or network restriction"),
        actor=principal.email,
        src_ip=client_ip(request),
        details={"token_name": body.name, "unrestricted": not (tok.allowed_sources or cidrs)},
    )
    return {"id": str(tok.id), "name": tok.name, "token": raw, "note": "Copy this token now — it is shown only once."}


@router.delete("/ingest-tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.ADMIN_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> None:
    tok = await db.get(IngestToken, token_id)
    if tok is None or tok.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    tok.revoked_at = datetime.now(UTC)
    await audit(
        db,
        action="ingest_token.revoke",
        resource_type="ingest_token",
        resource_id=tok.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )
    await selfmon.emit(
        db,
        principal.tenant_id,
        "ingest_token.revoke",
        f"{principal.email} revoked ingest token {tok.name}",
        actor=principal.email,
        src_ip=client_ip(request),
        details={"token_name": tok.name},
    )


@router.get("/integrations")
async def integrations(
    principal: Principal = Depends(require(Perm.RULE_READ)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    s = get_settings()
    from sentinelx.ai.service import model_for_tenant

    model = await model_for_tenant(principal.tenant_id)
    sources = (
        (await db.execute(select(IngestionSource).where(IngestionSource.tenant_id == principal.tenant_id)))
        .scalars()
        .all()
    )
    quarantined = (
        await db.execute(
            select(func.count()).select_from(QuarantinedEvent).where(QuarantinedEvent.tenant_id == principal.tenant_id)
        )
    ).scalar_one()
    by_source = {x.source_type: x for x in sources}

    def src(name: str, configured: bool, how: str) -> dict[str, Any]:
        row = by_source.get(name)
        return {
            "name": name,
            "configured": configured or row is not None,
            "how": how,
            "events_total": row.events_total if row else 0,
            "failures": row.failures_total if row else 0,
            "last_ingest_at": row.last_ingest_at if row else None,
            "last_error": row.last_error if row else None,
        }

    ai = await ai_status(model)
    return {
        "telemetry": [
            src(
                "wazuh",
                bool(s.wazuh_alerts_path or s.wazuh_indexer_url),
                "Wazuh indexer polling or alerts.json tailing, or HTTP push to /api/v1/ingest/wazuh",
            ),
            src("suricata", bool(s.suricata_eve_path), "EVE JSON tailing or HTTP push to /api/v1/ingest/suricata"),
            src("zeek", bool(s.zeek_log_dir), "JSON/TSV log directory tailing or HTTP push to /api/v1/ingest/zeek"),
            src("sentinelx", False, "Canonical-format events via HTTP push to /api/v1/ingest/sentinelx"),
        ],
        "services": [
            {"name": "PostgreSQL", "status": "connected", "detail": "Application state and event store"},
            {"name": "Background worker", **(await worker_status(db))},
            {
                "name": "Ollama (local AI)",
                "status": "available" if ai.get("available") else "unavailable",
                "detail": ai.get("reason") or f"model {model}",
                "url": s.ollama_url,
            },
            {
                "name": "MISP threat intelligence",
                "status": "configured" if s.misp_url else "not configured",
                "detail": s.misp_url or "Set MISP_URL and MISP_API_KEY to enable",
            },
            {
                "name": "OpenSearch",
                "status": "configured" if s.opensearch_url else "not configured",
                "detail": s.opensearch_url or "Optional: high-volume search sink (OPENSEARCH_URL)",
            },
            {
                "name": "Keycloak SSO",
                "status": "configured" if oidc_enabled() else "not configured",
                "detail": s.keycloak_url or "Optional: set AUTH_MODE=both and KEYCLOAK_URL",
            },
        ],
        "quarantined_events": quarantined,
    }


@router.get("/quarantine")
async def quarantine(
    principal: Principal = Depends(require(Perm.ADMIN_MANAGE)),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(QuarantinedEvent)
                .where(QuarantinedEvent.tenant_id == principal.tenant_id)
                .order_by(QuarantinedEvent.received_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(r.id),
            "source": r.source_type,
            "error": r.error,
            "payload": r.payload[:2000],
            "received_at": r.received_at,
        }
        for r in rows
    ]


@router.get("/audit-logs", response_model=Page[AuditOut])
async def audit_logs(
    principal: Principal = Depends(require(Perm.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
    action: str | None = None,
    actor: str | None = None,
    result: str | None = None,
    scope: str = Query("organization", pattern="^(organization|platform)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[AuditOut]:
    """``scope=platform`` (super admin only) shows records that belong to no organization, such as failed
    sign-ins for unknown email addresses - useful to spot password spraying against SentinelX itself."""
    if scope == "platform" and not principal.can(Perm.PLATFORM_MANAGE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing permission: platform:manage")
    stmt = select(AuditLog).where(
        AuditLog.tenant_id.is_(None) if scope == "platform" else AuditLog.tenant_id == principal.tenant_id
    )
    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"{action}%"))
    if actor:
        stmt = stmt.where(AuditLog.actor.ilike(f"%{actor}%"))
    if result:
        stmt = stmt.where(AuditLog.result == result)

    async def run(session: AsyncSession) -> Page[AuditOut]:
        total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
        rows = (
            (await session.execute(stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)))
            .scalars()
            .all()
        )
        return Page(items=[AuditOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)

    if scope == "platform":  # tenant-less rows are hidden by row-level security in tenant sessions
        async with system_session() as sdb:
            return await run(sdb)
    return await run(db)


@router.post("/tenants", status_code=201)
async def create_tenant(
    body: TenantIn, request: Request, principal: Principal = Depends(require(Perm.PLATFORM_MANAGE))
) -> dict[str, Any]:
    async with system_session() as s:
        if (await s.execute(select(Tenant.id).where(Tenant.slug == body.slug))).first():
            raise HTTPException(status.HTTP_409_CONFLICT, "Slug already in use")
        t = Tenant(id=uuid.uuid4(), slug=body.slug, name=body.name, settings={})
        s.add(t)
        await s.flush()
        await audit(
            s,
            action="tenant.create",
            resource_type="tenant",
            resource_id=t.id,
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=t.id,
            details={"slug": body.slug},
            source_ip=client_ip(request),
        )
        return {"id": str(t.id), "name": t.name, "slug": t.slug}


@router.post("/demo", status_code=202)
async def load_demo_data(
    request: Request, principal: Principal = Depends(require(Perm.PLATFORM_MANAGE))
) -> dict[str, Any]:
    """(Re)create the synthetic Demo Lab organization. Runs in the background worker."""
    from sentinelx.jobs.queue import enqueue

    async with system_session() as s:
        await enqueue(s, "load_demo", {}, dedup_key="load_demo", max_attempts=1)
        await audit(
            s,
            action="demo.load",
            resource_type="tenant",
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=principal.home_tenant_id,
            source_ip=client_ip(request),
        )
    return {"queued": True, "message": "Demo Lab is being (re)built. It takes about 10–20 seconds."}


@router.get("/audit-chain")
async def audit_chain(principal: Principal = Depends(require(Perm.PLATFORM_MANAGE))) -> dict[str, Any]:
    """Recompute the tamper-evident audit hash chain. Record ``head_hash`` outside SentinelX to also detect
    a complete rewrite by someone with database access."""
    from sentinelx.services.audit_chain import verify_chain

    async with system_session() as s:
        report = await verify_chain(s)
    return {**report.as_dict(), "checked_at": datetime.now(UTC)}
