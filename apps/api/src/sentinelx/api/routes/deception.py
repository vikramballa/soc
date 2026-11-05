"""Deception: honeytokens (decoy accounts, hosts, addresses, files, credentials) that nothing legitimate
should ever touch. Detection is by the ``sx-honeytoken`` built-in, which cannot be switched off."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.deps import Principal, client_ip, get_db, require, require_fresh
from sentinelx.persistence.models import Honeytoken
from sentinelx.security.rbac import Perm
from sentinelx.services import selfmon
from sentinelx.services.audit import audit

router = APIRouter(prefix="/deception", tags=["deception"])

Kind = Literal["account", "host", "ip", "domain", "file", "credential", "url"]
# substring-matched kinds need enough characters not to match ordinary telemetry by accident
_MIN_LEN = {"file": 8, "credential": 12, "url": 10, "account": 4, "host": 4, "domain": 4}

KIND_HELP = {
    "account": "A user name that exists in the directory but no person or service uses "
    "(e.g. a stale-looking 'svc_backup_old' with an attractive description).",
    "host": "A host name that resolves but runs nothing - any logon, connection or lookup is suspicious.",
    "ip": "An unused internal address. Port scans and lateral movement touch it; nothing legitimate does.",
    "domain": "An internal DNS name only an intruder reading configuration files would look up.",
    "file": "A file path planted with a tempting name (e.g. '\\\\fileserver\\finance\\passwords_2026.xlsx').",
    "credential": "A fake password, API key or connection string left in a script or wiki page.",
    "url": "An internal URL that only appears in a decoy document.",
}


class HoneytokenIn(BaseModel):
    kind: Kind
    value: str = Field(min_length=2, max_length=512)
    description: str = Field("", max_length=1000)


class HoneytokenPatch(BaseModel):
    enabled: bool | None = None
    description: str | None = Field(None, max_length=1000)


def _normalize(kind: str, value: str) -> str:
    v = value.strip()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as e:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Enter a valid IP address") from e
    if len(v) < _MIN_LEN.get(kind, 2):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"A {kind} decoy needs at least {_MIN_LEN[kind]} characters so it never matches normal activity",
        )
    return v.lower() if kind in ("account", "host", "domain") else v


def _out(t: Honeytoken) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "kind": t.kind,
        "value": t.value,
        "description": t.description,
        "enabled": t.enabled,
        "created_by": t.created_by,
        "created_at": t.created_at,
        "last_triggered_at": t.last_triggered_at,
        "trigger_count": t.trigger_count,
    }


@router.get("/honeytokens")
async def list_honeytokens(
    principal: Principal = Depends(require(Perm.DECEPTION_MANAGE)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    rows = (
        (
            await db.execute(
                select(Honeytoken)
                .where(Honeytoken.tenant_id == principal.tenant_id)
                .order_by(Honeytoken.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return {"items": [_out(t) for t in rows], "kinds": KIND_HELP}


@router.post("/honeytokens", status_code=201)
async def create_honeytoken(
    body: HoneytokenIn,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.DECEPTION_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tok = Honeytoken(
        id=uuid.uuid4(),
        tenant_id=principal.tenant_id,
        kind=body.kind,
        value=_normalize(body.kind, body.value),
        description=body.description,
        created_by=principal.email,
    )
    try:
        async with db.begin_nested():
            db.add(tok)
            await db.flush()
    except IntegrityError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, "That decoy already exists") from e
    await audit(
        db,
        action="honeytoken.create",
        resource_type="honeytoken",
        resource_id=tok.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"kind": tok.kind},  # the value itself stays out of the audit trail
        source_ip=client_ip(request),
    )
    return _out(tok)


async def _get(db: AsyncSession, principal: Principal, token_id: uuid.UUID) -> Honeytoken:
    tok = await db.get(Honeytoken, token_id)
    if tok is None or tok.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Decoy not found")
    return tok


@router.patch("/honeytokens/{token_id}")
async def update_honeytoken(
    token_id: uuid.UUID,
    body: HoneytokenPatch,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.DECEPTION_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tok = await _get(db, principal, token_id)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        if v is not None:
            setattr(tok, k, v)
    await audit(
        db,
        action="honeytoken.update",
        resource_type="honeytoken",
        resource_id=tok.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details=changes,
        source_ip=client_ip(request),
    )
    if changes.get("enabled") is False:
        await selfmon.emit(
            db,
            principal.tenant_id,
            "honeytoken.disable",
            f"{principal.email} switched off a {tok.kind} decoy",
            actor=principal.email,
            src_ip=client_ip(request),
            severity=40,
        )
    return _out(tok)


@router.delete("/honeytokens/{token_id}", status_code=204)
async def delete_honeytoken(
    token_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_fresh(Perm.DECEPTION_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> None:
    tok = await _get(db, principal, token_id)
    kind = tok.kind
    await db.delete(tok)
    await audit(
        db,
        action="honeytoken.delete",
        resource_type="honeytoken",
        resource_id=token_id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"kind": kind},
        source_ip=client_ip(request),
    )
    await selfmon.emit(
        db,
        principal.tenant_id,
        "honeytoken.disable",
        f"{principal.email} deleted a {kind} decoy",
        actor=principal.email,
        src_ip=client_ip(request),
        severity=40,
    )
