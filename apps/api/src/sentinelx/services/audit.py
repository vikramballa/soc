"""Audit trail. Records are append-only (enforced by a database trigger)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.logging import request_id_var
from sentinelx.persistence.models import AuditLog

_SENSITIVE = ("password", "token", "secret", "api_key", "authorization")


def _scrub(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if any(s in k.lower() for s in _SENSITIVE):
            out[k] = "[REDACTED]"
        elif isinstance(v, dict):
            out[k] = _scrub(v)
        else:
            out[k] = v
    return out


async def audit(
    session: AsyncSession,
    *,
    action: str,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    actor: str = "system",
    actor_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    result: str = "success",
    details: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> None:
    session.add(
        AuditLog(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor=actor[:320],
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            result=result,
            details=_scrub(details or {}),
            source_ip=source_ip,
            request_id=request_id_var.get(),
        )
    )
