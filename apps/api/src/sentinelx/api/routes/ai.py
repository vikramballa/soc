"""AI analyst status, model selection (local models only) and investigation feedback."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.ai.ollama import LlmUnavailable, OllamaClient
from sentinelx.ai.service import model_for_tenant
from sentinelx.api.deps import Principal, client_ip, get_db, require
from sentinelx.api.routes.analytics import redact_ai_reason
from sentinelx.api.schemas import AiInvestigationOut, FeedbackIn
from sentinelx.config import get_settings
from sentinelx.persistence.models import AiInvestigation, Tenant
from sentinelx.security.rbac import Perm
from sentinelx.services.audit import audit

router = APIRouter(prefix="/ai", tags=["ai"])


class ModelIn(BaseModel):
    model: str = Field(min_length=1, max_length=120)


@router.get("/status")
async def status_(
    principal: Principal = Depends(require(Perm.INCIDENT_READ)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    model = await model_for_tenant(principal.tenant_id)
    client = OllamaClient()
    st = await client.status(model)
    try:
        models = await client.local_models()
    except LlmUnavailable:
        models = []
    stats = dict(
        (
            await db.execute(
                select(AiInvestigation.status, func.count())
                .where(AiInvestigation.tenant_id == principal.tenant_id)
                .group_by(AiInvestigation.status)
            )
        ).all()
    )
    fb = dict(
        (
            await db.execute(
                select(AiInvestigation.feedback, func.count())
                .where(AiInvestigation.tenant_id == principal.tenant_id, AiInvestigation.feedback.isnot(None))
                .group_by(AiInvestigation.feedback)
            )
        ).all()
    )
    total_done = stats.get("completed", 0) + stats.get("rejected", 0)
    return {
        "enabled": get_settings().ai_enabled,
        "available": st.get("available", False),
        "reason": redact_ai_reason(st.get("reason"), principal.can(Perm.ADMIN_MANAGE)),
        "model": model,
        "ollama_url": get_settings().ollama_url if principal.can(Perm.ADMIN_MANAGE) else None,
        "local_models": models,
        "core_detection": "operational",
        "quality": {
            "investigations": stats,
            "invalid_output_rate": round(stats.get("rejected", 0) / total_done, 3) if total_done else None,
            "feedback": fb,
        },
    }


@router.put("/model")
async def set_model(
    body: ModelIn,
    request: Request,
    principal: Principal = Depends(require(Perm.ADMIN_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        installed = {m["name"] for m in await OllamaClient().local_models()}
    except LlmUnavailable as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(e)) from e
    if body.model not in installed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Only locally installed Ollama models can be used (cloud models are not allowed)",
        )
    t = await db.get(Tenant, principal.tenant_id)
    assert t is not None
    t.settings = {**(t.settings or {}), "ai_model": body.model}
    await audit(
        db,
        action="ai.model_change",
        resource_type="tenant",
        resource_id=t.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=t.id,
        details={"model": body.model},
        source_ip=client_ip(request),
    )
    return {"model": body.model}


@router.get("/investigations/{investigation_id}", response_model=AiInvestigationOut)
async def get_investigation(
    investigation_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> AiInvestigationOut:
    inv = await db.get(AiInvestigation, investigation_id)
    if inv is None or inv.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return AiInvestigationOut.model_validate(inv)


@router.post("/investigations/{investigation_id}/feedback", response_model=AiInvestigationOut)
async def feedback(
    investigation_id: uuid.UUID,
    body: FeedbackIn,
    request: Request,
    principal: Principal = Depends(require(Perm.INCIDENT_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> AiInvestigationOut:
    inv = await db.get(AiInvestigation, investigation_id)
    if inv is None or inv.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    inv.feedback = body.feedback
    await audit(
        db,
        action="ai.feedback",
        resource_type="ai_investigation",
        resource_id=inv.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"feedback": body.feedback},
        source_ip=client_ip(request),
    )
    return AiInvestigationOut.model_validate(inv)
