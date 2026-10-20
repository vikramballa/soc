"""Dashboard summary (noise-reduction funnel, attention queue, health) and ML analytics. All numbers are
computed from stored data - nothing is hard-coded."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.ai.ollama import OllamaClient
from sentinelx.ai.service import model_for_tenant
from sentinelx.api.deps import Principal, client_ip, get_db, require
from sentinelx.api.schemas import IncidentSummary
from sentinelx.jobs.queue import enqueue
from sentinelx.ml.service import FEATURE_LABELS
from sentinelx.persistence.models import (
    MlModel,
    MlPrediction,
    WorkerHeartbeat,
)
from sentinelx.security.rbac import Perm
from sentinelx.services import dashboard as dashboard_data
from sentinelx.services.audit import audit

router = APIRouter(tags=["analytics"])

_ai_cache: dict[str, tuple[float, dict[str, Any]]] = {}


async def ai_status(model: str) -> dict[str, Any]:
    hit = _ai_cache.get(model)
    if hit and time.monotonic() - hit[0] < 20:
        return hit[1]
    st = await OllamaClient().status(model)
    _ai_cache[model] = (time.monotonic(), st)
    return st


async def worker_status(db: AsyncSession) -> dict[str, Any]:
    beats = (await db.execute(select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen.desc()))).scalars().all()
    now = datetime.now(UTC)
    alive = [b for b in beats if now - b.last_seen < timedelta(seconds=45)]
    queued = (await db.execute(text("SELECT count(*) FROM jobs WHERE status = 'queued'"))).scalar_one()
    return {
        "running": bool(alive),
        "workers": len(alive),
        "queued_jobs": queued,
        "last_seen": beats[0].last_seen if beats else None,
    }


@router.get("/dashboard/summary")
async def dashboard(
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(24, ge=1, le=24 * 90),
) -> dict[str, Any]:
    tenant_id = principal.tenant_id
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    open_by_severity, attention = await dashboard_data.open_incidents(db, tenant_id)
    model = await model_for_tenant(tenant_id)
    ai = await ai_status(model)
    return {
        "window_hours": hours,
        "funnel": await dashboard_data.noise_funnel(db, tenant_id, since),
        "open_by_severity": open_by_severity,
        "open_total": sum(open_by_severity.values()),
        "attention": [IncidentSummary.model_validate(i).model_dump() for i in attention],
        "trend": await dashboard_data.trends(db, tenant_id, now),
        **await dashboard_data.riskiest_entities(db, tenant_id),
        "top_techniques": await dashboard_data.top_techniques(db, tenant_id, since),
        "threat_intel_matches": await dashboard_data.threat_intel_matches(db, tenant_id, since),
        "ingestion": await dashboard_data.ingestion_health(db, tenant_id, now),
        "metrics": await dashboard_data.response_metrics(db, tenant_id),
        "system": {
            "core_detection": "operational",
            "worker": await worker_status(db),
            "ai": {"available": ai.get("available", False), "model": model, "reason": ai.get("reason")},
        },
    }


@router.get("/analytics/anomalies")
async def anomalies(
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(72, ge=1, le=24 * 30),
    only_anomalies: bool = False,
) -> dict[str, Any]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    model = (
        await db.execute(
            select(MlModel)
            .where(MlModel.tenant_id == principal.tenant_id, MlModel.status == "active")
            .order_by(MlModel.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    stmt = select(MlPrediction).where(MlPrediction.tenant_id == principal.tenant_id, MlPrediction.window_start >= since)
    if only_anomalies:
        stmt = stmt.where(MlPrediction.is_anomaly.is_(True))
    preds = (
        (
            await db.execute(
                stmt.order_by(MlPrediction.window_start.desc(), MlPrediction.anomaly_score.desc()).limit(500)
            )
        )
        .scalars()
        .all()
    )
    history = (
        await db.execute(
            select(MlModel.version, MlModel.trained_at, MlModel.status, MlModel.metrics)
            .where(MlModel.tenant_id == principal.tenant_id)
            .order_by(MlModel.version.desc())
            .limit(10)
        )
    ).all()
    return {
        "model": None
        if model is None
        else {
            "id": str(model.id),
            "name": model.name,
            "version": model.version,
            "trained_at": model.trained_at,
            "metrics": model.metrics,
            "params": model.params,
            "baseline": model.baseline,
            "features": [{"key": f, "label": FEATURE_LABELS.get(f, f)} for f in model.feature_names],
        },
        "history": [{"version": v, "trained_at": t, "status": s, "metrics": m} for v, t, s, m in history],
        "predictions": [
            {
                "host": p.entity_id,
                "window_start": p.window_start,
                "anomaly_score": p.anomaly_score,
                "is_anomaly": p.is_anomaly,
                "top_contributors": p.top_contributors,
                "features": p.features,
            }
            for p in preds
        ],
    }


@router.post("/analytics/ml/train", status_code=202)
async def train(
    request: Request, principal: Principal = Depends(require(Perm.RULE_MANAGE)), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    await enqueue(db, "ml_train", {}, tenant_id=principal.tenant_id, dedup_key=f"ml_train:{principal.tenant_id}")
    await enqueue(
        db,
        "ml_score",
        {"hours": 24},
        tenant_id=principal.tenant_id,
        delay_seconds=2,
        dedup_key=f"ml_score_manual:{principal.tenant_id}",
    )
    await audit(
        db,
        action="ml.train",
        resource_type="ml_model",
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )
    return {"queued": True}
