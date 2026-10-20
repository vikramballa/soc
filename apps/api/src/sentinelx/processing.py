"""Processing of stored events: detection -> correlation -> enrichment -> risk (all deterministic, no LLM)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.correlation.engine import correlate, tenant_lock_key
from sentinelx.correlation.incidents import recompute_incident
from sentinelx.detection.engine import run_detection
from sentinelx.domain.events import is_private_ip
from sentinelx.jobs.queue import enqueue
from sentinelx.persistence.models import IncidentEntity
from sentinelx.threat_intel.service import enrich


async def incident_indicators(
    session: AsyncSession, tenant_id: uuid.UUID, incident_ids: set[uuid.UUID]
) -> dict[uuid.UUID, list[tuple[str, str]]]:
    rows = (
        await session.execute(
            select(IncidentEntity.incident_id, IncidentEntity.kind, IncidentEntity.value).where(
                IncidentEntity.tenant_id == tenant_id,
                IncidentEntity.incident_id.in_(incident_ids),
                IncidentEntity.kind.in_(["ip", "domain", "hash"]),
            )
        )
    ).all()
    out: dict[uuid.UUID, list[tuple[str, str]]] = {}
    for inc, kind, value in rows:
        if kind == "ip" and is_private_ip(value):
            continue
        out.setdefault(inc, []).append((kind, value))
    return out


async def enrich_incidents(
    session: AsyncSession, tenant_id: uuid.UUID, incident_ids: set[uuid.UUID], local_only: bool
) -> set[uuid.UUID]:
    """Enrich incident indicators; returns incidents whose TI picture changed (need re-scoring)."""
    by_inc = await incident_indicators(session, tenant_id, incident_ids)
    changed: set[uuid.UUID] = set()
    for inc, inds in by_inc.items():
        results = await enrich(session, tenant_id, inds, local_only=local_only)
        if any(r.verdict in ("malicious", "suspicious") for r in results):
            changed.add(inc)
    return changed


async def process_events(session: AsyncSession, tenant_id: uuid.UUID, event_ids: list[uuid.UUID]) -> dict[str, Any]:
    await session.execute(select(func.pg_advisory_xact_lock(tenant_lock_key(tenant_id))))
    alert_ids = await run_detection(session, tenant_id, event_ids)
    incident_ids = await correlate(session, tenant_id, alert_ids)
    if incident_ids:
        for inc in await enrich_incidents(session, tenant_id, incident_ids, local_only=True):
            await recompute_incident(session, tenant_id, inc)
        if get_settings().misp_url:
            for inc in incident_ids:
                await enqueue(
                    session, "ti_enrich", {"incident_id": str(inc)}, tenant_id=tenant_id, dedup_key=f"ti_enrich:{inc}"
                )
    return {"events": len(event_ids), "alerts": len(alert_ids), "incidents": len(incident_ids)}
