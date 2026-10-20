"""Load the synthetic demo lab into a dedicated, clearly-labelled tenant."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelx.demo.scenarios import build_demo
from sentinelx.ingestion.pipeline import ingest
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import Asset, Identity, Tenant
from sentinelx.threat_intel.service import import_indicators

DEMO_SLUG = "demo-lab"
DEMO_NAME = "Demo Lab (synthetic data)"
CHUNK = 1000


async def ensure_demo_tenant(reset: bool = False) -> uuid.UUID:
    async with system_session() as s:
        t = (await s.execute(select(Tenant).where(Tenant.slug == DEMO_SLUG))).scalar_one_or_none()
        if t is not None and reset:
            await s.execute(delete(Tenant).where(Tenant.id == t.id))
            await s.flush()
            t = None
        if t is None:
            t = Tenant(
                id=uuid.uuid4(),
                slug=DEMO_SLUG,
                name=DEMO_NAME,
                settings={"demo": True, "correlation_ignore": ["ip:10.10.0.2"]},
            )
            s.add(t)
        return t.id


async def load_demo(reset: bool = True, now: datetime | None = None, with_ml: bool = True) -> dict[str, Any]:
    tenant_id = await ensure_demo_tenant(reset=reset)
    data = build_demo(now=now)
    async with tenant_session(tenant_id) as s:
        for a in data.assets:
            stmt = pg_insert(Asset).values(id=uuid.uuid4(), tenant_id=tenant_id, **a)
            await s.execute(
                stmt.on_conflict_do_update(
                    index_elements=["tenant_id", "hostname"],
                    set_={
                        k: stmt.excluded[k]
                        for k in ("criticality", "owner", "environment", "os", "tags", "ip_addresses")
                    },
                )
            )
        for ident in data.identities:
            stmt = pg_insert(Identity).values(id=uuid.uuid4(), tenant_id=tenant_id, **ident)
            await s.execute(
                stmt.on_conflict_do_update(
                    index_elements=["tenant_id", "username"],
                    set_={k: stmt.excluded[k] for k in ("email", "department", "privileged")},
                )
            )
        await import_indicators(s, tenant_id, data.indicators)

    totals = {"accepted": 0, "duplicates": 0, "quarantined": 0}
    # Baseline first, ML trained on it, then the rest - mirrors how a real deployment builds history.
    for batch in data.batches:
        for i in range(0, len(batch.records), CHUNK):
            async with tenant_session(tenant_id) as s:
                res = await ingest(
                    s, tenant_id, batch.source, batch.records[i : i + CHUNK], batch.log_type, run_detection_inline=True
                )
            for k in totals:
                totals[k] += getattr(res, k)

    ml: dict[str, Any] = {}
    if with_ml:
        from sentinelx.ml.service import score_recent, train_model

        async with tenant_session(tenant_id) as s:
            ml["train"] = await train_model(s, tenant_id)
        async with tenant_session(tenant_id) as s:
            ml["score"] = await score_recent(s, tenant_id, hours=3)

    async with system_session() as s:
        t = await s.get(Tenant, tenant_id)
        if t is not None:
            t.settings = {**(t.settings or {}), "demo": True, "demo_loaded_at": datetime.now(UTC).isoformat()}
    return {"tenant_id": str(tenant_id), **totals, "ml": ml}
