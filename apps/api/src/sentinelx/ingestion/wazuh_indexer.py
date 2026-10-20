"""Poll Wazuh alerts from the Wazuh indexer (OpenSearch API) with search_after checkpoints.

Index pattern ``wazuh-alerts-*``; documents are the same JSON as alerts.json.
Reference: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html
Backoff: failures are recorded on the ingestion source and retried on the next scheduler tick.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelx.config import get_settings
from sentinelx.ingestion.pipeline import ingest
from sentinelx.logging import get_logger
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import IngestionCheckpoint, IngestionSource, Tenant
from sentinelx.threat_intel.providers import validate_integration_url

log = get_logger(__name__)
PAGE = 1000
KEY = "wazuh-indexer:wazuh-alerts-*"


def build_query(after: list[Any] | None, min_level: int) -> dict[str, Any]:
    q: dict[str, Any] = {
        "size": PAGE,
        "sort": [{"timestamp": "asc"}, {"id": "asc"}],
        "query": {"bool": {"filter": [{"range": {"rule.level": {"gte": min_level}}}]}},
    }
    if after:
        q["search_after"] = after
    else:
        q["query"]["bool"]["filter"].append({"range": {"timestamp": {"gte": "now-1h"}}})
    return q


async def poll_wazuh_indexer(transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    s = get_settings()
    if not s.wazuh_indexer_url:
        return {"status": "not_configured"}
    url = validate_integration_url(s.wazuh_indexer_url, allow_http=not s.is_production)
    async with system_session() as db:
        tid = (await db.execute(select(Tenant.id).where(Tenant.slug == s.file_ingest_tenant))).scalar_one_or_none()
    if tid is None:
        return {"status": "no_tenant"}
    async with tenant_session(tid) as db:
        cp = (
            await db.execute(select(IngestionCheckpoint).where(IngestionCheckpoint.source_key == KEY))
        ).scalar_one_or_none()
        after = (cp.position or {}).get("search_after") if cp else None
    auth = None
    if s.wazuh_indexer_username and s.wazuh_indexer_password:
        auth = (s.wazuh_indexer_username, s.wazuh_indexer_password.get_secret_value())
    # Low-level alerts are still ingested as telemetry (level >= 3) so Sigma rules see authentication etc.
    body = build_query(after, min_level=3)
    try:
        async with httpx.AsyncClient(
            timeout=20, verify=s.opensearch_verify_tls, auth=auth, follow_redirects=False, transport=transport
        ) as c:
            r = await c.post(f"{url}/wazuh-alerts-*/_search", json=body)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
    except (httpx.HTTPError, ValueError) as e:
        async with tenant_session(tid) as db:
            stmt = pg_insert(IngestionSource).values(
                id=uuid.uuid4(),
                tenant_id=tid,
                source_type="wazuh",
                last_error=f"indexer poll failed: {type(e).__name__}",
            )
            await db.execute(
                stmt.on_conflict_do_update(
                    index_elements=["tenant_id", "source_type"], set_={"last_error": stmt.excluded.last_error}
                )
            )
        log.warning("wazuh_poll_failed", error=type(e).__name__)
        return {"status": "error"}
    if not hits:
        return {"status": "ok", "ingested": 0}
    records = [h["_source"] for h in hits if "_source" in h]
    async with tenant_session(tid) as db:
        res = await ingest(db, tid, "wazuh", records)
        new_after = hits[-1].get("sort")
        stmt = pg_insert(IngestionCheckpoint).values(
            id=uuid.uuid4(), tenant_id=tid, source_key=KEY, position={"search_after": new_after}
        )
        await db.execute(
            stmt.on_conflict_do_update(index_elements=["source_key"], set_={"position": {"search_after": new_after}})
        )
    return {"status": "ok", "ingested": res.accepted, "more": len(hits) == PAGE}
