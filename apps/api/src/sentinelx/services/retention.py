"""Configurable retention. Telemetry ages out; incident evidence snapshots and audit logs stay.

Alert->event links are kept: they are tiny and still resolve to the incident evidence snapshots.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text

from sentinelx.config import get_settings
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import Tenant

BATCH = 5000


async def run_retention() -> dict[str, Any]:
    s = get_settings()
    deleted_events = 0
    async with system_session() as db:
        tenants = (await db.execute(select(Tenant.id, Tenant.settings))).all()
    for tid, settings in tenants:
        days = int((settings or {}).get("event_retention_days", s.event_retention_days))
        cutoff = datetime.now(UTC) - timedelta(days=days)
        while True:  # small batches keep locks short on large tables
            async with system_session() as db:
                n = (
                    await db.execute(
                        text(
                            "DELETE FROM security_events WHERE id IN "
                            "(SELECT id FROM security_events WHERE tenant_id = :t AND timestamp < :c LIMIT :b)"
                        ),
                        {"t": tid, "c": cutoff, "b": BATCH},
                    )
                ).rowcount or 0
            deleted_events += n
            if n < BATCH:
                break
    async with system_session() as db:
        rm = (
            await db.execute(
                text("DELETE FROM rule_matches WHERE ts < now() - make_interval(hours => :h)"),
                {"h": s.rule_match_retention_hours},
            )
        ).rowcount
        q = (
            await db.execute(text("DELETE FROM quarantined_events WHERE received_at < now() - interval '14 days'"))
        ).rowcount
        sess = (await db.execute(text("DELETE FROM sessions WHERE expires_at < now() - interval '1 day'"))).rowcount
    return {"events": deleted_events, "rule_matches": rm, "quarantined": q, "sessions": sess}
