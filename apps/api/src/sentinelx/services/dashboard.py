"""Dashboard figures. Every number is computed from stored data - nothing is hard-coded."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.detection.builtin import IOC_RULE
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import Alert, Asset, Identity, Incident, IngestionSource, SecurityEvent

OPEN_STATUSES = ["new", "triaged", "investigating", "contained"]
SEVERITIES = ("critical", "high", "medium", "low", "informational")


async def noise_funnel(db: AsyncSession, tenant_id: uuid.UUID, since: datetime) -> dict[str, Any]:
    """Raw events -> security-relevant events -> alerts -> correlated groups -> incidents."""

    async def count(stmt: Any) -> int:
        return int((await db.execute(stmt)).scalar_one())

    raw = await count(
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.timestamp >= since)
    )
    relevant = await count(
        text(
            """
            SELECT count(*) FROM (
              SELECT event_id FROM rule_matches WHERE tenant_id = :t AND ts >= :since AND event_id IS NOT NULL
              UNION
              SELECT ae.event_id FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id
              WHERE a.tenant_id = :t AND a.last_event_at >= :since
            ) matched
            """
        ).bindparams(t=tenant_id, since=since)
    )
    alerts = await count(
        select(func.count()).select_from(Alert).where(Alert.tenant_id == tenant_id, Alert.last_event_at >= since)
    )
    in_window = (Incident.tenant_id == tenant_id, Incident.status != "merged", Incident.last_event_at >= since)
    groups = await count(select(func.count()).select_from(Incident).where(*in_window))
    by_severity = dict(
        (
            await db.execute(
                select(Incident.severity, func.count())
                .where(*in_window, Incident.promoted.is_(True))
                .group_by(Incident.severity)
            )
        ).all()
    )
    incidents = sum(by_severity.values())
    return {
        "raw_events": raw,
        "security_events": relevant,
        "alerts": alerts,
        "correlated_groups": groups,
        "incidents": incidents,
        "critical": by_severity.get("critical", 0),
        "high": by_severity.get("high", 0),
        "reduction_pct": round(100 * (1 - incidents / alerts), 1) if alerts else None,
    }


async def open_incidents(db: AsyncSession, tenant_id: uuid.UUID) -> tuple[dict[str, int], list[Incident]]:
    """Open incident counts per severity, and the highest-risk ones for "Needs your attention"."""
    is_open = (Incident.tenant_id == tenant_id, Incident.promoted.is_(True), Incident.status.in_(OPEN_STATUSES))
    counts = dict(
        (await db.execute(select(Incident.severity, func.count()).where(*is_open).group_by(Incident.severity))).all()
    )
    top = (
        await db.execute(
            select(Incident)
            .where(*is_open)
            .order_by(Incident.risk_score.desc(), Incident.last_event_at.desc())
            .limit(6)
        )
    ).scalars()
    return {s: counts.get(s, 0) for s in SEVERITIES}, list(top)


async def trends(db: AsyncSession, tenant_id: uuid.UUID, now: datetime) -> dict[str, list[dict[str, Any]]]:
    """New incidents per day (14 days, zero-filled) and events per hour (24 hours)."""
    first_day = (now - timedelta(days=13)).replace(hour=0, minute=0, second=0, microsecond=0)
    per_day = await db.execute(
        text(
            """
            SELECT d::date, coalesce(x.n, 0) FROM generate_series(:start, :end, interval '1 day') d
            LEFT JOIN (SELECT date_trunc('day', promoted_at) AS day, count(*) AS n FROM incidents
                       WHERE tenant_id = :t AND promoted AND promoted_at >= :start GROUP BY 1) x ON x.day = d
            ORDER BY d
            """
        ),
        {"t": tenant_id, "start": first_day, "end": now},
    )
    per_hour = await db.execute(
        text(
            "SELECT date_trunc('hour', timestamp), count(*) FROM security_events "
            "WHERE tenant_id = :t AND timestamp >= :since GROUP BY 1 ORDER BY 1"
        ),
        {"t": tenant_id, "since": now - timedelta(hours=24)},
    )
    return {
        "incidents_per_day": [{"day": day, "count": n} for day, n in per_day.all()],
        "events_per_hour": [{"t": hour, "count": n} for hour, n in per_hour.all()],
    }


async def riskiest_entities(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, list[dict[str, Any]]]:
    assets = await db.execute(
        select(Asset.id, Asset.hostname, Asset.risk_score, Asset.criticality)
        .where(Asset.tenant_id == tenant_id, Asset.risk_score > 0)
        .order_by(Asset.risk_score.desc())
        .limit(5)
    )
    users = await db.execute(
        select(Identity.id, Identity.username, Identity.risk_score, Identity.privileged)
        .where(Identity.tenant_id == tenant_id, Identity.risk_score > 0)
        .order_by(Identity.risk_score.desc())
        .limit(5)
    )
    return {
        "top_assets": [{"id": str(i), "hostname": h, "risk_score": r, "criticality": c} for i, h, r, c in assets.all()],
        "top_users": [{"id": str(i), "username": u, "risk_score": r, "privileged": p} for i, u, r, p in users.all()],
    }


async def top_techniques(db: AsyncSession, tenant_id: uuid.UUID, since: datetime) -> list[dict[str, Any]]:
    rows = await db.execute(
        text(
            """
            SELECT technique, count(*) FROM (
              SELECT unnest(mitre_techniques) AS technique FROM incidents
              WHERE tenant_id = :t AND promoted AND status <> 'merged' AND last_event_at >= :since
            ) used
            GROUP BY technique ORDER BY 2 DESC LIMIT 6
            """
        ),
        {"t": tenant_id, "since": since},
    )
    catalog = get_catalog()
    out = []
    for technique_id, incidents in rows.all():
        technique = catalog.get(technique_id)
        out.append(
            {
                "id": technique_id,
                "incidents": incidents,
                "name": technique.name if technique else technique_id,
                "tactic": technique.tactics[0] if technique and technique.tactics else None,
            }
        )
    return out


async def threat_intel_matches(db: AsyncSession, tenant_id: uuid.UUID, since: datetime) -> int:
    stmt = (
        select(func.count())
        .select_from(Alert)
        .where(Alert.tenant_id == tenant_id, Alert.rule_uid == IOC_RULE, Alert.last_event_at >= since)
    )
    return int((await db.execute(stmt)).scalar_one())


async def ingestion_health(db: AsyncSession, tenant_id: uuid.UUID, now: datetime) -> list[dict[str, Any]]:
    """A source is healthy when it delivered data in the last 15 minutes."""
    sources = (await db.execute(select(IngestionSource).where(IngestionSource.tenant_id == tenant_id))).scalars()
    out = []
    for src in sources:
        if src.last_ingest_at is None:
            state = "never"
        else:
            state = "healthy" if (now - src.last_ingest_at).total_seconds() < 900 else "idle"
        out.append(
            {
                "source": src.source_type,
                "events_total": src.events_total,
                "failures": src.failures_total,
                "duplicates": src.duplicates_total,
                "last_ingest_at": src.last_ingest_at,
                "last_event_at": src.last_event_at,
                "status": state,
            }
        )
    return out


async def response_metrics(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, Any]:
    """Mean time to acknowledge / resolve and false-positive rate over the last 30 days."""
    since = datetime.now(UTC) - timedelta(days=30)
    mtta, mttr, false_positives, dispositioned = (
        await db.execute(
            select(
                func.avg(func.extract("epoch", Incident.acknowledged_at - Incident.promoted_at)),
                func.avg(func.extract("epoch", Incident.resolved_at - Incident.promoted_at)),
                func.count().filter(Incident.disposition == "false_positive"),
                func.count().filter(Incident.disposition.isnot(None)),
            ).where(Incident.tenant_id == tenant_id, Incident.promoted.is_(True), Incident.promoted_at >= since)
        )
    ).one()
    return {
        "mtta_seconds": float(mtta) if mtta else None,
        "mttr_seconds": float(mttr) if mttr else None,
        "false_positive_rate": round(false_positives / dispositioned, 3) if dispositioned else None,
        "dispositioned": dispositioned,
    }
