"""Alert -> incident correlation - the primary SentinelX-owned component.

Algorithm (documented in docs/architecture/correlation.md):

1. Each alert yields weighted entities: host/user/hash (1.0), external IP / domain (0.6), internal IP (0.4);
   the source IP of an alert without a known host identifies the actor and weighs 1.0.
2. Candidate incidents are open incidents sharing at least one entity whose activity overlaps the alert
   within the correlation window (configurable, default 60 min).
3. *Hub suppression*: an entity already shared by many open incidents (default >= 8) - e.g. a DNS
   server, a proxy, a shared admin account - gets weight 0, so it cannot glue unrelated activity together.
   Tenants can also list entities to ignore (``settings.correlation_ignore``).
4. If the summed weight of shared entities reaches the link threshold (default 1.0) the alert joins the
   best candidate; if it links several incidents they are merged (union) into the oldest one.
5. Otherwise a new (not yet promoted) incident group is created.
6. A per-tenant advisory lock serializes correlation so concurrent workers never race.
"""

from __future__ import annotations

import time
import uuid
import zlib
from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.correlation.incidents import recompute_incident
from sentinelx.domain.events import is_private_ip
from sentinelx.metrics import CORRELATION_DURATION
from sentinelx.persistence.models import (
    Alert,
    Incident,
    IncidentActivity,
    IncidentEntity,
    IncidentEvidence,
    Tenant,
)

IGNORED_USERS = {"system", "local service", "network service", "anonymous logon", "-", "n/a", "unknown"}
IGNORED_HOSTS = {"localhost", "-", "unknown"}
KIND_WEIGHT = {"host": 1.0, "user": 1.0, "hash": 1.0, "domain": 0.6}


def tenant_lock_key(tenant_id: uuid.UUID) -> int:
    return zlib.crc32(b"sentinelx-correlation:" + tenant_id.bytes) & 0x7FFFFFFF


def alert_entities(a: Alert) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if a.hostname and a.hostname.lower() not in IGNORED_HOSTS:
        out.append(("host", a.hostname))
    if a.username and a.username.lower() not in IGNORED_USERS:
        out.append(("user", a.username.lower()))
    for ip in (a.src_ip, a.dest_ip):
        if ip:
            out.append(("ip", ip))
    if a.domain:
        out.append(("domain", a.domain.lower()))
    if a.file_hash:
        out.append(("hash", a.file_hash.lower()))
    return list(dict.fromkeys(out))


def entity_weight(kind: str, value: str, a: Alert | None = None) -> float:
    """Weight of a shared entity, from the perspective of the alert being correlated.

    When an alert has no resolved host, its source IP is the best identity of the actor (an unmanaged
    scanner, an external attacker) and is weighted like a host.
    """
    if kind == "ip":
        if a is not None and not a.hostname and value == a.src_ip:
            return 1.0
        return 0.4 if is_private_ip(value) else 0.6
    return KIND_WEIGHT.get(kind, 0.5)


async def correlate(session: AsyncSession, tenant_id: uuid.UUID, alert_ids: list[uuid.UUID]) -> set[uuid.UUID]:
    """Attach alerts to incidents. Returns ids of incidents that changed (already recomputed)."""
    if not alert_ids:
        return set()
    started = time.perf_counter()
    s = get_settings()
    await session.execute(select(func.pg_advisory_xact_lock(tenant_lock_key(tenant_id))))
    tenant = await session.get(Tenant, tenant_id)
    tsettings = (tenant.settings or {}) if tenant else {}
    ignore = set(tsettings.get("correlation_ignore", []))
    window = timedelta(minutes=int(tsettings.get("correlation_window_minutes", s.correlation_window_minutes)))

    alerts = (
        (
            await session.execute(
                select(Alert)
                .where(Alert.tenant_id == tenant_id, Alert.id.in_(alert_ids))
                .order_by(Alert.first_event_at)
            )
        )
        .scalars()
        .all()
    )
    touched: set[uuid.UUID] = set()
    for a in alerts:
        ents = [(k, v) for k, v in alert_entities(a) if f"{k}:{v}" not in ignore]
        if a.incident_id is not None:
            await upsert_entities(session, tenant_id, a.incident_id, a, ents)
            touched.add(a.incident_id)
            continue
        target = await _find_target(
            session, tenant_id, a, ents, window, s.correlation_link_threshold, s.correlation_hub_entity_limit
        )
        if target is None:
            target = await _create_incident(session, tenant_id, a)
        a.incident_id = target
        await upsert_entities(session, tenant_id, target, a, ents)
        touched.add(target)

    await session.flush()
    for inc_id in list(touched):
        inc = await session.get(Incident, inc_id)
        if inc is not None and inc.status != "merged":
            await recompute_incident(session, tenant_id, inc_id)
    CORRELATION_DURATION.observe(time.perf_counter() - started)
    return touched


async def _find_target(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    a: Alert,
    ents: list[tuple[str, str]],
    window: timedelta,
    threshold: float,
    hub_limit: int,
) -> uuid.UUID | None:
    if not ents:
        return None
    rows = (
        await session.execute(
            select(IncidentEntity.incident_id, IncidentEntity.kind, IncidentEntity.value, Incident.created_at)
            .join(Incident, Incident.id == IncidentEntity.incident_id)
            .where(
                IncidentEntity.tenant_id == tenant_id,
                tuple_(IncidentEntity.kind, IncidentEntity.value).in_(ents),
                Incident.status.notin_(["resolved", "closed", "merged"]),
                Incident.last_event_at >= a.first_event_at - window,
                Incident.first_event_at <= a.last_event_at + window,
            )
        )
    ).all()
    if not rows:
        return None
    incidents_per_entity: dict[tuple[str, str], set[uuid.UUID]] = defaultdict(set)
    for inc_id, kind, value, _ in rows:
        incidents_per_entity[(kind, value)].add(inc_id)
    # hub suppression uses the global open-incident fan-out of each entity
    hub_counts = dict(
        (
            await session.execute(
                select(
                    IncidentEntity.kind + ":" + IncidentEntity.value,
                    func.count(func.distinct(IncidentEntity.incident_id)),
                )
                .join(Incident, Incident.id == IncidentEntity.incident_id)
                .where(
                    IncidentEntity.tenant_id == tenant_id,
                    tuple_(IncidentEntity.kind, IncidentEntity.value).in_(ents),
                    Incident.status.notin_(["resolved", "closed", "merged"]),
                )
                .group_by(IncidentEntity.kind, IncidentEntity.value)
            )
        ).all()
    )
    scores: dict[uuid.UUID, float] = defaultdict(float)
    created: dict[uuid.UUID, Any] = {}
    for inc_id, kind, value, created_at in rows:
        if hub_counts.get(f"{kind}:{value}", 0) >= hub_limit:
            continue
        scores[inc_id] += entity_weight(kind, value, a)
        created[inc_id] = created_at
    linked = [i for i, sc in scores.items() if sc >= threshold - 1e-9]
    if not linked:
        return None
    linked.sort(key=lambda i: created[i])
    target = linked[0]
    for other in linked[1:]:
        await merge_incidents(session, tenant_id, target, other)
    return target


async def next_incident_number(session: AsyncSession, tenant_id: uuid.UUID) -> int:
    n = (
        await session.execute(
            select(func.coalesce(func.max(Incident.number), 0)).where(Incident.tenant_id == tenant_id)
        )
    ).scalar_one()
    return int(n) + 1


async def _create_incident(session: AsyncSession, tenant_id: uuid.UUID, a: Alert) -> uuid.UUID:
    inc = Incident(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        number=await next_incident_number(session, tenant_id),
        title=a.title,
        description="",
        severity="low",
        risk_score=0,
        risk_breakdown=[],
        confidence=0.0,
        confidence_factors=[],
        status="new",
        promoted=False,
        first_event_at=a.first_event_at,
        last_event_at=a.last_event_at,
        mitre_techniques=[],
        tactics=[],
        alert_count=0,
        event_count=0,
        source_types=[],
    )
    session.add(inc)
    await session.flush()
    session.add(
        IncidentActivity(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            incident_id=inc.id,
            kind="created",
            message=f"Correlation group opened from alert: {a.title}",
            data={"alert_id": str(a.id)},
        )
    )
    return inc.id


async def upsert_entities(
    session: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, a: Alert, ents: list[tuple[str, str]]
) -> None:
    if not ents:
        return
    rows = [
        {
            "incident_id": incident_id,
            "kind": k,
            "value": v[:512],
            "tenant_id": tenant_id,
            "first_seen": a.first_event_at,
            "last_seen": a.last_event_at,
            "alert_count": 1,
        }
        for k, v in ents
    ]
    stmt = pg_insert(IncidentEntity).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["incident_id", "kind", "value"],
        set_={
            "last_seen": func.greatest(IncidentEntity.last_seen, stmt.excluded.last_seen),
            "first_seen": func.least(IncidentEntity.first_seen, stmt.excluded.first_seen),
            "alert_count": IncidentEntity.alert_count + 1,
        },
    )
    await session.execute(stmt)


async def merge_incidents(
    session: AsyncSession, tenant_id: uuid.UUID, target: uuid.UUID, source: uuid.UUID, actor: str = "system"
) -> None:
    """Union ``source`` into ``target``: move alerts, entities, evidence; mark source as merged."""
    if target == source:
        return
    await session.execute(
        update(Alert).where(Alert.tenant_id == tenant_id, Alert.incident_id == source).values(incident_id=target)
    )
    await session.execute(
        text(
            """
        INSERT INTO incident_entities (incident_id, kind, value, tenant_id, first_seen, last_seen, alert_count)
        SELECT :target, kind, value, tenant_id, first_seen, last_seen, alert_count
        FROM incident_entities WHERE incident_id = :source
        ON CONFLICT (incident_id, kind, value) DO UPDATE SET
          first_seen = LEAST(incident_entities.first_seen, EXCLUDED.first_seen),
          last_seen = GREATEST(incident_entities.last_seen, EXCLUDED.last_seen),
          alert_count = incident_entities.alert_count + EXCLUDED.alert_count
        """
        ),
        {"target": target, "source": source},
    )
    await session.execute(
        text(
            """
        INSERT INTO incident_evidence (incident_id, event_id, tenant_id, alert_id, timestamp, snapshot)
        SELECT :target, event_id, tenant_id, alert_id, timestamp, snapshot FROM incident_evidence
        WHERE incident_id = :source ON CONFLICT DO NOTHING
        """
        ),
        {"target": target, "source": source},
    )
    await session.execute(IncidentEntity.__table__.delete().where(IncidentEntity.incident_id == source))
    await session.execute(IncidentEvidence.__table__.delete().where(IncidentEvidence.incident_id == source))
    src = await session.get(Incident, source)
    tgt = await session.get(Incident, target)
    if src is not None and tgt is not None:
        src.status = "merged"
        src.merged_into = target
        if src.promoted and not tgt.promoted:
            tgt.promoted = True
            tgt.promoted_at = src.promoted_at
            tgt.promotion_reason = src.promotion_reason
        session.add(
            IncidentActivity(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=target,
                kind="merged",
                actor=actor,
                message=f"Merged related incident INC-{src.number} into this one",
                data={"merged_incident_id": str(source)},
            )
        )
        session.add(
            IncidentActivity(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=source,
                kind="merged",
                actor=actor,
                message=f"Merged into INC-{tgt.number}",
                data={"target_incident_id": str(target)},
            )
        )
