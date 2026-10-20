"""Alert creation with de-duplication (noise reduction): repeated hits of the same rule on the same
entities inside the dedup window update one alert instead of creating many."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.metrics import ALERTS_CREATED
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import Alert, AlertEvent

ENTITY_FIELDS = ("hostname", "username", "src_ip", "dest_ip", "domain", "process_name", "file_hash")


def level_for(severity: int) -> str:
    if severity >= 85:
        return "critical"
    if severity >= 65:
        return "high"
    if severity >= 40:
        return "medium"
    if severity >= 20:
        return "low"
    return "informational"


@dataclass
class AlertSpec:
    rule_uid: str
    title: str
    source: str
    severity: int
    dedup_key: str
    window_s: int
    first_ts: datetime
    last_ts: datetime
    event_ids: list[uuid.UUID] = field(default_factory=list)
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    entities: dict[str, Any] = field(default_factory=dict)
    source_types: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def merge(self, other: AlertSpec) -> None:
        have = set(self.event_ids)
        self.event_ids.extend(e for e in other.event_ids if e not in have)
        self.first_ts = min(self.first_ts, other.first_ts)
        self.last_ts = max(self.last_ts, other.last_ts)
        self.source_types = sorted(set(self.source_types) | set(other.source_types))
        for k, v in other.entities.items():
            self.entities.setdefault(k, v)
        for k, v in other.details.get("observed", {}).items():
            obs = self.details.setdefault("observed", {}).setdefault(k, [])
            for x in v:
                if x not in obs and len(obs) < 25:
                    obs.append(x)


def entities_from_event(ev: dict[str, Any]) -> dict[str, Any]:
    return {k: ev.get(k) for k in ENTITY_FIELDS if ev.get(k) not in (None, "")}


def observed_from_event(ev: dict[str, Any]) -> dict[str, list[Any]]:
    """Small set of distinct observed values kept on the alert for display (bounded)."""
    out: dict[str, list[Any]] = {}
    for k in ("src_ip", "dest_ip", "dest_port", "domain", "process_command_line", "file_path", "username"):
        v = ev.get(k)
        if v not in (None, ""):
            out[k] = [v if not isinstance(v, str) else v[:300]]
    return out


def collapse(specs: list[AlertSpec]) -> list[AlertSpec]:
    by_key: dict[str, AlertSpec] = {}
    for s in specs:
        if s.dedup_key in by_key:
            by_key[s.dedup_key].merge(s)
        else:
            by_key[s.dedup_key] = s
    return list(by_key.values())


async def upsert_alert(session: AsyncSession, tenant_id: uuid.UUID, spec: AlertSpec) -> tuple[uuid.UUID, bool]:
    catalog = get_catalog()
    techniques = sorted({t for t in spec.techniques if catalog.exists(t)})
    existing = (
        await session.execute(
            select(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.dedup_key == spec.dedup_key,
                Alert.status != "closed",
                Alert.last_event_at >= spec.first_ts - timedelta(seconds=spec.window_s),
            )
            .order_by(Alert.last_event_at.desc())
            .limit(1)
            .with_for_update()
        )
    ).scalar_one_or_none()

    if existing is not None:
        new = await _link_events(session, tenant_id, existing.id, spec.event_ids)
        existing.event_count += new
        existing.first_event_at = min(existing.first_event_at, spec.first_ts)
        existing.last_event_at = max(existing.last_event_at, spec.last_ts)
        existing.source_types = sorted(set(existing.source_types or []) | set(spec.source_types))
        existing.mitre_techniques = sorted(set(existing.mitre_techniques or []) | set(techniques))
        if spec.severity > existing.severity:
            existing.severity = spec.severity
            existing.level = level_for(spec.severity)
        details = dict(existing.details or {})
        for k, v in spec.details.get("observed", {}).items():
            obs = details.setdefault("observed", {}).setdefault(k, [])
            for x in v:
                if x not in obs and len(obs) < 25:
                    obs.append(x)
        existing.details = details
        return existing.id, False

    alert = Alert(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        rule_uid=spec.rule_uid,
        title=spec.title,
        description=spec.description,
        source=spec.source,
        severity=spec.severity,
        level=level_for(spec.severity),
        status="open",
        mitre_techniques=techniques,
        event_count=0,
        source_types=sorted(set(spec.source_types)),
        details=spec.details,
        dedup_key=spec.dedup_key,
        first_event_at=spec.first_ts,
        last_event_at=spec.last_ts,
        **{k: spec.entities.get(k) for k in ENTITY_FIELDS},
    )
    session.add(alert)
    await session.flush()
    alert.event_count = await _link_events(session, tenant_id, alert.id, spec.event_ids)
    ALERTS_CREATED.labels(source=spec.source).inc()
    return alert.id, True


async def _link_events(
    session: AsyncSession, tenant_id: uuid.UUID, alert_id: uuid.UUID, event_ids: list[uuid.UUID]
) -> int:
    if not event_ids:
        return 0
    rows = [{"alert_id": alert_id, "event_id": e, "tenant_id": tenant_id} for e in dict.fromkeys(event_ids)]
    total = 0
    for i in range(0, len(rows), 2000):
        res = await session.execute(
            pg_insert(AlertEvent).values(rows[i : i + 2000]).on_conflict_do_nothing().returning(AlertEvent.event_id)
        )
        total += len(res.all())
    return total
