"""Ingestion pipeline: parse -> validate -> enrich -> idempotent bulk insert -> queue detection.

Guarantees: schema validation, malformed-event quarantine, idempotency via deterministic ids,
source health counters, ingestion-lag and throughput metrics.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.domain.events import CanonicalEvent, deterministic_event_id, summarize
from sentinelx.ingestion.parsers import suricata, wazuh, zeek
from sentinelx.jobs.queue import enqueue
from sentinelx.metrics import EVENTS_DUPLICATE, EVENTS_FAILED, EVENTS_INGESTED, INGEST_BATCH_DURATION, INGESTION_LATENCY
from sentinelx.persistence.models import Asset, Identity, IngestionSource, QuarantinedEvent, SecurityEvent

SOURCES = ("wazuh", "suricata", "zeek", "sentinelx")
INSERT_CHUNK = 500  # keeps bind parameters well below PostgreSQL's 32767 limit
DETECT_CHUNK = 1000


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    quarantined: int = 0
    event_ids: list[uuid.UUID] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "quarantined": self.quarantined,
            "errors": self.errors[:20],
        }


def parse_canonical(rec: dict[str, Any], tenant_id: uuid.UUID) -> CanonicalEvent:
    """Accept events already in SentinelX canonical form (other shippers, demo generator)."""
    data = {k: v for k, v in rec.items() if k not in ("tenant_id", "event_id", "ingested_at")}
    native = rec.get("event_id") or json.dumps(rec, sort_keys=True, default=str)
    data.setdefault("source_type", "sentinelx")
    data.setdefault("raw_event", dict(rec))
    ev = CanonicalEvent(
        event_id=deterministic_event_id(tenant_id, "sentinelx", str(native)), tenant_id=tenant_id, **data
    )
    if not ev.summary:
        ev.summary = summarize(ev)
    return ev


def parse_record(source: str, rec: dict[str, Any], tenant_id: uuid.UUID, log_type: str | None = None) -> CanonicalEvent:
    if not isinstance(rec, dict):
        raise ValueError("record must be a JSON object")
    if source == "suricata":
        return suricata.parse(rec, tenant_id)
    if source == "zeek":
        return zeek.parse(rec, tenant_id, log_type)
    if source == "wazuh":
        return wazuh.parse(rec, tenant_id)
    if source == "sentinelx":
        return parse_canonical(rec, tenant_id)
    raise ValueError(f"unknown source {source!r}")


async def _ip_host_map(session: AsyncSession, tenant_id: uuid.UUID) -> dict[str, tuple[str, str | None]]:
    rows = (
        await session.execute(
            select(Asset.hostname, Asset.os, func.unnest(Asset.ip_addresses)).where(Asset.tenant_id == tenant_id)
        )
    ).all()
    return {ip: (host, os) for host, os, ip in rows}


async def ingest(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    source: str,
    records: Iterable[dict[str, Any]],
    log_type: str | None = None,
    run_detection_inline: bool = False,
) -> IngestResult:
    started = time.perf_counter()
    res = IngestResult()
    now = datetime.now(UTC)
    events: dict[uuid.UUID, CanonicalEvent] = {}
    quarantine: list[dict[str, Any]] = []
    for rec in records:
        try:
            ev = parse_record(source, rec, tenant_id, log_type)
            events.setdefault(ev.event_id, ev)
        except (ValueError, TypeError, KeyError, ValidationError) as e:
            msg = str(e).splitlines()[0][:500] if str(e) else type(e).__name__
            res.errors.append(msg)
            quarantine.append(
                {
                    "id": uuid.uuid4(),
                    "tenant_id": tenant_id,
                    "source_type": source[:16],
                    "error": msg,
                    "payload": json.dumps(rec, default=str)[:20000],
                }
            )
    res.quarantined = len(quarantine)
    if quarantine:
        await session.execute(pg_insert(QuarantinedEvent).values(quarantine))
        EVENTS_FAILED.labels(source=source).inc(len(quarantine))

    if events:
        ipmap = await _ip_host_map(session, tenant_id)
        for ev in events.values():
            # attribute network telemetry to known hosts so correlation can join on host
            if not ev.hostname:
                for ip in (ev.src_ip, ev.host_ip):
                    if ip and ip in ipmap:
                        ev.hostname, os_ = ipmap[ip]
                        ev.os = ev.os or os_
                        ev.metadata["hostname_source"] = "asset_ip_map"
                        break
            if not ev.summary:
                ev.summary = summarize(ev)
            INGESTION_LATENCY.labels(source=source).observe(max(0.0, (now - ev.timestamp).total_seconds()))

        rows = [ev.to_row() for ev in events.values()]
        for i in range(0, len(rows), INSERT_CHUNK):
            stmt = (
                pg_insert(SecurityEvent)
                .values(rows[i : i + INSERT_CHUNK])
                .on_conflict_do_nothing(index_elements=["id"])
                .returning(SecurityEvent.id)
            )
            res.event_ids.extend((await session.execute(stmt)).scalars().all())
        res.accepted = len(res.event_ids)
        res.duplicates = len(events) - res.accepted
        EVENTS_INGESTED.labels(source=source).inc(res.accepted)
        EVENTS_DUPLICATE.labels(source=source).inc(res.duplicates)

        new = [events[i] for i in res.event_ids]
        await _upsert_assets(session, tenant_id, new)
        await _upsert_identities(session, tenant_id, new)
        if new:
            from sentinelx.ingestion.opensearch_sink import index_events

            await index_events(new)

    await _update_source(session, tenant_id, source, res, events, now)

    if res.event_ids:
        if run_detection_inline:
            from sentinelx.processing import process_events

            await process_events(session, tenant_id, res.event_ids)
        else:
            for i in range(0, len(res.event_ids), DETECT_CHUNK):
                await enqueue(
                    session,
                    "process_events",
                    {"event_ids": [str(x) for x in res.event_ids[i : i + DETECT_CHUNK]]},
                    tenant_id=tenant_id,
                )
    INGEST_BATCH_DURATION.observe(time.perf_counter() - started)
    return res


async def _upsert_assets(session: AsyncSession, tenant_id: uuid.UUID, events: list[CanonicalEvent]) -> None:
    hosts: dict[str, dict[str, Any]] = {}
    for ev in events:
        if not ev.hostname or ev.metadata.get("hostname_source") == "asset_ip_map":
            continue
        h = hosts.setdefault(ev.hostname, {"ips": set(), "os": None, "agent": None, "last": ev.timestamp})
        if ev.host_ip:
            h["ips"].add(ev.host_ip)
        h["os"] = h["os"] or ev.os
        h["agent"] = h["agent"] or ev.metadata.get("agent_id")
        h["last"] = max(h["last"], ev.timestamp)
    if not hosts:
        return
    rows = [
        {
            "id": uuid.uuid4(),
            "tenant_id": tenant_id,
            "hostname": name,
            "os": h["os"],
            "ip_addresses": sorted(h["ips"]),
            "wazuh_agent_id": h["agent"],
            "last_seen": h["last"],
        }
        for name, h in hosts.items()
    ]
    stmt = pg_insert(Asset).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "hostname"],
        set_={
            "last_seen": func.greatest(Asset.last_seen, stmt.excluded.last_seen),
            "os": func.coalesce(Asset.os, stmt.excluded.os),
            "wazuh_agent_id": func.coalesce(Asset.wazuh_agent_id, stmt.excluded.wazuh_agent_id),
            "ip_addresses": literal_column(
                "ARRAY(SELECT DISTINCT x FROM unnest(array_cat(assets.ip_addresses, excluded.ip_addresses)) AS x"
                " ORDER BY x)"
            ),
        },
    )
    await session.execute(stmt)


async def _upsert_identities(session: AsyncSession, tenant_id: uuid.UUID, events: list[CanonicalEvent]) -> None:
    users: dict[str, datetime] = {}
    for ev in events:
        if ev.username and ev.event_type in ("authentication", "ssh", "process", "iam"):
            users[ev.username] = max(users.get(ev.username, ev.timestamp), ev.timestamp)
    if not users:
        return
    rows = [
        {
            "id": uuid.uuid4(),
            "tenant_id": tenant_id,
            "username": u[:255],
            "last_seen": ts,
            "privileged": u in ("administrator", "admin", "root"),
        }
        for u, ts in users.items()
    ]
    stmt = pg_insert(Identity).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "username"],
        set_={"last_seen": func.greatest(Identity.last_seen, stmt.excluded.last_seen)},
    )
    await session.execute(stmt)


async def _update_source(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    source: str,
    res: IngestResult,
    events: dict[uuid.UUID, CanonicalEvent],
    now: datetime,
) -> None:
    last_ev = max((e.timestamp for e in events.values()), default=None)
    stmt = pg_insert(IngestionSource).values(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        source_type=source,
        events_total=res.accepted,
        failures_total=res.quarantined,
        duplicates_total=res.duplicates,
        last_event_at=last_ev,
        last_ingest_at=now,
        last_error=res.errors[0] if res.errors else None,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "source_type"],
        set_={
            "events_total": IngestionSource.events_total + res.accepted,
            "failures_total": IngestionSource.failures_total + res.quarantined,
            "duplicates_total": IngestionSource.duplicates_total + res.duplicates,
            "last_event_at": func.greatest(IngestionSource.last_event_at, stmt.excluded.last_event_at),
            "last_ingest_at": now,
            "last_error": func.coalesce(stmt.excluded.last_error, IngestionSource.last_error),
        },
    )
    await session.execute(stmt)
