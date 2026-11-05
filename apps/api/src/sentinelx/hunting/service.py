"""Periodic hunts per organization. Each finding becomes an ordinary alert and goes through correlation,
so it joins (and raises the risk of) incidents on the same hosts.
"""

from __future__ import annotations

import statistics
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.correlation.engine import correlate, tenant_lock_key
from sentinelx.detection.alerts import AlertSpec, collapse, upsert_alert
from sentinelx.detection.builtin import (
    BEACON_RULE,
    BUILTIN_RULES,
    DNS_TUNNEL_RULE,
    SILENCE_RULE,
    STORM_RULE,
)
from sentinelx.domain.events import is_private_ip
from sentinelx.hunting.scoring import base_domain, beacon_score
from sentinelx.logging import get_logger
from sentinelx.persistence.models import Alert, SecurityEvent, TelemetrySource, Tenant

log = get_logger(__name__)
_RULES = {r["rule_uid"]: r for r in BUILTIN_RULES}
# infrastructure chatter that is periodic by design
_BEACON_IGNORED_PORTS = {53, 67, 68, 123, 137, 138, 161, 162, 514, 5353}


def _spec(rule_uid: str, **kw: Any) -> AlertSpec:
    r = _RULES[rule_uid]
    kw.setdefault("description", r["description"])
    kw.setdefault("techniques", list(r["techniques"]))
    return AlertSpec(rule_uid=rule_uid, source="builtin", **kw)


def _allowed(value: str | None, allowlist: list[str]) -> bool:
    if not value:
        return False
    v = value.lower()
    return any(v == a or v.endswith("." + a) for a in allowlist)


async def run_hunts(
    session: AsyncSession, tenant_id: uuid.UUID, now: datetime | None = None, beacons: bool = True
) -> dict[str, Any]:
    """``beacons=False`` skips the 24 h beacon aggregation (the scheduler runs it hourly, the rest every run)."""
    from sentinelx.detection.engine import enabled_rule_uids

    now = now or datetime.now(UTC)
    await session.execute(select(func.pg_advisory_xact_lock(tenant_lock_key(tenant_id))))
    enabled = await enabled_rule_uids(session, tenant_id)
    tenant = await session.get(Tenant, tenant_id)
    allowlist = [str(x).lower() for x in ((tenant.settings or {}) if tenant else {}).get("hunt_allowlist", [])]
    specs: list[AlertSpec] = []
    counts: dict[str, Any] = {}
    if beacons and BEACON_RULE in enabled:
        found = await find_beacons(session, tenant_id, now, allowlist)
        counts["beacons"] = len(found)
        specs += found
    if DNS_TUNNEL_RULE in enabled:
        found = await find_dns_tunnels(session, tenant_id, now, allowlist)
        counts["dns_tunnels"] = len(found)
        specs += found
    if SILENCE_RULE in enabled:
        found = await find_silent_sources(session, tenant_id, now)
        counts["silent_sources"] = len(found)
        specs += found
    if STORM_RULE in enabled:
        found = await find_alert_storm(session, tenant_id, now)
        counts["alert_storm"] = len(found)
        specs += found
    ids = [(await upsert_alert(session, tenant_id, s))[0] for s in collapse(specs)]
    if ids:
        await correlate(session, tenant_id, ids)
    return {**counts, "alerts": len(ids)}


async def find_beacons(
    session: AsyncSession, tenant_id: uuid.UUID, now: datetime, allowlist: list[str]
) -> list[AlertSpec]:
    s = get_settings()
    since = now - timedelta(hours=s.beacon_lookback_hours)
    rows = (
        await session.execute(
            text(
                """
                SELECT src_ip, coalesce(domain, dest_ip) AS dst, dest_ip, dest_port, source_type,
                       min(hostname) AS host,
                       array_agg(extract(epoch FROM timestamp)::float8 ORDER BY timestamp) AS ts,
                       array_agg(coalesce(bytes_out, 0) ORDER BY timestamp) AS sizes,
                       (array_agg(id ORDER BY timestamp DESC))[1:30] AS ids,
                       min(timestamp) AS first_ts, max(timestamp) AS last_ts
                FROM security_events
                WHERE tenant_id = :t AND timestamp >= :since AND timestamp <= :now
                  AND event_type = 'network' AND src_ip IS NOT NULL AND coalesce(domain, dest_ip) IS NOT NULL
                GROUP BY src_ip, coalesce(domain, dest_ip), dest_ip, dest_port, source_type
                HAVING count(*) >= :min
                ORDER BY count(*) DESC
                LIMIT 1000
                """
            ),
            {"t": tenant_id, "since": since, "now": now, "min": s.beacon_min_connections},
        )
    ).all()
    specs: list[AlertSpec] = []
    for src, dst, dest_ip, port, source_type, host, ts, sizes, ids, first_ts, last_ts in rows:
        if port in _BEACON_IGNORED_PORTS or _allowed(dst, allowlist) or (dest_ip and is_private_ip(dest_ip)):
            continue
        sc = beacon_score(list(ts), list(sizes))
        if sc is None or sc.score < s.beacon_score_threshold or sc.span_hours < 1 or sc.median_interval_s < 5:
            continue
        severity = int(55 + 30 * (sc.score - s.beacon_score_threshold) / max(0.01, 1 - s.beacon_score_threshold))
        who = host or src
        specs.append(
            _spec(
                BEACON_RULE,
                title=f"Possible C2 beaconing: {who} → {dst}:{port or ''} every ~{sc.median_interval_s:.0f}s",
                severity=min(85, severity),
                dedup_key=f"{BEACON_RULE}|{src}|{dst}|{port}",
                window_s=s.beacon_lookback_hours * 3600,
                first_ts=first_ts,
                last_ts=last_ts,
                event_ids=list(ids),
                entities={k: v for k, v in {"hostname": host, "src_ip": src, "dest_ip": dest_ip}.items() if v},
                source_types=[source_type],
                details={"beacon": {**sc.as_dict(), "destination": dst, "port": port}},
            )
        )
    return specs


async def find_dns_tunnels(
    session: AsyncSession, tenant_id: uuid.UUID, now: datetime, allowlist: list[str]
) -> list[AlertSpec]:
    s = get_settings()
    rows = (
        await session.execute(
            text(
                """
                SELECT coalesce(hostname, src_ip) AS who, min(hostname), min(src_ip), domain, count(*),
                       (array_agg(id ORDER BY timestamp DESC))[1:5], min(timestamp), max(timestamp),
                       min(source_type)
                FROM security_events
                WHERE tenant_id = :t AND event_type = 'dns' AND domain IS NOT NULL
                  AND timestamp >= :since AND timestamp <= :now
                GROUP BY coalesce(hostname, src_ip), domain
                LIMIT 50000
                """
            ),
            {"t": tenant_id, "since": now - timedelta(hours=1), "now": now},
        )
    ).all()
    groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"subs": set(), "lens": [], "ids": [], "n": 0, "first": None, "last": None}
    )
    for who, host, src, domain, n, ids, first, last, source_type in rows:
        base = base_domain(domain)
        sub = domain[: -len(base)].rstrip(".") if domain.endswith(base) else ""
        if not sub or who is None:
            continue
        g = groups[(who, base)]
        g.update(host=host, src=src, source_type=source_type)
        g["subs"].add(sub)
        g["lens"].append(len(sub))
        g["n"] += n
        if len(g["ids"]) < 30:
            g["ids"].extend(ids)
        g["first"] = min(x for x in (g["first"], first) if x is not None)
        g["last"] = max(x for x in (g["last"], last) if x is not None)
    specs: list[AlertSpec] = []
    for (who, base), g in groups.items():
        if len(g["subs"]) < s.dns_tunnel_min_unique_subdomains or _allowed(base, allowlist):
            continue
        avg_len = statistics.mean(g["lens"])
        if avg_len < 20:
            continue
        specs.append(
            _spec(
                DNS_TUNNEL_RULE,
                title=f"Possible DNS tunnelling: {who} sent {len(g['subs'])} unique subdomains of {base}",
                severity=70 if avg_len >= 35 else 62,
                dedup_key=f"{DNS_TUNNEL_RULE}|{who}|{base}",
                window_s=3 * 3600,
                first_ts=g["first"],
                last_ts=g["last"],
                event_ids=g["ids"][:30],
                entities={k: v for k, v in {"hostname": g["host"], "src_ip": g["src"], "domain": base}.items() if v},
                source_types=[g["source_type"]],
                details={
                    "dns_tunnel": {
                        "domain": base,
                        "unique_subdomains": len(g["subs"]),
                        "queries": g["n"],
                        "avg_subdomain_length": round(avg_len, 1),
                        "examples": sorted(g["subs"], key=len, reverse=True)[:3],
                    }
                },
            )
        )
    return specs


def silence_threshold_seconds(avg_gap: float | None) -> float:
    s = get_settings()
    return max(s.silence_min_minutes * 60.0, s.silence_gap_multiplier * (avg_gap or 0.0))


async def find_silent_sources(session: AsyncSession, tenant_id: uuid.UUID, now: datetime) -> list[AlertSpec]:
    s = get_settings()
    sources = (
        (
            await session.execute(
                select(TelemetrySource).where(
                    TelemetrySource.tenant_id == tenant_id,
                    TelemetrySource.silent_since.is_(None),
                    TelemetrySource.event_count >= s.silence_min_events,
                )
            )
        )
        .scalars()
        .all()
    )
    specs: list[AlertSpec] = []
    min_history = timedelta(hours=s.silence_min_history_hours)
    for src in sources:
        if src.muted_until is not None and src.muted_until > now:
            continue
        if src.last_seen - src.first_seen < min_history:
            continue
        quiet = (now - src.last_seen).total_seconds()
        if quiet <= silence_threshold_seconds(src.avg_gap_seconds):
            continue
        src.silent_since = now
        is_host = src.source_type == "wazuh" and src.hostname != "wazuh manager"
        recent_alerts: list[str] = []
        if is_host:
            recent_alerts = list(
                (
                    await session.execute(
                        select(Alert.title)
                        .where(
                            Alert.tenant_id == tenant_id,
                            Alert.hostname == src.hostname,
                            Alert.rule_uid != SILENCE_RULE,
                            Alert.created_at >= src.last_seen - timedelta(minutes=30),
                            Alert.created_at <= src.last_seen + timedelta(minutes=5),
                        )
                        .limit(5)
                    )
                ).scalars()
            )
        ev_ids: list[uuid.UUID] = []
        if is_host:
            ev_ids = list(
                (
                    await session.execute(
                        select(SecurityEvent.id)
                        .where(
                            SecurityEvent.tenant_id == tenant_id,
                            SecurityEvent.hostname == src.hostname,
                            SecurityEvent.source_type == src.source_type,
                        )
                        .order_by(SecurityEvent.ingested_at.desc())
                        .limit(10)
                    )
                ).scalars()
            )
        minutes = int(quiet // 60)
        after = f" right after: {recent_alerts[0]}" if recent_alerts else ""
        specs.append(
            _spec(
                SILENCE_RULE,
                title=f"{src.source_type.capitalize()} telemetry from {src.hostname} stopped {minutes} min ago{after}",
                severity=75 if recent_alerts else 45,
                dedup_key=f"{SILENCE_RULE}|{src.source_type}|{src.hostname}",
                window_s=86400,
                first_ts=src.last_seen,
                last_ts=now,
                event_ids=ev_ids,
                entities={"hostname": src.hostname} if is_host else {},
                source_types=[src.source_type],
                details={
                    "telemetry_silence": {
                        "source": src.source_type,
                        "sender": src.hostname,
                        "last_received": src.last_seen.isoformat(),
                        "quiet_minutes": minutes,
                        "usual_gap_seconds": round(src.avg_gap_seconds or 0, 1),
                        "events_before_silence": src.event_count,
                        "alerts_just_before": recent_alerts,
                    }
                },
            )
        )
    return specs


async def find_alert_storm(session: AsyncSession, tenant_id: uuid.UUID, now: datetime) -> list[AlertSpec]:
    s = get_settings()
    window = timedelta(minutes=10)
    oldest = (
        await session.execute(select(func.min(Alert.created_at)).where(Alert.tenant_id == tenant_id))
    ).scalar_one()
    if oldest is None or oldest > now - timedelta(days=1):
        return []  # no baseline yet (a fresh organization's first import is not a storm)
    recent = (
        await session.execute(
            select(Alert.rule_uid, func.count())
            .where(Alert.tenant_id == tenant_id, Alert.created_at >= now - window, Alert.rule_uid != STORM_RULE)
            .group_by(Alert.rule_uid)
        )
    ).all()
    total = sum(n for _, n in recent)
    if total < s.alert_storm_min_alerts:
        return []
    start = max(oldest, now - timedelta(days=7))
    before = (
        await session.execute(
            select(func.count()).where(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= start,
                Alert.created_at < now - window,
                Alert.rule_uid != STORM_RULE,
            )
        )
    ).scalar_one()
    slots = max(1.0, (now - window - start) / window)
    baseline = before / slots
    if total < s.alert_storm_factor * max(1.0, baseline):
        return []
    top = Counter(dict(recent)).most_common(5)
    return [
        _spec(
            STORM_RULE,
            title=f"Alert storm: {total} alerts in 10 minutes (usually ~{baseline:.0f})",
            severity=55,
            dedup_key=f"{STORM_RULE}|{tenant_id}",
            window_s=3600,
            first_ts=now - window,
            last_ts=now,
            details={
                "alert_storm": {
                    "alerts_last_10_min": total,
                    "usual_per_10_min": round(baseline, 1),
                    "top_rules": [{"rule_uid": r, "alerts": n} for r, n in top],
                }
            },
        )
    ]
