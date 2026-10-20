"""Detection pipeline: events -> Sigma rules + built-ins -> rule matches -> Sigma correlations -> alerts."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.detection.alerts import AlertSpec, collapse, entities_from_event, observed_from_event, upsert_alert
from sentinelx.detection.builtin import BUILTIN_RULES, evaluate_builtins
from sentinelx.detection.sigma.fields import MATCH_FIELDS
from sentinelx.detection.sigma.rules import RuleSet, SigmaCorrelation, SigmaRule, load_rules
from sentinelx.logging import get_logger
from sentinelx.metrics import DETECTION_DURATION
from sentinelx.persistence.models import AlertEvent, DetectionRule, RuleMatch, SecurityEvent

log = get_logger(__name__)

EVENT_COLUMNS = list(SecurityEvent.__table__.columns.keys())


def event_to_dict(row: SecurityEvent) -> dict[str, Any]:
    d = {c: getattr(row, c if c != "metadata" else "event_metadata") for c in EVENT_COLUMNS}
    d["metadata"] = d.get("metadata") or {}
    return d


@dataclass
class CompiledRules:
    ruleset: RuleSet
    by_event_type: dict[str | None, list[SigmaRule]]
    correlation_inputs: set[str]
    stamp: str = ""


_compiled: CompiledRules | None = None
_custom_docs: list[tuple[str, str]] = []
CUSTOM_PREFIX = "custom:"


def compile_ruleset(rs: RuleSet) -> CompiledRules:
    by_type: dict[str | None, list[SigmaRule]] = defaultdict(list)
    for r in rs.rules:
        if r.event_types is None:
            by_type[None].append(r)
        else:
            for et in r.event_types:
                by_type[et].append(r)
    inputs = {ref for c in rs.correlations for ref in c.resolved_refs}
    return CompiledRules(rs, dict(by_type), inputs)


def get_rules(reload: bool = False) -> CompiledRules:
    global _compiled
    if _compiled is None or reload:
        rs = load_rules(get_settings().sigma_rules_dir, _custom_docs)
        for path, err in rs.errors:
            log.warning("sigma_rule_rejected", path=path, error=err)
        stamp = _compiled.stamp if _compiled else ""
        _compiled = compile_ruleset(rs)
        _compiled.stamp = stamp
    return _compiled


async def refresh_custom_rules(session: AsyncSession, force: bool = False) -> CompiledRules:
    """Reload rules when the rule catalogue changed (another process added/edited a custom rule).

    The stamp (rule count + latest update) is one cheap indexed query per detection batch."""
    global _custom_docs
    row = (await session.execute(select(func.count(), func.max(DetectionRule.updated_at)))).one()
    stamp = f"{row[0]}|{row[1]}"
    compiled = get_rules()
    if force or compiled.stamp != stamp:
        customs = (
            await session.execute(
                select(DetectionRule.rule_uid, DetectionRule.content).where(
                    DetectionRule.source_path.is_(None), DetectionRule.kind.in_(["sigma", "correlation"])
                )
            )
        ).all()
        _custom_docs = [(f"{CUSTOM_PREFIX}{uid}", content) for uid, content in customs]
        compiled = get_rules(reload=True)
        compiled.stamp = stamp
    return compiled


async def enabled_rule_uids(session: AsyncSession, tenant_id: uuid.UUID | None = None) -> set[str]:
    """Globally enabled rules minus the ones this tenant switched off (per-tenant tuning)."""
    rows = set((await session.execute(select(DetectionRule.rule_uid).where(DetectionRule.enabled.is_(True)))).scalars())
    if tenant_id is not None:
        from sentinelx.persistence.models import Tenant

        t = await session.get(Tenant, tenant_id)
        rows -= set(((t.settings or {}) if t else {}).get("disabled_rules", []))
    return rows


def _cmp(value: int, cond: dict[str, Any]) -> bool:
    checks = {
        "gte": value >= cond.get("gte", 0),
        "gt": value > cond.get("gt", -1),
        "lte": value <= cond.get("lte", 0),
        "lt": value < cond.get("lt", 0),
        "eq": value == cond.get("eq"),
    }
    return all(checks[k] for k in ("gte", "gt", "lte", "lt", "eq") if k in cond)


def _match_fields(ev: dict[str, Any]) -> dict[str, Any]:
    return {k: (str(ev[k]) if ev.get(k) is not None else None) for k in MATCH_FIELDS}


async def run_detection(session: AsyncSession, tenant_id: uuid.UUID, event_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    """Evaluate all enabled detections on the given (already stored) events. Returns touched alert ids."""
    started = time.perf_counter()
    s = get_settings()
    rows = (
        (
            await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.id.in_(event_ids))
                .order_by(SecurityEvent.timestamp)
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return []
    events = [event_to_dict(r) for r in rows]
    compiled = await refresh_custom_rules(session)
    enabled = await enabled_rule_uids(session, tenant_id)
    window = s.correlation_window_minutes * 60

    specs: list[AlertSpec] = []
    matches: list[dict[str, Any]] = []
    sigma_matched: set[uuid.UUID] = set()
    for ev in events:
        candidates = compiled.by_event_type.get(ev["event_type"], []) + compiled.by_event_type.get(None, [])
        for rule in candidates:
            if rule.uid not in enabled:
                continue
            try:
                hit = rule.matches(ev)
            except Exception as e:  # a broken rule must never stop the pipeline
                log.warning("rule_evaluation_error", rule=rule.uid, error=str(e))
                continue
            if not hit:
                continue
            if rule.uid in compiled.correlation_inputs:
                matches.append(
                    {
                        "tenant_id": tenant_id,
                        "rule_uid": rule.uid,
                        "event_id": ev["id"],
                        "ts": ev["timestamp"],
                        "fields": _match_fields(ev),
                        "alert_id": None,
                    }
                )
            if rule.generate:
                sigma_matched.add(ev["id"])
                who = ev.get("hostname") or ev.get("src_ip") or "-"
                specs.append(
                    AlertSpec(
                        rule_uid=rule.uid,
                        title=rule.title,
                        description=rule.description,
                        source="sigma",
                        severity=rule.severity,
                        dedup_key=f"{rule.uid}|{who}|{ev.get('username') or '-'}",
                        window_s=window,
                        first_ts=ev["timestamp"],
                        last_ts=ev["timestamp"],
                        event_ids=[ev["id"]],
                        techniques=rule.techniques,
                        entities=entities_from_event(ev),
                        source_types=[ev["source_type"]],
                        details={"observed": observed_from_event(ev), "falsepositives": rule.falsepositives},
                    )
                )

    specs.extend(await evaluate_builtins(session, tenant_id, events, sigma_matched, enabled))

    touched: list[uuid.UUID] = []
    for spec in collapse(specs):
        aid, _ = await upsert_alert(session, tenant_id, spec)
        touched.append(aid)

    if matches:
        for i in range(0, len(matches), 1000):
            await session.execute(pg_insert(RuleMatch).values(matches[i : i + 1000]))
        touched.extend(await _run_correlations(session, tenant_id, compiled, matches, enabled))

    DETECTION_DURATION.observe(time.perf_counter() - started)
    return list(dict.fromkeys(touched))


async def _run_correlations(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    compiled: CompiledRules,
    new_matches: list[dict[str, Any]],
    enabled: set[str],
) -> list[uuid.UUID]:
    touched: list[uuid.UUID] = []
    pending = list(new_matches)
    for corr in compiled.ruleset.correlations:
        if corr.uid not in enabled:
            continue
        relevant = [m for m in pending if m["rule_uid"] in corr.resolved_refs]
        if not relevant:
            continue
        groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        for m in relevant:
            key = tuple(m["fields"].get(g) for g in corr.group_by)
            if any(v is None for v in key):
                continue
            if key not in groups or m["ts"] > groups[key]["ts"]:
                groups[key] = m
        for key, last in groups.items():
            fired = await _evaluate_group(session, tenant_id, corr, key, last["ts"])
            if fired is None:
                continue
            value, evidence = fired
            group_vals = dict(zip(corr.group_by, key, strict=True))
            entities = {
                k: v
                for k, v in last["fields"].items()
                if v and k in ("hostname", "username", "src_ip", "dest_ip", "domain", "process_name", "file_hash")
            }
            entities.update(
                {
                    k: v
                    for k, v in group_vals.items()
                    if k in entities or k in ("hostname", "username", "src_ip", "dest_ip", "domain")
                }
            )
            first_ts = last["ts"] - timedelta(seconds=corr.timespan_s)
            evidence_ts = await _evidence_bounds(session, tenant_id, evidence)
            spec = AlertSpec(
                rule_uid=corr.uid,
                title=corr.title,
                description=corr.description,
                source="correlation",
                severity=corr.severity,
                dedup_key=f"{corr.uid}|" + "|".join(str(k) for k in key),
                window_s=corr.timespan_s,
                first_ts=evidence_ts[0] or first_ts,
                last_ts=evidence_ts[1] or last["ts"],
                event_ids=evidence,
                techniques=corr.techniques,
                entities=entities,
                source_types=await _source_types(session, tenant_id, evidence),
                details={
                    "correlation": {
                        "type": corr.type,
                        "group_by": group_vals,
                        "value": value,
                        "condition": corr.condition,
                        "timespan_seconds": corr.timespan_s,
                    },
                    "falsepositives": corr.falsepositives,
                },
            )
            aid, _ = await upsert_alert(session, tenant_id, spec)
            touched.append(aid)
            m = {
                "tenant_id": tenant_id,
                "rule_uid": corr.uid,
                "event_id": None,
                "alert_id": aid,
                "ts": last["ts"],
                "fields": {**last["fields"], **{k: str(v) for k, v in group_vals.items()}},
            }
            await session.execute(pg_insert(RuleMatch).values([m]))
            pending.append(m)
    return touched


async def _evaluate_group(
    session: AsyncSession, tenant_id: uuid.UUID, corr: SigmaCorrelation, key: tuple[Any, ...], t_end: datetime
) -> tuple[int, list[uuid.UUID]] | None:
    t_start = t_end - timedelta(seconds=corr.timespan_s)
    conds = [
        RuleMatch.tenant_id == tenant_id,
        RuleMatch.rule_uid.in_(corr.resolved_refs),
        RuleMatch.ts >= t_start,
        RuleMatch.ts <= t_end,
    ]
    for g, v in zip(corr.group_by, key, strict=True):
        conds.append(RuleMatch.fields[g].astext == str(v))
    where = and_(*conds)

    if corr.type == "event_count":
        n = (await session.execute(select(func.count()).where(where))).scalar_one()
        if not _cmp(n, corr.condition):
            return None
        value = n
    elif corr.type == "value_count":
        f = corr.condition["field"]
        n = (
            await session.execute(select(func.count(func.distinct(RuleMatch.fields[f].astext))).where(where))
        ).scalar_one()
        if not _cmp(n, corr.condition):
            return None
        value = n
    else:
        rows = (
            await session.execute(select(RuleMatch.rule_uid, RuleMatch.ts).where(where).order_by(RuleMatch.ts))
        ).all()
        seen: dict[str, list[datetime]] = defaultdict(list)
        for uid, ts in rows:
            seen[uid].append(ts)
        if corr.type == "temporal":
            if not all(seen.get(r) for r in corr.resolved_refs):
                return None
        else:  # temporal_ordered: greedy in-order sequence
            t = t_start
            for ref in corr.resolved_refs:
                nxt = next((ts for ts in seen.get(ref, []) if ts >= t), None)
                if nxt is None:
                    return None
                t = nxt
        value = len(rows)

    ev_rows = (
        await session.execute(
            select(RuleMatch.event_id, RuleMatch.alert_id).where(where).order_by(RuleMatch.ts.desc()).limit(500)
        )
    ).all()
    evidence = [e for e, _ in ev_rows if e]
    alert_ids = [a for _, a in ev_rows if a]
    if alert_ids:
        linked = (
            (
                await session.execute(
                    select(AlertEvent.event_id).where(AlertEvent.alert_id.in_(set(alert_ids))).limit(500)
                )
            )
            .scalars()
            .all()
        )
        evidence.extend(linked)
    return value, list(dict.fromkeys(evidence))


async def _evidence_bounds(
    session: AsyncSession, tenant_id: uuid.UUID, ids: list[uuid.UUID]
) -> tuple[datetime | None, datetime | None]:
    if not ids:
        return None, None
    row = (
        await session.execute(
            select(func.min(SecurityEvent.timestamp), func.max(SecurityEvent.timestamp)).where(
                SecurityEvent.tenant_id == tenant_id, SecurityEvent.id.in_(ids)
            )
        )
    ).one()
    return row[0], row[1]


async def _source_types(session: AsyncSession, tenant_id: uuid.UUID, ids: list[uuid.UUID]) -> list[str]:
    if not ids:
        return []
    return sorted(
        set(
            (
                await session.execute(
                    select(SecurityEvent.source_type)
                    .where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.id.in_(ids))
                    .distinct()
                )
            )
            .scalars()
            .all()
        )
    )


async def sync_rules_to_db(session: AsyncSession, actor: str = "system") -> dict[str, int]:
    """Mirror the rules repository into ``detection_rules`` with versioning (rule_versions)."""
    from sentinelx.detection.sigma.rules import content_hash
    from sentinelx.persistence.models import RuleVersion

    compiled = await refresh_custom_rules(session, force=True)
    existing = {r.rule_uid: r for r in (await session.execute(select(DetectionRule))).scalars().all()}
    created = updated = 0
    items: list[dict[str, Any]] = []
    for r in (x for x in compiled.ruleset.rules if not x.path.startswith(CUSTOM_PREFIX)):
        items.append(
            {
                "rule_uid": r.uid,
                "name": r.name,
                "title": r.title,
                "description": r.description,
                "kind": "sigma",
                "status": r.status,
                "level": r.level,
                "severity": r.severity,
                "tags": r.tags,
                "techniques": r.techniques,
                "content": r.content,
                "path": r.path,
                "generate": r.generate,
                "falsepositives": r.falsepositives,
            }
        )
    for c in (x for x in compiled.ruleset.correlations if not x.path.startswith(CUSTOM_PREFIX)):
        items.append(
            {
                "rule_uid": c.uid,
                "name": c.name,
                "title": c.title,
                "description": c.description,
                "kind": "correlation",
                "status": c.status,
                "level": c.level,
                "severity": c.severity,
                "tags": c.tags,
                "techniques": c.techniques,
                "content": c.content,
                "path": c.path,
                "generate": True,
                "falsepositives": c.falsepositives,
            }
        )
    from sentinelx.detection.sigma.rules import LEVEL_SEVERITY

    for b in BUILTIN_RULES:
        content = f"builtin evaluator: {b['rule_uid']}\n{b['description']}"
        items.append(
            {
                "rule_uid": b["rule_uid"],
                "name": None,
                "title": b["title"],
                "description": b["description"],
                "kind": "source"
                if b["rule_uid"].startswith("sx-source")
                else "ml"
                if b["rule_uid"].startswith("sx-ml")
                else "builtin",
                "status": "stable",
                "level": b["level"],
                "severity": LEVEL_SEVERITY[b["level"]],
                "tags": [],
                "techniques": b["techniques"],
                "content": content,
                "path": None,
                "generate": True,
                "falsepositives": b["falsepositives"],
            }
        )
    for it in items:
        sha = content_hash(it["content"])
        row = existing.get(it["rule_uid"])
        if row is None:
            row = DetectionRule(
                id=uuid.uuid4(),
                rule_uid=it["rule_uid"],
                name=it["name"],
                title=it["title"],
                description=it["description"],
                kind=it["kind"],
                status=it["status"],
                level=it["level"],
                severity=it["severity"],
                tags=it["tags"],
                mitre_techniques=it["techniques"],
                content=it["content"],
                content_sha256=sha,
                version=1,
                enabled=True,
                generates_alerts=it["generate"],
                source_path=it["path"],
                falsepositives=it["falsepositives"],
            )
            session.add(row)
            await session.flush()
            session.add(
                RuleVersion(
                    id=uuid.uuid4(),
                    rule_id=row.id,
                    version=1,
                    content=it["content"],
                    content_sha256=sha,
                    created_by=actor,
                )
            )
            created += 1
        elif row.content_sha256 != sha:
            row.version += 1
            row.title, row.description, row.status, row.level = (
                it["title"],
                it["description"],
                it["status"],
                it["level"],
            )
            row.severity, row.tags, row.mitre_techniques = it["severity"], it["tags"], it["techniques"]
            row.content, row.content_sha256, row.generates_alerts = it["content"], sha, it["generate"]
            row.falsepositives, row.source_path, row.name = it["falsepositives"], it["path"], it["name"]
            row.updated_at = func.now()
            session.add(
                RuleVersion(
                    id=uuid.uuid4(),
                    rule_id=row.id,
                    version=row.version,
                    content=it["content"],
                    content_sha256=sha,
                    created_by=actor,
                )
            )
            updated += 1
    return {"created": created, "updated": updated, "total": len(items), "rejected": len(compiled.ruleset.errors)}
