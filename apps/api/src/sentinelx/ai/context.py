"""Incident context builder: the *minimum relevant* evidence for the AI, never the whole database.

Evidence sampling keeps the context small enough for a 4B-parameter local model:
for each alert (most severe first) events are grouped by behaviour signature, and only the first and
last event of each group are included, annotated with how many times the behaviour repeated.
Each included event gets a short reference (E01...) that the model must cite; references are mapped back
to real event ids after validation.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.ai.sanitize import sanitize_record
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import (
    Alert,
    Asset,
    Identity,
    Incident,
    IncidentEntity,
    IncidentEvidence,
    MlPrediction,
    ThreatIntelResult,
)

_SIG_FIELDS = (
    "event_type",
    "event_action",
    "outcome",
    "username",
    "src_ip",
    "dest_ip",
    "dest_port",
    "process_name",
    "domain",
    "rule_name",
)


@dataclass
class AiContext:
    payload: dict[str, Any]
    ref_to_event: dict[str, str]
    allowed_techniques: set[str]
    allowed_indicators: set[str]
    injection_flags: list[dict[str, Any]] = field(default_factory=list)

    def sha256(self) -> str:
        return hashlib.sha256(json.dumps(self.payload, sort_keys=True, default=str).encode()).hexdigest()

    def stats(self) -> dict[str, Any]:
        return {
            "evidence_events": len(self.ref_to_event),
            "alerts": len(self.payload.get("alerts", [])),
            "chars": len(json.dumps(self.payload, default=str)),
            "techniques": sorted(self.allowed_techniques),
        }


def _event_view(snap: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": str(snap.get("timestamp", ""))[:19].replace("T", " "),
        "source": snap.get("source_type"),
        "type": snap.get("event_type"),
        "action": snap.get("event_action"),
        "outcome": snap.get("outcome"),
        "host": snap.get("hostname"),
        "user": snap.get("username"),
        "src_ip": snap.get("src_ip"),
        "dest_ip": snap.get("dest_ip"),
        "dest_port": snap.get("dest_port"),
        "process": snap.get("process_name"),
        "parent_process": snap.get("parent_process_name"),
        "command_line": snap.get("process_command_line"),
        "domain": snap.get("domain"),
        "url": snap.get("url"),
        "file": snap.get("file_path"),
        "bytes_out": snap.get("bytes_out"),
        "source_rule": snap.get("rule_name"),
    }


async def build_context(
    session: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, max_events: int = 40
) -> AiContext:
    """Assemble the (sanitized, size-bounded) evidence package the AI analyst is allowed to see."""
    inc = await session.get(Incident, incident_id)
    if inc is None or inc.tenant_id != tenant_id:
        raise LookupError("incident not found")
    alerts = list(
        (
            await session.execute(
                select(Alert)
                .where(Alert.tenant_id == tenant_id, Alert.incident_id == incident_id)
                .order_by(Alert.severity.desc(), Alert.first_event_at)
            )
        ).scalars()
    )
    evidence = list(
        (
            await session.execute(
                select(IncidentEvidence)
                .where(IncidentEvidence.tenant_id == tenant_id, IncidentEvidence.incident_id == incident_id)
                .order_by(IncidentEvidence.timestamp)
            )
        ).scalars()
    )
    entities = list(
        (await session.execute(select(IncidentEntity).where(IncidentEntity.incident_id == incident_id))).scalars()
    )

    flags: list[dict[str, Any]] = []
    sampled, events_per_alert = _sample_evidence(alerts, evidence, max_events)
    events, ref_to_event, event_to_ref = _number_events(sampled, flags)
    surroundings = await _surrounding_context(session, tenant_id, inc, entities)
    techniques = sorted(set(inc.mitre_techniques or []))
    urls = {str(e["url"]).lower() for e in events if e.get("url")}
    allowed_indicators = surroundings.pop("indicator_values") | urls

    payload: dict[str, Any] = {
        "incident": _incident_view(inc),
        "alerts": _alert_views(alerts, events_per_alert, event_to_ref, flags),
        "evidence_events": events,
        "mitre_techniques_supported_by_rules": _technique_views(techniques),
        **surroundings,
        "allowed_indicators": sorted(allowed_indicators)[:40],
    }
    if flags:
        payload["security_note"] = (
            f"{len({f['ref'] for f in flags})} event(s) contained text written to manipulate AI analysis; it was "
            "withheld. Attempting to manipulate security tooling is itself a strong sign of malicious intent."
        )
    return AiContext(
        payload=payload,
        ref_to_event=ref_to_event,
        allowed_techniques=set(techniques),
        allowed_indicators=allowed_indicators,
        injection_flags=flags,
    )


def _sample_evidence(
    alerts: list[Alert], evidence: list[IncidentEvidence], max_events: int
) -> tuple[list[tuple[IncidentEvidence, int]], dict[uuid.UUID, list[uuid.UUID]]]:
    """Pick a small, representative set of evidence events.

    Pass 1 takes one event per detection so every detection is represented; pass 2 adds the first and
    last event of each behaviour group (events that look alike). Each pick remembers how many similar
    events it stands for. Returns the picks and, per alert, which picked events belong to it.
    """
    by_alert: dict[uuid.UUID | None, list[IncidentEvidence]] = defaultdict(list)
    for ev in evidence:
        by_alert[ev.alert_id].append(ev)
    alert_ids = [a.id for a in alerts]
    order: list[uuid.UUID | None] = [*alert_ids, *(k for k in by_alert if k not in set(alert_ids))]

    chosen: dict[uuid.UUID, tuple[IncidentEvidence, int]] = {}
    per_alert: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for first_pass in (True, False):
        for alert_id in order:
            groups: dict[tuple[Any, ...], list[IncidentEvidence]] = defaultdict(list)
            for ev in by_alert.get(alert_id, []):
                groups[tuple(ev.snapshot.get(f) for f in _SIG_FIELDS)].append(ev)
            for similar in groups.values():
                for pick in [similar[-1]] if first_pass else [similar[0], similar[-1]]:
                    if len(chosen) >= max_events and pick.event_id not in chosen:
                        break
                    chosen.setdefault(pick.event_id, (pick, len(similar)))
                    if alert_id is not None and pick.event_id not in per_alert[alert_id]:
                        per_alert[alert_id].append(pick.event_id)
                if first_pass:
                    break  # one behaviour group per alert in the first pass
    return sorted(chosen.values(), key=lambda item: item[0].timestamp), per_alert


def _number_events(
    sampled: list[tuple[IncidentEvidence, int]], flags: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, str], dict[uuid.UUID, str]]:
    """Give each sampled event a short reference (E01, E02...) and a sanitized view."""
    events: list[dict[str, Any]] = []
    ref_to_event: dict[str, str] = {}
    event_to_ref: dict[uuid.UUID, str] = {}
    for i, (ev, repeats) in enumerate(sampled, start=1):
        ref = f"E{i:02d}"
        ref_to_event[ref] = str(ev.event_id)
        event_to_ref[ev.event_id] = ref
        view = {"ref": ref, **sanitize_record(_event_view(ev.snapshot), ref, flags)}
        if repeats > 1:
            view["similar_events_in_group"] = repeats
        events.append(view)
    return events, ref_to_event, event_to_ref


def _incident_view(inc: Incident) -> dict[str, Any]:
    return {
        "id": f"INC-{inc.number}",
        "title": inc.title,
        "category": inc.category,
        "status": inc.status,
        "risk_score": inc.risk_score,
        "risk_band": inc.severity,
        "deterministic_confidence": inc.confidence,
        "first_event": inc.first_event_at.isoformat(),
        "last_event": inc.last_event_at.isoformat(),
        "alert_count": inc.alert_count,
        "event_count": inc.event_count,
        "telemetry_sources": inc.source_types,
        "risk_contributors": [
            {"factor": c["label"], "points": c["value"], "max": c["max"], "why": c["reason"]}
            for c in inc.risk_breakdown
            if c.get("value")
        ],
    }


def _alert_views(
    alerts: list[Alert],
    events_per_alert: dict[uuid.UUID, list[uuid.UUID]],
    event_to_ref: dict[uuid.UUID, str],
    flags: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    views = []
    for a in alerts:
        refs = [event_to_ref[e] for e in events_per_alert.get(a.id, []) if e in event_to_ref][:8]
        record = {
            "title": a.title,
            "detection_type": a.source,
            "severity": a.severity,
            "level": a.level,
            "event_count": a.event_count,
            "techniques": a.mitre_techniques,
            "evidence_refs": refs,
            "rule_description": a.description[:300],
            "correlation": (a.details or {}).get("correlation"),
        }
        views.append(sanitize_record(record, "alert", flags))
    return views


def _technique_views(techniques: list[str]) -> list[dict[str, Any]]:
    catalog = get_catalog()
    views = []
    for technique_id in techniques:
        technique = catalog.get(technique_id)
        if technique:
            views.append({"technique_id": technique_id, "name": technique.name, "tactics": list(technique.tactics)})
    return views


async def _surrounding_context(
    session: AsyncSession, tenant_id: uuid.UUID, inc: Incident, entities: list[IncidentEntity]
) -> dict[str, Any]:
    """Threat intel, asset/identity context, ML findings and related past incidents."""
    hosts = [e.value for e in entities if e.kind == "host"]
    users = [e.value for e in entities if e.kind == "user"]
    indicator_values = sorted({e.value for e in entities if e.kind in ("ip", "domain", "hash")})

    async def rows(stmt: Any) -> list[Any]:
        return list((await session.execute(stmt)).scalars())

    ti = (
        await rows(
            select(ThreatIntelResult).where(
                ThreatIntelResult.tenant_id == tenant_id, ThreatIntelResult.value.in_(indicator_values)
            )
        )
        if indicator_values
        else []
    )
    assets = await rows(select(Asset).where(Asset.tenant_id == tenant_id, Asset.hostname.in_(hosts))) if hosts else []
    identities = (
        await rows(select(Identity).where(Identity.tenant_id == tenant_id, Identity.username.in_(users)))
        if users
        else []
    )
    anomalies = (
        await rows(
            select(MlPrediction).where(
                MlPrediction.tenant_id == tenant_id,
                MlPrediction.entity_id.in_(hosts),
                MlPrediction.is_anomaly.is_(True),
                MlPrediction.window_start >= inc.first_event_at - timedelta(hours=2),
                MlPrediction.window_start <= inc.last_event_at + timedelta(hours=1),
            )
        )
        if hosts
        else []
    )
    prior = (
        await session.execute(
            select(Incident.number, Incident.title, Incident.status, Incident.disposition)
            .join(IncidentEntity, IncidentEntity.incident_id == Incident.id)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.id != inc.id,
                Incident.promoted.is_(True),
                Incident.created_at >= inc.created_at - timedelta(days=30),
                or_(IncidentEntity.value.in_(hosts or ["-"]), IncidentEntity.value.in_(users or ["-"])),
            )
            .distinct()
            .limit(5)
        )
    ).all()

    return {
        "indicator_values": {v.lower() for v in indicator_values} | {r.value.lower() for r in ti},
        "threat_intelligence": [
            {
                "indicator": r.value,
                "type": r.indicator_type,
                "provider": r.provider,
                "verdict": r.verdict,
                "confidence": r.confidence,
                "tags": r.tags[:6],
            }
            for r in ti
        ],
        "assets": [
            {
                "hostname": a.hostname,
                "os": a.os,
                "criticality_1_to_5": a.criticality,
                "owner": a.owner,
                "environment": a.environment,
                "tags": a.tags,
            }
            for a in assets
        ],
        "identities": [
            {"username": i.username, "privileged": i.privileged, "department": i.department} for i in identities
        ],
        "behavioral_anomalies": [
            {
                "host": m.entity_id,
                "hour": m.window_start.isoformat(),
                "anomaly_score": round(m.anomaly_score, 3),
                "top_deviations": m.top_contributors[:3],
            }
            for m in anomalies
        ],
        "prior_related_incidents": [
            {"id": f"INC-{number}", "title": title, "status": status, "disposition": disposition}
            for number, title, status, disposition in prior
        ],
    }
