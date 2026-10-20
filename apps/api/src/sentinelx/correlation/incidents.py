"""Incident builder: aggregates alerts, preserves evidence, scores risk, names and promotes incidents."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.detection.builtin import IOC_RULE, NEW_SOURCE_RULE
from sentinelx.metrics import INCIDENTS_CREATED
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import (
    Alert,
    AlertEvent,
    Asset,
    Identity,
    Incident,
    IncidentActivity,
    IncidentEntity,
    MlPrediction,
    ThreatIntelResult,
)
from sentinelx.risk.engine import RiskInputs, confidence, score_incident

EVIDENCE_CAP = 5000

CATEGORY_LABELS = {
    "account_compromise": "Possible account compromise",
    "credential_attack": "Password guessing",
    "reconnaissance": "Network reconnaissance",
    "ransomware_activity": "Possible ransomware activity",
    "data_exfiltration": "Possible data exfiltration",
    "privilege_abuse": "Suspicious privilege change",
    "suspicious_execution": "Suspicious execution",
    "c2_activity": "Possible command-and-control activity",
    "known_threat": "Contact with known malicious infrastructure",
    "behavioral_anomaly": "Unusual behavior",
    "suspicious_activity": "Suspicious activity",
}


def classify(techniques: set[str], tactics: list[str], rule_uids: set[str], sources: set[str]) -> str:
    base = {t.split(".")[0] for t in techniques}
    if sources == {"ml"}:
        return "behavioral_anomaly"
    if "T1110" in base and ("T1078" in base or NEW_SOURCE_RULE in rule_uids):
        return "account_compromise"
    if {"T1486", "T1490"} & base:
        return "ransomware_activity"
    if "exfiltration" in tactics:
        return "data_exfiltration"
    if "T1110" in base:
        return "credential_attack"
    if tactics and set(tactics) <= {"discovery", "reconnaissance"}:
        return "reconnaissance"
    if {"T1098", "T1136", "T1548"} & base:
        return "privilege_abuse"
    if "execution" in tactics:
        return "suspicious_execution"
    if "command-and-control" in tactics:
        return "c2_activity"
    if IOC_RULE in rule_uids:
        return "known_threat"
    return "suspicious_activity"


def make_title(category: str, host: str | None, user: str | None, src: str | None, top_alert: str) -> str:
    label = CATEGORY_LABELS[category]
    if category in ("account_compromise", "credential_attack"):
        target = " on ".join(x for x in (user, host) if x) or src or "unknown account"
        return f"{label}: {target}"
    if category == "reconnaissance":
        return f"{label} from {src or host or 'unknown source'}"
    if category == "suspicious_activity":
        return f"{top_alert}{' on ' + host if host else ''}"
    where = host or user or src
    return f"{label}{' on ' + where if where else ''}"


def _primary(entities: list[IncidentEntity], kind: str) -> str | None:
    cands = [e for e in entities if e.kind == kind]
    if not cands:
        return None
    return max(cands, key=lambda e: (e.alert_count, e.last_seen)).value


async def _snapshot_evidence(session: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> None:
    await session.execute(
        text(
            """
        INSERT INTO incident_evidence (incident_id, event_id, tenant_id, alert_id, timestamp, snapshot)
        SELECT :inc, x.id, x.tenant_id, x.alert_id, x.timestamp, x.snap FROM (
            SELECT DISTINCT ON (e.id) e.id, e.tenant_id, ae.alert_id, e.timestamp,
                   (to_jsonb(e) - 'tenant_id') AS snap
            FROM alerts a
            JOIN alert_events ae ON ae.alert_id = a.id
            JOIN security_events e ON e.id = ae.event_id
            WHERE a.incident_id = :inc AND a.tenant_id = :t
            ORDER BY e.id, ae.alert_id
        ) x
        WHERE NOT EXISTS (SELECT 1 FROM incident_evidence ie WHERE ie.incident_id = :inc AND ie.event_id = x.id)
        ORDER BY x.timestamp
        LIMIT GREATEST(0, :cap - (SELECT count(*) FROM incident_evidence WHERE incident_id = :inc))
        ON CONFLICT DO NOTHING
        """
        ),
        {"inc": incident_id, "t": tenant_id, "cap": EVIDENCE_CAP},
    )


async def recompute_incident(session: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> Incident | None:
    """Rebuild everything derived from an incident's alerts: evidence, ATT&CK, risk, confidence, title,
    description and promotion. Called whenever alerts are added, moved or enriched."""
    catalog = get_catalog()
    inc = await session.get(Incident, incident_id)
    if inc is None or inc.status == "merged":
        return inc
    alerts = list(
        (
            await session.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.incident_id == incident_id))
        ).scalars()
    )
    if not alerts:
        return inc
    await _snapshot_evidence(session, tenant_id, incident_id)
    event_count = (
        await session.execute(
            select(func.count(func.distinct(AlertEvent.event_id)))
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(Alert.incident_id == incident_id, Alert.tenant_id == tenant_id)
        )
    ).scalar_one()
    entities = list(
        (await session.execute(select(IncidentEntity).where(IncidentEntity.incident_id == incident_id))).scalars()
    )

    techniques = sorted({t for a in alerts for t in (a.mitre_techniques or []) if catalog.exists(t)})
    tactics = catalog.tactics_for(techniques)
    source_types = sorted({st for a in alerts for st in (a.source_types or [])})
    telemetry_sources = [st for st in source_types if st != "ml"]  # ML is an analysis, not a telemetry source
    rule_uids = {a.rule_uid for a in alerts}
    only_ml = {a.source for a in alerts} == {"ml"}

    inputs = await _risk_inputs(session, tenant_id, alerts, entities, event_count, tactics, telemetry_sources)
    risk = score_incident(inputs)
    inc.confidence, inc.confidence_factors = confidence(
        len(telemetry_sources), len(rule_uids), bool(inputs.ti_matches), only_ml
    )

    category = classify(set(techniques), tactics, rule_uids, {a.source for a in alerts})
    first_src = next((a.src_ip for a in sorted(alerts, key=lambda a: a.first_event_at) if a.src_ip), None)
    inc.category = category
    inc.title = make_title(
        category, _primary(entities, "host"), _primary(entities, "user"), first_src, inputs.top_alert_title
    )
    inc.description = _describe(alerts, event_count, telemetry_sources)
    inc.risk_score, inc.severity, inc.risk_breakdown = risk.score, risk.severity, risk.breakdown()
    inc.first_event_at = min(a.first_event_at for a in alerts)
    inc.last_event_at = max(a.last_event_at for a in alerts)
    inc.mitre_techniques, inc.tactics = techniques, tactics
    inc.alert_count, inc.event_count, inc.source_types = len(alerts), event_count, source_types
    inc.updated_at = datetime.now(UTC)

    if not inc.promoted:
        _promote_if_warranted(session, inc, alerts, risk.score, tactics)
    await _update_entity_risk(
        session,
        tenant_id,
        sorted({e.value for e in entities if e.kind == "host"}),
        sorted({e.value for e in entities if e.kind == "user"}),
    )
    return inc


async def _risk_inputs(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    alerts: list[Alert],
    entities: list[IncidentEntity],
    event_count: int,
    tactics: list[str],
    telemetry_sources: list[str],
) -> RiskInputs:
    """Collect the context the risk model needs: asset criticality, privileged users, threat intel, ML."""
    hosts = sorted({e.value for e in entities if e.kind == "host"})
    users = sorted({e.value for e in entities if e.kind == "user"})
    indicators = [e.value for e in entities if e.kind in ("ip", "domain", "hash")]
    first = min(a.first_event_at for a in alerts)
    last = max(a.last_event_at for a in alerts)

    assets: list[Any] = []
    privileged: list[str] = []
    ti_rows: list[ThreatIntelResult] = []
    ml_rows: list[Any] = []
    if hosts:
        assets = list(
            (
                await session.execute(
                    select(Asset.hostname, Asset.criticality).where(
                        Asset.tenant_id == tenant_id, Asset.hostname.in_(hosts)
                    )
                )
            ).all()
        )
        ml_rows = list(
            (
                await session.execute(
                    select(MlPrediction.entity_id, func.max(MlPrediction.anomaly_score))
                    .where(
                        MlPrediction.tenant_id == tenant_id,
                        MlPrediction.entity_id.in_(hosts),
                        MlPrediction.is_anomaly.is_(True),
                        MlPrediction.window_start >= first - timedelta(hours=1),
                        MlPrediction.window_start <= last + timedelta(hours=1),
                    )
                    .group_by(MlPrediction.entity_id)
                )
            ).all()
        )
    if users:
        privileged = list(
            (
                await session.execute(
                    select(Identity.username).where(
                        Identity.tenant_id == tenant_id, Identity.username.in_(users), Identity.privileged.is_(True)
                    )
                )
            ).scalars()
        )
    if indicators:
        ti_rows = list(
            (
                await session.execute(
                    select(ThreatIntelResult).where(
                        ThreatIntelResult.tenant_id == tenant_id,
                        ThreatIntelResult.value.in_(indicators),
                        ThreatIntelResult.verdict.in_(["malicious", "suspicious"]),
                    )
                )
            ).scalars()
        )

    # ML alerts never drive the "detection severity" factor unless nothing else exists
    rule_alerts = [a for a in alerts if a.source != "ml"] or alerts
    top = max(alerts, key=lambda a: (a.severity, a.event_count))
    return RiskInputs(
        max_alert_severity=max(a.severity for a in rule_alerts),
        alert_count=len(alerts),
        event_count=event_count,
        distinct_rules=len({a.rule_uid for a in alerts}),
        distinct_sources=max(1, len(telemetry_sources)),
        max_asset_criticality=max((c for _, c in assets), default=None),
        critical_assets=[h for h, c in assets if c >= 4],
        privileged_users=privileged,
        new_source_logon=any(a.rule_uid == NEW_SOURCE_RULE for a in alerts),
        ti_matches=[
            {"value": r.value, "verdict": r.verdict, "confidence": r.confidence, "provider": r.provider}
            for r in ti_rows
        ],
        ml_max_score=max((float(score) for _, score in ml_rows), default=0.0),
        ml_hosts=[host for host, _ in ml_rows],
        tactics=tactics,
        top_alert_title=top.title,
    )


def _describe(alerts: list[Alert], event_count: int, telemetry_sources: list[str]) -> str:
    """Plain-language summary: how much, from where, over how long, and what happened in order."""
    ordered = sorted(alerts, key=lambda a: a.first_event_at)
    sequence: list[str] = []
    for a in ordered:
        name = a.title.split(":")[0] if a.rule_uid == IOC_RULE else a.title  # "Known malicious ip observed"
        if name not in sequence:
            sequence.append(name)
    first, last = ordered[0].first_event_at, max(a.last_event_at for a in alerts)
    seconds = (last - first).total_seconds()
    duration = f"{int(seconds // 60)} minutes" if seconds < 7200 else f"{seconds / 3600:.1f} hours"

    def plural(n: int, word: str) -> str:
        return f"{n} {word}{'s' if n != 1 else ''}"

    shown = " → ".join(sequence[:8]) + (f" → and {len(sequence) - 8} more" if len(sequence) > 8 else "")
    return (
        f"{plural(len(alerts), 'related detection')} from {plural(event_count, 'event')} "
        f"({', '.join(telemetry_sources) or 'behavioral analysis'}) over {duration}, "
        f"starting {first:%Y-%m-%d %H:%M} UTC. In order: {shown}."
    )


def _promote_if_warranted(
    session: AsyncSession, inc: Incident, alerts: list[Alert], score: int, tactics: list[str]
) -> None:
    s = get_settings()
    reason = _promotion_reason(
        alerts, score, tactics, s.incident_promote_severity, s.incident_promote_risk, s.ml_alone_can_promote
    )
    if not reason:
        return
    inc.promoted = True
    inc.promoted_at = datetime.now(UTC)
    inc.promotion_reason = reason
    INCIDENTS_CREATED.inc()
    session.add(
        IncidentActivity(
            id=uuid.uuid4(),
            tenant_id=inc.tenant_id,
            incident_id=inc.id,
            kind="promoted",
            message=f"Raised to an incident: {reason}",
            data={"risk_score": score},
        )
    )


def _promotion_reason(
    alerts: list[Alert], score: int, tactics: list[str], sev_thr: int, risk_thr: int, ml_alone: bool
) -> str | None:
    """Deterministic promotion policy. ML signals alone never promote unless explicitly enabled."""
    non_ml = [a for a in alerts if a.source != "ml"]
    if not non_ml:
        return "behavioral anomaly policy (ML-only promotion enabled)" if ml_alone and score >= risk_thr else None
    worst = max(non_ml, key=lambda a: a.severity)
    if worst.severity >= sev_thr:
        return f"high-severity detection '{worst.title}' ({worst.severity}/100)"
    if score >= risk_thr:
        return f"risk score {score} reached the threshold of {risk_thr}"
    if len({a.rule_uid for a in non_ml}) >= 2 and len(tactics) >= 2:
        return f"{len({a.rule_uid for a in non_ml})} related detections across {len(tactics)} ATT&CK tactics"
    return None


async def _open_incident_risk(
    session: AsyncSession, tenant_id: uuid.UUID, kind: str, names: list[str]
) -> dict[str, int]:
    """Highest risk score among the open, promoted incidents that involve each host/user."""
    rows = (
        await session.execute(
            select(IncidentEntity.value, func.max(Incident.risk_score))
            .join(Incident, Incident.id == IncidentEntity.incident_id)
            .where(
                IncidentEntity.tenant_id == tenant_id,
                IncidentEntity.kind == kind,
                IncidentEntity.value.in_(names),
                Incident.promoted.is_(True),
                Incident.status.notin_(["resolved", "closed", "merged"]),
            )
            .group_by(IncidentEntity.value)
        )
    ).all()
    return {name: int(score or 0) for name, score in rows}


def _record_risk(obj: Asset | Identity, score: int, now: str) -> None:
    if score != obj.risk_score:
        obj.risk_score = score
        obj.risk_history = [*(obj.risk_history or [])[-49:], {"at": now, "score": score}]


async def _update_entity_risk(session: AsyncSession, tenant_id: uuid.UUID, hosts: list[str], users: list[str]) -> None:
    """An asset's / identity's risk is the highest risk of its open incidents (with a bounded history)."""
    now = datetime.now(UTC).isoformat()
    if hosts:
        scores = await _open_incident_risk(session, tenant_id, "host", hosts)
        assets = await session.execute(select(Asset).where(Asset.tenant_id == tenant_id, Asset.hostname.in_(hosts)))
        for asset in assets.scalars():
            _record_risk(asset, scores.get(asset.hostname, 0), now)
    if users:
        scores = await _open_incident_risk(session, tenant_id, "user", users)
        identities = await session.execute(
            select(Identity).where(Identity.tenant_id == tenant_id, Identity.username.in_(users))
        )
        for identity in identities.scalars():
            _record_risk(identity, scores.get(identity.username, 0), now)
