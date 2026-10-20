"""Incidents: list, detail, timeline, evidence, graph, lifecycle, notes, response actions, AI, reports."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.ai.service import model_for_tenant
from sentinelx.api.deps import Principal, client_ip, deny, get_db, require
from sentinelx.api.schemas import (
    AiInvestigationOut,
    AlertOut,
    IncidentCreate,
    IncidentDetail,
    IncidentPatch,
    IncidentSummary,
    NoteIn,
    Page,
    ResponseActionIn,
    ResponseActionOut,
    TiResultOut,
)
from sentinelx.correlation.engine import merge_incidents, next_incident_number, tenant_lock_key
from sentinelx.correlation.incidents import recompute_incident
from sentinelx.jobs.queue import enqueue
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import (
    AiInvestigation,
    Alert,
    AnalystNote,
    Asset,
    Identity,
    Incident,
    IncidentActivity,
    IncidentEntity,
    IncidentEvidence,
    MlPrediction,
    ResponseAction,
    ThreatIntelResult,
    User,
)
from sentinelx.reports.incident_report import build_report, render_html
from sentinelx.security.rbac import Perm
from sentinelx.services.audit import audit
from sentinelx.threat_intel.service import classify_indicator, import_indicators, normalize_indicator

router = APIRouter(prefix="/incidents", tags=["incidents"])

OPEN_STATUSES = ["new", "triaged", "investigating", "contained"]


async def _get(db: AsyncSession, principal: Principal, incident_id: uuid.UUID) -> Incident:
    inc = await db.get(Incident, incident_id)
    if inc is None or inc.tenant_id != principal.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return inc


def _activity(db: AsyncSession, inc: Incident, kind: str, actor: str, message: str, **data: Any) -> None:
    db.add(
        IncidentActivity(
            id=uuid.uuid4(),
            tenant_id=inc.tenant_id,
            incident_id=inc.id,
            kind=kind,
            actor=actor,
            message=message,
            data=data,
        )
    )


async def _check_assignee(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Assignees must be active members of this organization (or a super admin, who can work in any)."""
    async with system_session() as sdb:
        u = await sdb.get(User, user_id)
        ok = u is not None and u.is_active and (u.tenant_id == tenant_id or u.role == "SUPER_ADMIN")
    if not ok:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Assignee must be an active member of this organization"
        )


@router.get("/assignees")
async def assignees(
    principal: Principal = Depends(require(Perm.INCIDENT_READ)), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    """People an incident can be assigned to (only roles that can work incidents)."""
    rows = (
        await db.execute(
            select(User.id, User.display_name, User.email, User.role)
            .where(
                User.tenant_id == principal.tenant_id,
                User.is_active.is_(True),
                User.role.in_(["IT_OPERATOR", "SECURITY_ANALYST", "TENANT_ADMIN", "SUPER_ADMIN"]),
            )
            .order_by(User.display_name)
        )
    ).all()
    return [{"id": str(i), "display_name": n, "email": e, "role": r} for i, n, e, r in rows]


@router.get("", response_model=Page[IncidentSummary])
async def list_incidents(
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
    status_: str | None = Query(None, alias="status", description="open | closed | a specific status"),
    severity: str | None = None,
    category: str | None = None,
    q: str | None = Query(None, max_length=200),
    include_groups: bool = Query(False, description="Include un-promoted correlation groups"),
    host: str | None = None,
    user: str | None = None,
    technique: str | None = None,
    sort: str = Query("priority", pattern="^(priority|newest|updated|risk)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[IncidentSummary]:
    stmt: Select[Any] = select(Incident).where(Incident.tenant_id == principal.tenant_id, Incident.status != "merged")
    if not include_groups:
        stmt = stmt.where(Incident.promoted.is_(True))
    if status_ == "open":
        stmt = stmt.where(Incident.status.in_(OPEN_STATUSES))
    elif status_ == "closed":
        stmt = stmt.where(Incident.status.in_(["resolved", "closed"]))
    elif status_:
        stmt = stmt.where(Incident.status == status_)
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity.split(",")))
    if category:
        stmt = stmt.where(Incident.category == category)
    if technique:
        stmt = stmt.where(Incident.mitre_techniques.any(technique.upper()))
    if q:
        like = f"%{q}%"
        num = q.upper().removeprefix("INC-")
        conds = [Incident.title.ilike(like), Incident.description.ilike(like)]
        if num.isdigit():
            conds.append(Incident.number == int(num))
        stmt = stmt.where(or_(*conds))
    for kind, val in (("host", host), ("user", user)):
        if val:
            stmt = stmt.where(
                Incident.id.in_(
                    select(IncidentEntity.incident_id).where(
                        IncidentEntity.tenant_id == principal.tenant_id,
                        IncidentEntity.kind == kind,
                        IncidentEntity.value == val,
                    )
                )
            )
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    if sort == "priority":
        stmt = stmt.order_by(
            Incident.status.in_(OPEN_STATUSES).desc(), Incident.risk_score.desc(), Incident.last_event_at.desc()
        )
    elif sort == "newest":
        stmt = stmt.order_by(Incident.created_at.desc())
    elif sort == "updated":
        stmt = stmt.order_by(Incident.updated_at.desc())
    else:
        stmt = stmt.order_by(Incident.risk_score.desc())
    rows = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return Page(items=[IncidentSummary.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.post("", response_model=IncidentDetail, status_code=201)
async def create_incident(
    body: IncidentCreate,
    request: Request,
    principal: Principal = Depends(require(Perm.INCIDENT_CREATE)),
    db: AsyncSession = Depends(get_db),
) -> IncidentDetail:
    await db.execute(select(func.pg_advisory_xact_lock(tenant_lock_key(principal.tenant_id))))
    alerts = (
        (await db.execute(select(Alert).where(Alert.tenant_id == principal.tenant_id, Alert.id.in_(body.alert_ids))))
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    inc = Incident(
        id=uuid.uuid4(),
        tenant_id=principal.tenant_id,
        number=await next_incident_number(db, principal.tenant_id),
        title=body.title,
        description=body.description,
        status="new",
        promoted=True,
        promoted_at=now,
        promotion_reason=f"created manually by {principal.email}",
        first_event_at=min((a.first_event_at for a in alerts), default=now),
        last_event_at=max((a.last_event_at for a in alerts), default=now),
        risk_breakdown=[],
        confidence_factors=[],
        mitre_techniques=[],
        tactics=[],
        source_types=[],
    )
    db.add(inc)
    await db.flush()
    previous = {a.incident_id for a in alerts if a.incident_id is not None}
    for a in alerts:
        a.incident_id = inc.id
    _activity(db, inc, "created", principal.email, "Incident created manually")
    await db.flush()
    if alerts:
        from sentinelx.correlation.engine import alert_entities, upsert_entities

        for a in alerts:
            await upsert_entities(db, principal.tenant_id, inc.id, a, alert_entities(a))
        await recompute_incident(db, principal.tenant_id, inc.id)
        inc.title = body.title
        await _refresh_after_move(db, principal, previous, inc)
    await audit(
        db,
        action="incident.create",
        resource_type="incident",
        resource_id=inc.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        source_ip=client_ip(request),
    )
    return IncidentDetail.model_validate(inc)


async def _refresh_after_move(db: AsyncSession, principal: Principal, sources: set[uuid.UUID], dest: Incident) -> None:
    """Alerts moved into ``dest``: the incidents they left must not keep stale counts, evidence or entities."""
    for old_id in sources:
        old = await db.get(Incident, old_id)
        if old is None:
            continue
        remaining = (
            await db.execute(select(func.count()).select_from(Alert).where(Alert.incident_id == old_id))
        ).scalar_one()
        await db.execute(
            IncidentEvidence.__table__.delete().where(
                IncidentEvidence.incident_id == old_id,
                IncidentEvidence.alert_id.notin_(select(Alert.id).where(Alert.incident_id == old_id)),
            )
        )
        if remaining:
            await recompute_incident(db, principal.tenant_id, old_id)
        else:
            old.alert_count = old.event_count = 0
            old.updated_at = datetime.now(UTC)
        _activity(db, old, "moved", principal.email, f"Alerts moved to INC-{dest.number}")


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> IncidentDetail:
    return IncidentDetail.model_validate(await _get(db, principal, incident_id))


@router.patch("/{incident_id}", response_model=IncidentDetail)
async def update_incident(
    incident_id: uuid.UUID,
    body: IncidentPatch,
    request: Request,
    principal: Principal = Depends(require(Perm.INCIDENT_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> IncidentDetail:
    inc = await _get(db, principal, incident_id)
    if inc.status == "merged":
        raise HTTPException(status.HTTP_409_CONFLICT, "This incident was merged into another one")
    changes: dict[str, Any] = {}
    now = datetime.now(UTC)
    # Resolving/closing and recording a verdict are analyst judgements (incident:close).
    if body.status in ("resolved", "closed") and body.status != inc.status and not principal.can(Perm.INCIDENT_CLOSE):
        raise await deny(request, principal, Perm.INCIDENT_CLOSE, f"set status {body.status}")
    if body.disposition and body.disposition != inc.disposition and not principal.can(Perm.INCIDENT_CLOSE):
        raise await deny(request, principal, Perm.INCIDENT_CLOSE, "record a disposition")
    if "assigned_to" in body.model_fields_set and body.assigned_to is not None:
        await _check_assignee(db, inc.tenant_id, body.assigned_to)
    if body.status and body.status != inc.status:
        if body.status == "closed" and not (body.disposition or inc.disposition):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Choose a disposition (true positive, false positive…) before closing",
            )
        reopening = inc.status in ("resolved", "closed") and body.status in OPEN_STATUSES
        changes["status"] = [inc.status, body.status]
        _activity(
            db,
            inc,
            "status",
            principal.email,
            f"{'Reopened' if reopening else 'Status changed'}: {inc.status} → {body.status}",
        )
        if inc.status == "new" and inc.acknowledged_at is None:
            inc.acknowledged_at = now
        if body.status in ("resolved", "closed") and inc.resolved_at is None:
            inc.resolved_at = now
        if body.status in OPEN_STATUSES:
            inc.resolved_at = None
        inc.status = body.status
    if body.disposition and body.disposition != inc.disposition:
        changes["disposition"] = [inc.disposition, body.disposition]
        _activity(db, inc, "disposition", principal.email, f"Disposition set to {body.disposition.replace('_', ' ')}")
        inc.disposition = body.disposition
    if "assigned_to" in body.model_fields_set:
        changes["assigned_to"] = [
            str(inc.assigned_to) if inc.assigned_to else None,
            str(body.assigned_to) if body.assigned_to else None,
        ]
        inc.assigned_to = body.assigned_to
        _activity(db, inc, "assignment", principal.email, "Assignee changed")
        if inc.acknowledged_at is None:
            inc.acknowledged_at = now
    if body.title and body.title != inc.title:
        changes["title"] = [inc.title, body.title]
        inc.title = body.title
    inc.updated_at = now
    await audit(
        db,
        action="incident.update",
        resource_type="incident",
        resource_id=inc.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details=changes,
        source_ip=client_ip(request),
    )
    return IncidentDetail.model_validate(inc)


@router.post("/{incident_id}/merge/{other_id}", response_model=IncidentDetail)
async def merge(
    incident_id: uuid.UUID,
    other_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Perm.INCIDENT_CREATE)),
    db: AsyncSession = Depends(get_db),
) -> IncidentDetail:
    target = await _get(db, principal, incident_id)
    other = await _get(db, principal, other_id)
    if target.id == other.id or "merged" in (target.status, other.status):
        raise HTTPException(status.HTTP_409_CONFLICT, "Pick two different incidents that are not already merged")
    await db.execute(select(func.pg_advisory_xact_lock(tenant_lock_key(principal.tenant_id))))
    await merge_incidents(db, principal.tenant_id, target.id, other_id, actor=principal.email)
    await db.flush()
    await recompute_incident(db, principal.tenant_id, target.id)
    await audit(
        db,
        action="incident.merge",
        resource_type="incident",
        resource_id=target.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"merged": str(other_id)},
        source_ip=client_ip(request),
    )
    return IncidentDetail.model_validate(target)


@router.get("/{incident_id}/alerts", response_model=list[AlertOut])
async def incident_alerts(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[AlertOut]:
    await _get(db, principal, incident_id)
    rows = (
        (
            await db.execute(
                select(Alert)
                .where(Alert.tenant_id == principal.tenant_id, Alert.incident_id == incident_id)
                .order_by(Alert.first_event_at)
            )
        )
        .scalars()
        .all()
    )
    return [AlertOut.model_validate(a) for a in rows]


def _timeline_entry(ev: IncidentEvidence, alert_titles: dict[uuid.UUID, str]) -> dict[str, Any]:
    s = ev.snapshot
    return {
        "event_id": str(ev.event_id),
        "timestamp": ev.timestamp,
        "summary": s.get("summary"),
        "source_type": s.get("source_type"),
        "event_type": s.get("event_type"),
        "outcome": s.get("outcome"),
        "hostname": s.get("hostname"),
        "username": s.get("username"),
        "src_ip": s.get("src_ip"),
        "dest_ip": s.get("dest_ip"),
        "dest_port": s.get("dest_port"),
        "domain": s.get("domain"),
        "process_name": s.get("process_name"),
        "process_command_line": s.get("process_command_line"),
        "severity": s.get("severity"),
        "alert_id": str(ev.alert_id) if ev.alert_id else None,
        "alert_title": alert_titles.get(ev.alert_id) if ev.alert_id else None,
    }


@router.get("/{incident_id}/timeline")
async def timeline(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    collapse: bool = True,
) -> dict[str, Any]:
    """Chronological evidence. With ``collapse`` consecutive repeats of the same behaviour are grouped
    ("Failed login ×43") - every group still links to all its source events."""
    inc = await _get(db, principal, incident_id)
    titles = dict((await db.execute(select(Alert.id, Alert.title).where(Alert.incident_id == inc.id))).all())
    total = (
        await db.execute(
            select(func.count()).select_from(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id)
        )
    ).scalar_one()
    rows = (
        (
            await db.execute(
                select(IncidentEvidence)
                .where(IncidentEvidence.incident_id == inc.id)
                .order_by(IncidentEvidence.timestamp)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    entries = [_timeline_entry(r, titles) for r in rows]
    milestones: list[dict[str, Any]] = []
    acts = (
        (
            await db.execute(
                select(IncidentActivity)
                .where(IncidentActivity.incident_id == inc.id, IncidentActivity.kind.in_(["created", "promoted"]))
                .order_by(IncidentActivity.created_at)
            )
        )
        .scalars()
        .all()
    )
    for a in acts:
        milestones.append({"timestamp": a.created_at, "kind": a.kind, "message": a.message})
    alert_marks = (
        await db.execute(
            select(Alert.id, Alert.title, Alert.first_event_at, Alert.last_event_at, Alert.severity, Alert.source)
            .where(Alert.incident_id == inc.id)
            .order_by(Alert.last_event_at)
        )
    ).all()
    detections = [
        {"alert_id": str(a), "title": t, "timestamp": last, "first_event_at": first, "severity": sev, "source": src}
        for a, t, first, last, sev, src in alert_marks
    ]
    if collapse:
        grouped: list[dict[str, Any]] = []
        for e in entries:
            prev = grouped[-1] if grouped else None
            key = (e["summary"], e["alert_id"])
            if prev and (prev["summary"], prev["alert_id"]) == key:
                prev["count"] += 1
                prev["event_ids"].append(e["event_id"])
                prev["last_timestamp"] = e["timestamp"]
            else:
                grouped.append({**e, "count": 1, "event_ids": [e["event_id"]], "last_timestamp": e["timestamp"]})
        entries = grouped
    return {"total_events": total, "entries": entries, "detections": detections, "milestones": milestones}


@router.get("/{incident_id}/evidence/{event_id}")
async def evidence_event(
    incident_id: uuid.UUID,
    event_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    await _get(db, principal, incident_id)
    ev = (
        await db.execute(
            select(IncidentEvidence).where(
                IncidentEvidence.incident_id == incident_id, IncidentEvidence.event_id == event_id
            )
        )
    ).scalar_one_or_none()
    if ev is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event is not part of this incident's evidence")
    return {
        "event_id": str(ev.event_id),
        "alert_id": str(ev.alert_id) if ev.alert_id else None,
        "timestamp": ev.timestamp,
        "snapshot": ev.snapshot,
    }


@router.get("/{incident_id}/context")
async def incident_context(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Entities with asset / identity context, threat intel, ML findings and the evidence graph."""
    inc = await _get(db, principal, incident_id)
    ents = (await db.execute(select(IncidentEntity).where(IncidentEntity.incident_id == inc.id))).scalars().all()
    hosts = [e.value for e in ents if e.kind == "host"]
    users = [e.value for e in ents if e.kind == "user"]
    values = [e.value for e in ents if e.kind in ("ip", "domain", "hash")]
    assets = (
        (await db.execute(select(Asset).where(Asset.tenant_id == inc.tenant_id, Asset.hostname.in_(hosts))))
        .scalars()
        .all()
        if hosts
        else []
    )
    idents = (
        (await db.execute(select(Identity).where(Identity.tenant_id == inc.tenant_id, Identity.username.in_(users))))
        .scalars()
        .all()
        if users
        else []
    )
    ti = (
        (
            await db.execute(
                select(ThreatIntelResult)
                .where(ThreatIntelResult.tenant_id == inc.tenant_id, ThreatIntelResult.value.in_(values))
                .order_by(ThreatIntelResult.confidence.desc())
            )
        )
        .scalars()
        .all()
        if values
        else []
    )
    ml = (
        (
            await db.execute(
                select(MlPrediction)
                .where(MlPrediction.tenant_id == inc.tenant_id, MlPrediction.entity_id.in_(hosts))
                .order_by(MlPrediction.anomaly_score.desc())
                .limit(6)
            )
        )
        .scalars()
        .all()
        if hosts
        else []
    )
    ml = [m for m in ml if m.window_start >= inc.first_event_at - timedelta(hours=3)]
    alerts = (await db.execute(select(Alert).where(Alert.incident_id == inc.id))).scalars().all()

    # evidence graph: entities + detections, edges where a detection involves an entity
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    asset_by = {a.hostname: a for a in assets}
    for e in ents:
        node = {"id": f"{e.kind}:{e.value}", "kind": e.kind, "label": e.value, "alerts": e.alert_count}
        if e.kind == "host" and e.value in asset_by:
            node["criticality"] = asset_by[e.value].criticality
        if any(r.value == e.value and r.verdict in ("malicious", "suspicious") for r in ti):
            node["threat"] = True
        nodes.append(node)
    for a in alerts:
        aid = f"alert:{a.id}"
        nodes.append({"id": aid, "kind": "alert", "label": a.title, "severity": a.severity, "source": a.source})
        for kind, val in (
            ("host", a.hostname),
            ("user", a.username),
            ("ip", a.src_ip),
            ("ip", a.dest_ip),
            ("domain", a.domain),
            ("hash", a.file_hash),
        ):
            if val:
                v = val.lower() if kind in ("user", "domain", "hash") else val
                if any(n["id"] == f"{kind}:{v}" for n in nodes):
                    edges.append({"source": aid, "target": f"{kind}:{v}"})
    catalog = get_catalog()
    return {
        "entities": [
            {
                "kind": e.kind,
                "value": e.value,
                "alert_count": e.alert_count,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            }
            for e in ents
        ],
        "assets": [
            {
                "hostname": a.hostname,
                "os": a.os,
                "criticality": a.criticality,
                "owner": a.owner,
                "environment": a.environment,
                "tags": a.tags,
                "ip_addresses": a.ip_addresses,
                "risk_score": a.risk_score,
            }
            for a in assets
        ],
        "identities": [
            {
                "username": i.username,
                "email": i.email,
                "department": i.department,
                "privileged": i.privileged,
                "risk_score": i.risk_score,
            }
            for i in idents
        ],
        "threat_intel": [TiResultOut.model_validate(r).model_dump() for r in ti],
        "ml": [
            {
                "host": m.entity_id,
                "window_start": m.window_start,
                "anomaly_score": m.anomaly_score,
                "is_anomaly": m.is_anomaly,
                "top_contributors": m.top_contributors,
            }
            for m in ml
        ],
        "mitre": [
            {
                "id": t,
                "name": catalog.get(t).name if catalog.get(t) else t,
                "tactics": list(catalog.get(t).tactics) if catalog.get(t) else [],
                "url": catalog.get(t).url if catalog.get(t) else None,
                "alerts": [a.title for a in alerts if t in (a.mitre_techniques or [])],
            }
            for t in inc.mitre_techniques
        ],
        "graph": {"nodes": nodes, "edges": edges},
    }


@router.get("/{incident_id}/activity")
async def activity(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    await _get(db, principal, incident_id)
    acts = (
        (
            await db.execute(
                select(IncidentActivity)
                .where(IncidentActivity.incident_id == incident_id)
                .order_by(IncidentActivity.created_at.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    notes = (await db.execute(select(AnalystNote).where(AnalystNote.incident_id == incident_id))).scalars().all()
    out = [
        {
            "id": str(a.id),
            "kind": a.kind,
            "actor": a.actor,
            "message": a.message,
            "data": a.data,
            "created_at": a.created_at,
        }
        for a in acts
    ]
    out += [
        {
            "id": str(n.id),
            "kind": "note",
            "actor": n.author_name,
            "message": n.body,
            "data": {},
            "created_at": n.created_at,
        }
        for n in notes
    ]
    return sorted(out, key=lambda x: x["created_at"], reverse=True)


@router.post("/{incident_id}/notes", status_code=201)
async def add_note(
    incident_id: uuid.UUID,
    body: NoteIn,
    request: Request,
    principal: Principal = Depends(require(Perm.INCIDENT_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    inc = await _get(db, principal, incident_id)
    note = AnalystNote(
        id=uuid.uuid4(),
        tenant_id=inc.tenant_id,
        incident_id=inc.id,
        author_id=principal.user_id,
        author_name=principal.display_name,
        body=body.body,
    )
    db.add(note)
    if inc.acknowledged_at is None:
        inc.acknowledged_at = datetime.now(UTC)
    await audit(
        db,
        action="incident.note",
        resource_type="incident",
        resource_id=inc.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=inc.tenant_id,
        source_ip=client_ip(request),
    )
    return {"id": str(note.id)}


@router.get("/{incident_id}/responses", response_model=list[ResponseActionOut])
async def list_responses(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[ResponseActionOut]:
    await _get(db, principal, incident_id)
    rows = (
        (
            await db.execute(
                select(ResponseAction)
                .where(ResponseAction.incident_id == incident_id)
                .order_by(ResponseAction.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [ResponseActionOut.model_validate(r) for r in rows]


@router.post("/{incident_id}/responses", response_model=ResponseActionOut, status_code=201)
async def create_response(
    incident_id: uuid.UUID,
    body: ResponseActionIn,
    request: Request,
    principal: Principal = Depends(require(Perm.RESPONSE_EXECUTE)),
    db: AsyncSession = Depends(get_db),
) -> ResponseActionOut:
    """Safe, auditable actions only. No remote command execution exists in SentinelX."""
    inc = await _get(db, principal, incident_id)
    payload = dict(body.payload)
    now = datetime.now(UTC)
    if body.kind == "watchlist_ioc":
        value = str(payload.get("value", "")).strip()
        itype = classify_indicator(value)
        if not itype:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Not a valid IP, domain, hash or URL")
        value = normalize_indicator(itype, value)
        await import_indicators(
            db,
            inc.tenant_id,
            [
                {
                    "type": itype,
                    "value": value,
                    "source": "analyst-watchlist",
                    "confidence": 0.8,
                    "verdict": "malicious",
                    "tags": ["watchlist", f"INC-{inc.number}"],
                    "description": f"Added from INC-{inc.number} by {principal.email}",
                    "reference": None,
                }
            ],
        )
        payload = {"type": itype, "value": value}
    elif body.kind == "task":
        payload = {
            "assignee": payload.get("assignee"),
            "done": False,
            "details": str(payload.get("details", ""))[:2000],
        }
    action = ResponseAction(
        id=uuid.uuid4(),
        tenant_id=inc.tenant_id,
        incident_id=inc.id,
        kind=body.kind,
        status="open" if body.kind == "task" else "completed",
        title=body.title,
        payload=payload,
        requested_by=principal.email,
        completed_at=None if body.kind == "task" else now,
    )
    db.add(action)
    _activity(db, inc, "response", principal.email, f"Response action: {body.title}", action_kind=body.kind)
    await audit(
        db,
        action=f"response.{body.kind}",
        resource_type="incident",
        resource_id=inc.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=inc.tenant_id,
        details={"title": body.title, "payload": payload},
        source_ip=client_ip(request),
    )
    await db.flush()
    return ResponseActionOut.model_validate(action)


@router.patch("/{incident_id}/responses/{action_id}", response_model=ResponseActionOut)
async def complete_task(
    incident_id: uuid.UUID,
    action_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Perm.INCIDENT_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> ResponseActionOut:
    await _get(db, principal, incident_id)
    act = await db.get(ResponseAction, action_id)
    if act is None or act.incident_id != incident_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")
    act.status = "completed" if act.status != "completed" else "open"
    act.completed_at = datetime.now(UTC) if act.status == "completed" else None
    await audit(
        db,
        action="response.task_toggle",
        resource_type="response_action",
        resource_id=act.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=principal.tenant_id,
        details={"status": act.status},
        source_ip=client_ip(request),
    )
    return ResponseActionOut.model_validate(act)


@router.post("/{incident_id}/investigate", response_model=AiInvestigationOut, status_code=202)
async def investigate(
    incident_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Perm.AI_INVESTIGATE)),
    db: AsyncSession = Depends(get_db),
) -> AiInvestigationOut:
    inc = await _get(db, principal, incident_id)
    running = (
        (
            await db.execute(
                select(AiInvestigation).where(
                    AiInvestigation.incident_id == inc.id, AiInvestigation.status.in_(["queued", "running"])
                )
            )
        )
        .scalars()
        .first()
    )
    if running is not None:
        return AiInvestigationOut.model_validate(running)
    from sentinelx.ai.prompt import PROMPT_VERSION

    inv = AiInvestigation(
        id=uuid.uuid4(),
        tenant_id=inc.tenant_id,
        incident_id=inc.id,
        status="queued",
        model=await model_for_tenant(inc.tenant_id),
        prompt_version=PROMPT_VERSION,
        requested_by=principal.email,
        context_stats={},
        validation_errors=[],
        injection_flags=[],
        attempts=0,
    )
    db.add(inv)
    await db.flush()
    await enqueue(db, "ai_investigate", {"investigation_id": str(inv.id)}, tenant_id=inc.tenant_id, max_attempts=1)
    await audit(
        db,
        action="ai.investigate",
        resource_type="incident",
        resource_id=inc.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=inc.tenant_id,
        details={"model": inv.model},
        source_ip=client_ip(request),
    )
    return AiInvestigationOut.model_validate(inv)


@router.get("/{incident_id}/investigations", response_model=list[AiInvestigationOut])
async def investigations(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.INCIDENT_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[AiInvestigationOut]:
    await _get(db, principal, incident_id)
    rows = (
        (
            await db.execute(
                select(AiInvestigation)
                .where(AiInvestigation.incident_id == incident_id)
                .order_by(AiInvestigation.created_at.desc())
                .limit(20)
            )
        )
        .scalars()
        .all()
    )
    return [AiInvestigationOut.model_validate(r) for r in rows]


@router.get("/{incident_id}/threat-intel", response_model=list[TiResultOut])
async def incident_ti(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require(Perm.THREATINTEL_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[TiResultOut]:
    await _get(db, principal, incident_id)
    values = (
        (await db.execute(select(IncidentEntity.value).where(IncidentEntity.incident_id == incident_id)))
        .scalars()
        .all()
    )
    rows = (
        (
            await db.execute(
                select(ThreatIntelResult).where(
                    ThreatIntelResult.tenant_id == principal.tenant_id, ThreatIntelResult.value.in_(values)
                )
            )
        )
        .scalars()
        .all()
    )
    return [TiResultOut.model_validate(r) for r in rows]


@router.get("/{incident_id}/report")
async def report(
    incident_id: uuid.UUID,
    request: Request,
    fmt: str = Query("json", pattern="^(json|html)$"),
    principal: Principal = Depends(require(Perm.REPORT_GENERATE)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    inc = await _get(db, principal, incident_id)
    data = await build_report(db, inc)
    await audit(
        db,
        action="report.generate",
        resource_type="incident",
        resource_id=inc.id,
        actor=principal.email,
        actor_id=principal.user_id,
        tenant_id=inc.tenant_id,
        details={"format": fmt},
        source_ip=client_ip(request),
    )
    if fmt == "html":
        return HTMLResponse(
            render_html(data), headers={"Content-Disposition": f'attachment; filename="INC-{inc.number}-report.html"'}
        )
    return data
