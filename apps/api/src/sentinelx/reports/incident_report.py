"""Incident report. Clearly separates observed evidence, automated inference,
AI-generated interpretation and analyst conclusions."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import (
    AiInvestigation,
    Alert,
    AnalystNote,
    Asset,
    Identity,
    Incident,
    IncidentEntity,
    IncidentEvidence,
    MlPrediction,
    ResponseAction,
    ThreatIntelResult,
)


async def build_report(db: AsyncSession, inc: Incident) -> dict[str, Any]:
    catalog = get_catalog()
    alerts = (
        (await db.execute(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_event_at)))
        .scalars()
        .all()
    )
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
                select(ThreatIntelResult).where(
                    ThreatIntelResult.tenant_id == inc.tenant_id, ThreatIntelResult.value.in_(values)
                )
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
                select(MlPrediction).where(
                    MlPrediction.tenant_id == inc.tenant_id,
                    MlPrediction.entity_id.in_(hosts),
                    MlPrediction.is_anomaly.is_(True),
                )
            )
        )
        .scalars()
        .all()
        if hosts
        else []
    )
    evidence = (
        (
            await db.execute(
                select(IncidentEvidence)
                .where(IncidentEvidence.incident_id == inc.id)
                .order_by(IncidentEvidence.timestamp)
                .limit(300)
            )
        )
        .scalars()
        .all()
    )
    ai = (
        await db.execute(
            select(AiInvestigation)
            .where(AiInvestigation.incident_id == inc.id, AiInvestigation.status == "completed")
            .order_by(AiInvestigation.completed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    notes = (
        (
            await db.execute(
                select(AnalystNote).where(AnalystNote.incident_id == inc.id).order_by(AnalystNote.created_at)
            )
        )
        .scalars()
        .all()
    )
    actions = (
        (
            await db.execute(
                select(ResponseAction).where(ResponseAction.incident_id == inc.id).order_by(ResponseAction.created_at)
            )
        )
        .scalars()
        .all()
    )
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "incident": {
            "id": f"INC-{inc.number}",
            "title": inc.title,
            "status": inc.status,
            "disposition": inc.disposition,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "confidence": inc.confidence,
            "first_event": inc.first_event_at.isoformat(),
            "last_event": inc.last_event_at.isoformat(),
            "created": inc.created_at.isoformat(),
            "resolved": inc.resolved_at.isoformat() if inc.resolved_at else None,
        },
        "executive_summary": inc.description,
        "observed_evidence": {
            "detection_sources": inc.source_types,
            "affected_assets": [
                {"hostname": a.hostname, "criticality": a.criticality, "owner": a.owner, "os": a.os} for a in assets
            ]
            or [{"hostname": h} for h in hosts],
            "affected_users": [{"username": i.username, "privileged": i.privileged} for i in idents]
            or [{"username": u} for u in users],
            "timeline": [
                {
                    "time": e.timestamp.isoformat(),
                    "event_id": str(e.event_id),
                    "summary": e.snapshot.get("summary"),
                    "source": e.snapshot.get("source_type"),
                }
                for e in evidence
            ],
            "evidence_event_count": inc.event_count,
        },
        "automated_inference": {
            "detections": [
                {
                    "title": a.title,
                    "type": a.source,
                    "severity": a.severity,
                    "events": a.event_count,
                    "techniques": a.mitre_techniques,
                }
                for a in alerts
            ],
            "risk_breakdown": inc.risk_breakdown,
            "confidence_factors": inc.confidence_factors,
            "mitre_attack": [
                {
                    "id": t,
                    "name": tech.name if tech else t,
                    "tactics": list(tech.tactics) if tech else [],
                }
                for t in inc.mitre_techniques
                for tech in [catalog.get(t)]
            ],
            "threat_intelligence": [
                {"indicator": r.value, "provider": r.provider, "verdict": r.verdict, "confidence": r.confidence}
                for r in ti
            ],
            "ml_findings": [
                {
                    "host": m.entity_id,
                    "window": m.window_start.isoformat(),
                    "anomaly_score": round(m.anomaly_score, 3),
                    "top_contributors": m.top_contributors,
                }
                for m in ml
            ],
        },
        "ai_interpretation": (
            {
                "model": ai.model,
                "prompt_version": ai.prompt_version,
                "generated_at": ai.completed_at.isoformat() if ai.completed_at else None,
                "summary": (ai.result or {}).get("summary"),
                "verdict": (ai.result or {}).get("verdict"),
                "recommended_steps": (ai.result or {}).get("recommended_investigation_steps", []),
                "benign_explanations": (ai.result or {}).get("possible_benign_explanations", []),
            }
            if ai
            else None
        ),
        "analyst_conclusion": {
            "notes": [{"author": n.author_name, "at": n.created_at.isoformat(), "text": n.body} for n in notes],
            "actions_taken": [
                {
                    "title": a.title,
                    "kind": a.kind,
                    "status": a.status,
                    "by": a.requested_by,
                    "at": a.created_at.isoformat(),
                }
                for a in actions
            ],
            "resolution": inc.disposition,
        },
    }


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def render_html(r: dict[str, Any]) -> str:
    inc = r["incident"]
    obs, auto, ai, an = (
        r["observed_evidence"],
        r["automated_inference"],
        r["ai_interpretation"],
        r["analyst_conclusion"],
    )

    def rows(items: list[dict[str, Any]], cols: list[str]) -> str:
        if not items:
            return "<p class='muted'>None.</p>"
        head = "".join(f"<th>{_e(c.replace('_', ' ').title())}</th>" for c in cols)
        body = "".join("<tr>" + "".join(f"<td>{_e(i.get(c))}</td>" for c in cols) + "</tr>" for i in items)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    risk_rows = [
        {"factor": c["label"], "points": f"{c['value']:g} / {c['max']:g}", "why": c["reason"]}
        for c in auto["risk_breakdown"]
    ]
    ai_html = "<p class='muted'>No validated AI investigation was run for this incident.</p>"
    if ai:
        steps = "".join(f"<li>{_e(s)}</li>" for s in ai.get("recommended_steps") or [])
        benign = "".join(f"<li>{_e(s)}</li>" for s in ai.get("benign_explanations") or [])
        ai_html = (
            f"<p class='ai-label'>AI-generated interpretation · {_e(ai['model'])} · {_e(ai['prompt_version'])}"
            f" — verify against the evidence above.</p><p>{_e(ai.get('summary'))}</p>"
            f"<h4>Suggested next steps</h4><ol>{steps}</ol><h4>Possible benign explanations</h4><ul>{benign}</ul>"
        )
    notes = (
        "".join(
            f"<blockquote><b>{_e(n['author'])}</b> · {_e(n['at'][:16])}<br>{_e(n['text'])}</blockquote>"
            for n in an["notes"]
        )
        or "<p class='muted'>No analyst notes.</p>"
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{_e(inc["id"])} — Incident report</title>
<style>
body{{font:14px/1.5 -apple-system,Segoe UI,Inter,sans-serif;color:#1c2330;max-width:960px;margin:32px auto;padding:0 20px}}
h1{{font-size:22px;margin:0}} h2{{font-size:16px;margin-top:32px;border-bottom:1px solid #e3e7ee;padding-bottom:6px}}
h4{{margin:16px 0 4px}} table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #eef1f5;vertical-align:top}} th{{color:#5b6576;font-weight:600}}
.meta{{color:#5b6576}} .muted{{color:#8a93a3}} .tag{{display:inline-block;padding:2px 8px;border-radius:6px;background:#eef1f5;margin-right:6px}}
.section-label{{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#5b6576}}
.ai-label{{background:#f3f0ff;border:1px solid #ddd5ff;padding:8px 10px;border-radius:8px;color:#4b3aa6}}
blockquote{{margin:8px 0;padding:8px 12px;background:#f7f8fa;border-left:3px solid #c9d1dd}}
@media print{{body{{margin:0}}}}
</style></head><body>
<p class="section-label">SentinelX incident report · generated {_e(r["generated_at"][:19])} UTC</p>
<h1>{_e(inc["id"])}: {_e(inc["title"])}</h1>
<p class="meta"><span class="tag">Severity: {_e(inc["severity"])}</span><span class="tag">Risk {_e(inc["risk_score"])}/100</span>
<span class="tag">Confidence {_e(round(inc["confidence"] * 100))}%</span><span class="tag">Status: {_e(inc["status"])}</span>
<span class="tag">Disposition: {_e(inc["disposition"] or "not set")}</span></p>
<h2>Executive summary</h2><p>{_e(r["executive_summary"])}</p>
<h2>1 · Observed evidence</h2>
<p>Detection sources: {_e(", ".join(obs["detection_sources"]))} · {_e(obs["evidence_event_count"])} evidence events</p>
<h4>Affected assets</h4>{rows(obs["affected_assets"], ["hostname", "criticality", "owner", "os"])}
<h4>Affected users</h4>{rows(obs["affected_users"], ["username", "privileged"])}
<h4>Timeline</h4>{rows(obs["timeline"][:150], ["time", "source", "summary", "event_id"])}
<h2>2 · Automated inference (deterministic)</h2>
<h4>Detections</h4>{rows(auto["detections"], ["title", "type", "severity", "events"])}
<h4>Risk score breakdown</h4>{rows(risk_rows, ["factor", "points", "why"])}
<h4>MITRE ATT&amp;CK</h4>{rows(auto["mitre_attack"], ["id", "name"])}
<h4>Threat intelligence</h4>{rows(auto["threat_intelligence"], ["indicator", "provider", "verdict", "confidence"])}
<h4>Behavioral (ML) findings</h4>{rows(auto["ml_findings"], ["host", "window", "anomaly_score"])}
<h2>3 · AI-generated interpretation</h2>{ai_html}
<h2>4 · Analyst conclusion</h2>{notes}
<h4>Actions taken</h4>{rows(an["actions_taken"], ["title", "kind", "status", "by", "at"])}
<p><b>Resolution:</b> {_e(an["resolution"] or "Not yet resolved")}</p>
<p class="muted">ATT&amp;CK® is a registered trademark of The MITRE Corporation.</p>
</body></html>"""
