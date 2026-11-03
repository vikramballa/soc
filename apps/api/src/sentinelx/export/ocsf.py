"""Map SentinelX alerts and incidents to OCSF findings (Detection Finding 2004, Incident Finding 2005).

OCSF is the vendor-neutral event schema most SIEM, data-lake and SOAR products can ingest natively. This is
an export view only: the canonical event model (ADR-004) stays the internal source of truth, see ADR-013.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sentinelx import __version__
from sentinelx.mitre.catalog import MitreCatalog
from sentinelx.persistence.models import Alert, Incident

OCSF_VERSION = "1.3.0"
FINDINGS_CATEGORY = 2
DETECTION_FINDING = 2004
INCIDENT_FINDING = 2005
ACTIVITY_CREATE = 1

PRODUCT = {"name": "SentinelX", "vendor_name": "SentinelX project", "version": __version__}

# OCSF severity_id: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical
_SEVERITY_NAMES = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
_INCIDENT_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# Detection Finding status_id: 1 New, 2 In Progress, 3 Suppressed, 4 Resolved
_ALERT_STATUS = {"open": (1, "New"), "acknowledged": (2, "In Progress"), "closed": (4, "Resolved")}
# Incident Finding status_id: 1 New, 2 In Progress, 3 On Hold, 4 Resolved, 5 Closed
_INCIDENT_STATUS = {
    "new": (1, "New"),
    "triaged": (2, "In Progress"),
    "investigating": (2, "In Progress"),
    "contained": (2, "In Progress"),
    "resolved": (4, "Resolved"),
    "closed": (5, "Closed"),
}
# verdict_id: 1 False Positive, 2 True Positive, 5 Benign, 7 Insufficient Data, 10 Duplicate
_VERDICT = {
    "false_positive": (1, "False Positive"),
    "true_positive": (2, "True Positive"),
    "benign_true_positive": (5, "Benign"),
    "undetermined": (7, "Insufficient Data"),
}
# analytic.type_id: 1 Rule, 2 Behavioral, 3 Statistical, 4 Learning (ML/DL)
_ANALYTIC_TYPE = {
    "sigma": (1, "Rule"),
    "correlation": (1, "Rule"),
    "source": (1, "Rule"),
    "ti": (1, "Rule"),
    "builtin": (2, "Behavioral"),
    "ml": (4, "Learning (ML/DL)"),
}
# observable type_id: 1 Hostname, 2 IP Address, 4 User Name, 8 Hash, 9 Process Name
_OBSERVABLES = (
    ("hostname", 1, "Hostname"),
    ("src_ip", 2, "IP Address"),
    ("dest_ip", 2, "IP Address"),
    ("username", 4, "User Name"),
    ("domain", 1, "Hostname"),
    ("file_hash", 8, "Hash"),
    ("process_name", 9, "Process Name"),
)


def _ms(dt: datetime | None) -> int | None:
    return int(dt.timestamp() * 1000) if dt else None


def severity_id_from_score(score: int) -> int:
    """SentinelX alert severities are 0-100 (Sigma levels map to 10/30/50/75/90)."""
    if score >= 90:
        return 5
    if score >= 70:
        return 4
    if score >= 45:
        return 3
    if score >= 20:
        return 2
    return 1


def attacks(techniques: list[str], catalog: MitreCatalog) -> list[dict[str, Any]]:
    """One OCSF ``attack`` object per (technique, tactic); unknown ids are dropped, never invented."""
    out: list[dict[str, Any]] = []
    for tid in sorted(set(techniques)):
        t = catalog.get(tid)
        if t is None:
            continue
        technique: dict[str, Any] = {"uid": t.id, "name": t.name, "src_url": t.url}
        attack: dict[str, Any] = {"version": catalog.version}
        if t.parent_id and (parent := catalog.get(t.parent_id)) is not None:
            attack["technique"] = {"uid": parent.id, "name": parent.name, "src_url": parent.url}
            attack["sub_technique"] = technique
        else:
            attack["technique"] = technique
        tactics = [catalog.tactic_by_short[s] for s in t.tactics if s in catalog.tactic_by_short]
        if not tactics:
            out.append(attack)
        for tac in tactics:
            out.append({**attack, "tactic": {"uid": tac.id, "name": tac.name, "src_url": tac.url}})
    return out


def _metadata(uid: str, tenant_id: Any, labels: list[str]) -> dict[str, Any]:
    return {
        "version": OCSF_VERSION,
        "product": PRODUCT,
        "uid": uid,
        "tenant_uid": str(tenant_id),
        "labels": sorted(set(labels)),
    }


def _observables(alert: Alert) -> list[dict[str, Any]]:
    out = []
    for attr, type_id, type_name in _OBSERVABLES:
        value = getattr(alert, attr)
        if value:
            out.append({"name": attr, "type_id": type_id, "type": type_name, "value": str(value)})
    return out


def finding_info(alert: Alert, catalog: MitreCatalog) -> dict[str, Any]:
    analytic_type = _ANALYTIC_TYPE.get(alert.source, (99, "Other"))
    return {
        "uid": str(alert.id),
        "title": alert.title,
        "desc": alert.description or None,
        "types": [alert.source],
        "created_time": _ms(alert.created_at),
        "first_seen_time": _ms(alert.first_event_at),
        "last_seen_time": _ms(alert.last_event_at),
        "analytic": {
            "uid": alert.rule_uid,
            "name": alert.title,
            "type_id": analytic_type[0],
            "type": analytic_type[1],
        },
        "attacks": attacks(alert.mitre_techniques or [], catalog),
    }


def detection_finding(alert: Alert, catalog: MitreCatalog) -> dict[str, Any]:
    sev = severity_id_from_score(alert.severity)
    status_id, status_name = _ALERT_STATUS.get(alert.status, (99, "Other"))
    return {
        "category_uid": FINDINGS_CATEGORY,
        "category_name": "Findings",
        "class_uid": DETECTION_FINDING,
        "class_name": "Detection Finding",
        "activity_id": ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": DETECTION_FINDING * 100 + ACTIVITY_CREATE,
        "type_name": "Detection Finding: Create",
        "time": _ms(alert.last_event_at),
        "severity_id": sev,
        "severity": _SEVERITY_NAMES[sev],
        "status_id": status_id,
        "status": status_name,
        "message": alert.title,
        "finding_info": finding_info(alert, catalog),
        "observables": _observables(alert),
        "count": alert.event_count,
        "metadata": _metadata(str(alert.id), alert.tenant_id, alert.source_types or []),
        "unmapped": {
            "sentinelx": {
                "severity_score": alert.severity,
                "level": alert.level,
                "incident_id": str(alert.incident_id) if alert.incident_id else None,
            }
        },
    }


def incident_finding(inc: Incident, alerts: list[Alert], catalog: MitreCatalog, base_url: str) -> dict[str, Any]:
    sev = _INCIDENT_SEVERITY.get(inc.severity, 0)
    status_id, status_name = _INCIDENT_STATUS.get(inc.status, (99, "Other"))
    out: dict[str, Any] = {
        "category_uid": FINDINGS_CATEGORY,
        "category_name": "Findings",
        "class_uid": INCIDENT_FINDING,
        "class_name": "Incident Finding",
        "activity_id": ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": INCIDENT_FINDING * 100 + ACTIVITY_CREATE,
        "type_name": "Incident Finding: Create",
        "time": _ms(inc.last_event_at),
        "start_time": _ms(inc.first_event_at),
        "end_time": _ms(inc.last_event_at),
        "severity_id": sev,
        "severity": _SEVERITY_NAMES[sev],
        "status_id": status_id,
        "status": status_name,
        "priority_id": max(1, sev - 1) if sev else 0,
        "message": f"INC-{inc.number}: {inc.title}",
        "desc": inc.description or None,
        "src_url": f"{base_url.rstrip('/')}/incidents/{inc.id}",
        "finding_info_list": [finding_info(a, catalog) for a in alerts],
        "metadata": _metadata(str(inc.id), inc.tenant_id, inc.source_types or []),
        "unmapped": {
            "sentinelx": {
                "number": inc.number,
                "category": inc.category,
                "risk_score": inc.risk_score,
                "risk_breakdown": inc.risk_breakdown,
                "confidence": inc.confidence,
                "promotion_reason": inc.promotion_reason,
                "mitre_techniques": inc.mitre_techniques,
                "alert_count": inc.alert_count,
                "event_count": inc.event_count,
            }
        },
    }
    if inc.disposition in _VERDICT:
        out["verdict_id"], out["verdict"] = _VERDICT[inc.disposition]
    if inc.assigned_to:
        out["assignee"] = {"uid": str(inc.assigned_to)}
    return out
