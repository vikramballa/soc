"""Transparent incident risk scoring.

The score is a sum of capped, named contributors, clipped to 0-100. Each contributor records its
value, cap and the reason, so the UI can always show *why* a score is what it is. Weights are
SentinelX product decisions (documented in docs/architecture/risk-model.md), not industry standards.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any

# ATT&CK tactic "stage" weights: later kill-chain stages carry more risk.
TACTIC_WEIGHTS: dict[str, float] = {
    "impact": 10,
    "exfiltration": 10,
    "command-and-control": 8,
    "credential-access": 8,
    "lateral-movement": 8,
    "privilege-escalation": 7,
    "defense-impairment": 7,
    "persistence": 6,
    "execution": 6,
    "stealth": 5,
    "initial-access": 6,
    "collection": 6,
    "discovery": 4,
    "reconnaissance": 3,
    "resource-development": 2,
}

CRITICALITY_POINTS = {1: 0.0, 2: 2.5, 3: 5.0, 4: 7.5, 5: 10.0}

BANDS = [(25, "informational"), (50, "low"), (75, "medium"), (90, "high"), (100, "critical")]


@dataclass
class Contributor:
    key: str
    label: str
    value: float
    max: float
    reason: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class RiskInputs:
    max_alert_severity: int = 0
    alert_count: int = 0
    event_count: int = 0
    distinct_rules: int = 0
    distinct_sources: int = 0
    max_asset_criticality: int | None = None
    critical_assets: list[str] = field(default_factory=list)
    privileged_users: list[str] = field(default_factory=list)
    new_source_logon: bool = False
    ti_matches: list[dict[str, Any]] = field(default_factory=list)  # {value, verdict, confidence, provider}
    ml_max_score: float = 0.0
    ml_hosts: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    top_alert_title: str = ""


@dataclass
class RiskResult:
    score: int
    severity: str
    contributors: list[Contributor]

    def breakdown(self) -> list[dict[str, Any]]:
        return [asdict(c) for c in self.contributors]


def band(score: int) -> str:
    for upper, name in BANDS:
        if score <= upper:
            return name
    return "critical"


def score_incident(i: RiskInputs) -> RiskResult:
    c: list[Contributor] = []

    sev = round(0.30 * max(0, min(100, i.max_alert_severity)), 1)
    c.append(
        Contributor(
            "detection_severity",
            "Detection severity",
            sev,
            30,
            f"Highest-severity detection: {i.top_alert_title or 'n/a'} ({i.max_alert_severity}/100)",
        )
    )

    vol = round(min(10.0, 2.0 * math.log2(1 + max(i.event_count, 0))), 1)
    c.append(
        Contributor(
            "event_volume", "Event volume", vol, 10, f"{i.event_count} evidence events across {i.alert_count} alerts"
        )
    )

    crit = CRITICALITY_POINTS.get(i.max_asset_criticality or 2, 2.5) if i.max_asset_criticality else 0.0
    c.append(
        Contributor(
            "asset_criticality",
            "Asset criticality",
            crit,
            10,
            f"Most critical affected asset: level {i.max_asset_criticality}/5"
            if i.max_asset_criticality
            else "No known asset affected",
            i.critical_assets,
        )
    )

    ident = 0.0
    reasons = []
    if i.privileged_users:
        ident += 6
        reasons.append(f"privileged account(s) involved: {', '.join(i.privileged_users[:3])}")
    if i.new_source_logon:
        ident += 4
        reasons.append("login from a source never seen for this user")
    c.append(
        Contributor(
            "identity_context",
            "User context",
            min(10.0, ident),
            10,
            "; ".join(reasons) or "No privileged or unusual identity context",
            i.privileged_users,
        )
    )

    ti = 0.0
    ti_ev: list[str] = []
    for m in i.ti_matches:
        weight = 1.0 if m.get("verdict") == "malicious" else 0.5 if m.get("verdict") == "suspicious" else 0.0
        val = 20.0 * weight * float(m.get("confidence", 0))
        if val > 0:
            ti_ev.append(f"{m.get('value')} ({m.get('provider')}, {m.get('verdict')}, conf {m.get('confidence')})")
        ti = max(ti, val)
    c.append(
        Contributor(
            "threat_intel",
            "Threat intelligence",
            round(ti, 1),
            20,
            f"{len(ti_ev)} indicator(s) matched threat intelligence" if ti_ev else "No threat-intelligence matches",
            ti_ev,
        )
    )

    corr = min(15.0, 4.0 * max(0, i.distinct_rules - 1) + 3.0 * max(0, i.distinct_sources - 1))
    c.append(
        Contributor(
            "correlation_strength",
            "Correlation strength",
            round(corr, 1),
            15,
            f"{i.distinct_rules} distinct detections from {i.distinct_sources} telemetry source(s)",
        )
    )

    ml = round(10.0 * max(0.0, min(1.0, i.ml_max_score)), 1) if i.ml_max_score else 0.0
    c.append(
        Contributor(
            "behavioral_anomaly",
            "Behavioral anomaly",
            ml,
            10,
            f"Anomaly score {i.ml_max_score:.2f} on {', '.join(i.ml_hosts[:3])}"
            if ml
            else "No behavioral anomaly on affected hosts",
            i.ml_hosts,
        )
    )

    stage = max((TACTIC_WEIGHTS.get(t, 0) for t in i.tactics), default=0)
    top = max(i.tactics, key=lambda t: TACTIC_WEIGHTS.get(t, 0)) if i.tactics else None
    c.append(
        Contributor(
            "attack_stage",
            "ATT&CK stage",
            float(stage),
            10,
            f"Most advanced tactic observed: {top}" if top else "No ATT&CK tactic mapped",
            i.tactics,
        )
    )

    total = sum(x.value for x in c)
    score = int(max(0, min(100, round(total))))
    return RiskResult(score=score, severity=band(score), contributors=c)


def confidence(
    distinct_sources: int, distinct_rules: int, ti_confirmed: bool, only_ml: bool
) -> tuple[float, list[str]]:
    """Deterministic heuristic confidence that the incident reflects real malicious activity."""
    factors = ["base 0.35"]
    v = 0.35
    if distinct_sources > 1:
        add = 0.15 * min(2, distinct_sources - 1)
        v += add
        factors.append(f"+{add:.2f} corroborated by {distinct_sources} independent telemetry sources")
    if distinct_rules > 1:
        add = 0.08 * min(3, distinct_rules - 1)
        v += add
        factors.append(f"+{add:.2f} {distinct_rules} distinct detections agree")
    if ti_confirmed:
        v += 0.1
        factors.append("+0.10 threat intelligence corroborates an indicator")
    if only_ml:
        v -= 0.15
        factors.append("-0.15 based only on a behavioral anomaly")
    return round(max(0.05, min(0.95, v)), 2), factors
