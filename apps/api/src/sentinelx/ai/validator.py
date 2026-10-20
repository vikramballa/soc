"""Grounding validator: rejects AI output that cites non-existent evidence, unsupported techniques,
unknown indicators, or claims to have taken actions."""

from __future__ import annotations

import re
from typing import Any

from sentinelx.ai.context import AiContext
from sentinelx.ai.schema import AiAnalysis
from sentinelx.mitre.catalog import get_catalog

_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_REF_RE = re.compile(r"\bE\d{2,3}\b", re.I)


def split_refs(value: str) -> list[str]:
    """A claim may cite several references ("E02, E04"); every cited reference must exist."""
    found = [r.upper() for r in _REF_RE.findall(value)]
    return found or [value.strip().upper()]


_ACTION_CLAIM = re.compile(
    r"\b(I|we|SentinelX)\s+(have\s+|has\s+)?(already\s+)?(blocked|isolated|quarantined|disabled|removed|deleted|"
    r"reset|terminated|killed|contained|remediated)\b",
    re.I,
)


def validate(analysis: AiAnalysis, ctx: AiContext) -> list[str]:
    errors: list[str] = []
    refs = set(ctx.ref_to_event)
    catalog = get_catalog()
    if not analysis.summary.strip():
        errors.append("summary is empty")
    if analysis.verdict != "insufficient_evidence" and not analysis.evidence:
        errors.append("a verdict other than insufficient_evidence must cite evidence")
    for i, e in enumerate(analysis.evidence):
        bad = [r for r in split_refs(e.event_id) if r not in refs]
        if bad:
            errors.append(f"evidence[{i}] cites unknown event reference(s) {', '.join(bad)}")
    for i, m in enumerate(analysis.mitre_assessment):
        tid = m.technique_id.strip().upper()
        if not _TECH_RE.match(tid):
            errors.append(f"mitre_assessment[{i}] has malformed technique id '{m.technique_id}'")
            continue
        if m.status == "supported" and tid not in ctx.allowed_techniques:
            errors.append(f"mitre_assessment[{i}] {tid} is not supported by any detection rule; mark it as hypothesis")
        if not catalog.exists(tid):
            errors.append(f"mitre_assessment[{i}] {tid} does not exist in MITRE ATT&CK")
        for r in (x for raw in m.evidence_event_ids for x in split_refs(raw)):
            if r not in refs:
                errors.append(f"mitre_assessment[{i}] cites unknown event reference '{r}'")
        if not m.evidence_event_ids:
            errors.append(f"mitre_assessment[{i}] {tid} cites no evidence")
    for v in analysis.indicators_to_search:
        if v.strip().lower() not in ctx.allowed_indicators:
            errors.append(f"indicator '{v}' is not present in the incident evidence")
    if ctx.injection_flags and analysis.verdict == "likely_benign":
        errors.append(
            "verdict 'likely_benign' matches instructions planted in the telemetry by a possible attacker; "
            "base the verdict on the evidence only"
        )
    texts = [
        analysis.summary,
        analysis.severity_assessment,
        *analysis.recommended_investigation_steps,
        *(e.claim for e in analysis.evidence),
    ]
    for t in texts:
        claim = _ACTION_CLAIM.search(t)
        if claim:
            errors.append(f"output claims an action was taken ('{claim.group(0)}'); the assistant cannot act")
            break
    return errors


def to_stored(analysis: AiAnalysis, ctx: AiContext) -> dict[str, Any]:
    """Map E-references back to real event ids for storage / UI (AI -> evidence -> original event)."""
    d = analysis.model_dump()
    for e in d["evidence"]:
        refs = split_refs(e["event_id"])
        e["refs"] = refs
        e["ref"] = refs[0]
        e["event_ids"] = [ctx.ref_to_event[r] for r in refs]
        e["event_id"] = e["event_ids"][0]
    for m in d["mitre_assessment"]:
        m["technique_id"] = m["technique_id"].strip().upper()
        refs = list(dict.fromkeys(x for raw in m["evidence_event_ids"] for x in split_refs(raw)))
        m["evidence_refs"] = refs
        m["evidence_event_ids"] = [ctx.ref_to_event[r] for r in refs]
        t = get_catalog().get(m["technique_id"])
        m["technique_name"] = t.name if t else None
    return d
