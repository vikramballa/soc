"""Structured AI output schema + JSON schema handed to Ollama's ``format`` parameter."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def _clip(n: int) -> BeforeValidator:
    """Truncate over-long text instead of rejecting it: length is not a grounding problem."""
    return BeforeValidator(lambda v: v[:n] if isinstance(v, str) else v)


def _clip_list(n: int) -> BeforeValidator:
    return BeforeValidator(lambda v: v[:n] if isinstance(v, list) else v)


Text = Annotated[str, _clip(600)]
LongText = Annotated[str, _clip(2000)]


class EvidenceClaim(BaseModel):
    model_config = ConfigDict(extra="ignore")
    event_id: Annotated[str, _clip(600)]
    claim: Text


class MitreAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    technique_id: Annotated[str, _clip(16)]
    reason: Text
    evidence_event_ids: Annotated[list[str], _clip_list(20)] = Field(default_factory=list)
    status: Literal["supported", "hypothesis"] = "supported"


class AiAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    summary: LongText
    verdict: Literal["likely_malicious", "suspicious", "likely_benign", "insufficient_evidence"]
    severity_assessment: LongText
    evidence: Annotated[list[EvidenceClaim], _clip_list(25)] = Field(default_factory=list)
    mitre_assessment: Annotated[list[MitreAssessment], _clip_list(15)] = Field(default_factory=list)
    possible_benign_explanations: Annotated[list[Text], _clip_list(8)] = Field(default_factory=list)
    recommended_investigation_steps: Annotated[list[Text], _clip_list(10)] = Field(default_factory=list)
    indicators_to_search: Annotated[list[Annotated[str, _clip(1024)]], _clip_list(20)] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


def _str(max_len: int) -> dict[str, Any]:
    return {"type": "string", "maxLength": max_len}


OLLAMA_FORMAT: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": _str(1200),
        "verdict": {
            "type": "string",
            "enum": ["likely_malicious", "suspicious", "likely_benign", "insufficient_evidence"],
        },
        "severity_assessment": _str(500),
        "evidence": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "properties": {"event_id": {"type": "string"}, "claim": _str(300)},
                "required": ["event_id", "claim"],
            },
        },
        "mitre_assessment": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "reason": _str(300),
                    "evidence_event_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 6},
                    "status": {"type": "string", "enum": ["supported", "hypothesis"]},
                },
                "required": ["technique_id", "reason", "evidence_event_ids", "status"],
            },
        },
        "possible_benign_explanations": {"type": "array", "items": _str(300), "maxItems": 5},
        "recommended_investigation_steps": {"type": "array", "items": _str(300), "maxItems": 8},
        "indicators_to_search": {"type": "array", "items": {"type": "string"}, "maxItems": 12},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": [
        "summary",
        "verdict",
        "severity_assessment",
        "evidence",
        "mitre_assessment",
        "possible_benign_explanations",
        "recommended_investigation_steps",
        "indicators_to_search",
        "confidence",
    ],
}
