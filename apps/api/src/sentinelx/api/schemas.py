"""API response/request models (internal ORM models are never exposed directly)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AlertOut(ORM):
    id: uuid.UUID
    rule_uid: str
    title: str
    description: str
    source: str
    severity: int
    level: str
    status: str
    hostname: str | None
    username: str | None
    src_ip: str | None
    dest_ip: str | None
    domain: str | None
    process_name: str | None
    mitre_techniques: list[str]
    event_count: int
    source_types: list[str]
    details: dict[str, Any]
    first_event_at: datetime
    last_event_at: datetime
    incident_id: uuid.UUID | None
    created_at: datetime


class IncidentSummary(ORM):
    id: uuid.UUID
    number: int
    title: str
    category: str
    severity: str
    risk_score: int
    confidence: float
    status: str
    promoted: bool
    first_event_at: datetime
    last_event_at: datetime
    mitre_techniques: list[str]
    tactics: list[str]
    alert_count: int
    event_count: int
    source_types: list[str]
    disposition: str | None
    assigned_to: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    promoted_at: datetime | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None


class IncidentDetail(IncidentSummary):
    description: str
    risk_breakdown: list[dict[str, Any]]
    confidence_factors: list[str]
    promotion_reason: str | None
    merged_into: uuid.UUID | None


IncidentStatus = Literal["new", "triaged", "investigating", "contained", "resolved", "closed"]
Disposition = Literal["true_positive", "benign_true_positive", "false_positive", "undetermined"]


class IncidentPatch(BaseModel):
    status: IncidentStatus | None = None
    disposition: Disposition | None = None
    assigned_to: uuid.UUID | None = None
    title: str | None = Field(None, min_length=3, max_length=300)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field("", max_length=4000)
    alert_ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class EventOut(ORM):
    id: uuid.UUID
    timestamp: datetime
    ingested_at: datetime
    source_type: str
    event_type: str
    event_action: str | None
    outcome: str | None
    severity: int
    hostname: str | None
    username: str | None
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    protocol: str | None
    process_name: str | None
    process_command_line: str | None
    parent_process_name: str | None
    domain: str | None
    url: str | None
    file_path: str | None
    file_hash: str | None
    rule_id: str | None
    rule_name: str | None
    summary: str


class EventDetail(EventOut):
    host_ip: str | None
    os: str | None
    bytes_out: int | None
    bytes_in: int | None
    process_path: str | None
    parent_process_path: str | None
    event_category: str | None
    mitre_techniques: list[str]
    raw_event: dict[str, Any]
    event_metadata: dict[str, Any] = Field(serialization_alias="metadata")


class AssetOut(ORM):
    id: uuid.UUID
    hostname: str
    os: str | None
    environment: str | None
    ip_addresses: list[str]
    criticality: int
    owner: str | None
    tags: list[str]
    wazuh_agent_id: str | None
    first_seen: datetime
    last_seen: datetime | None
    risk_score: int
    risk_history: list[Any]


class AssetPatch(BaseModel):
    criticality: int | None = Field(None, ge=1, le=5)
    owner: str | None = Field(None, max_length=200)
    environment: str | None = Field(None, max_length=60)
    tags: list[str] | None = Field(None, max_length=30)


class IdentityOut(ORM):
    id: uuid.UUID
    username: str
    email: str | None
    department: str | None
    privileged: bool
    first_seen: datetime
    last_seen: datetime | None
    risk_score: int


class IdentityPatch(BaseModel):
    privileged: bool | None = None
    department: str | None = Field(None, max_length=120)
    email: str | None = Field(None, max_length=320)


class RuleOut(ORM):
    id: uuid.UUID
    rule_uid: str
    name: str | None
    title: str
    description: str
    kind: str
    status: str
    level: str
    severity: int
    tags: list[str]
    mitre_techniques: list[str]
    version: int
    enabled: bool
    generates_alerts: bool
    falsepositives: list[str]
    updated_at: datetime


class RuleDetail(RuleOut):
    content: str
    source_path: str | None


class RulePatch(BaseModel):
    enabled: bool


class IndicatorOut(ORM):
    id: uuid.UUID
    type: str
    value: str
    source: str
    confidence: float
    verdict: str
    tags: list[str]
    description: str | None
    reference: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    expires_at: datetime | None
    created_at: datetime


class IndicatorIn(BaseModel):
    value: str = Field(min_length=3, max_length=1024)
    type: Literal["ip", "domain", "hash", "url"] | None = None
    confidence: float = Field(0.7, ge=0, le=1)
    verdict: Literal["malicious", "suspicious", "benign"] = "malicious"
    tags: list[str] = Field(default_factory=list, max_length=20)
    description: str | None = Field(None, max_length=2000)
    expires_days: int | None = Field(None, ge=1, le=3650)


class FeedImportIn(BaseModel):
    content: str = Field(min_length=1, max_length=5_000_000)
    format: Literal["csv", "txt", "json"]
    source: str = Field(min_length=1, max_length=120)
    default_confidence: float = Field(0.6, ge=0, le=1)
    expires_days: int | None = Field(None, ge=1, le=3650)


class TiResultOut(ORM):
    indicator_type: str
    value: str
    provider: str
    verdict: str
    confidence: float
    tags: list[str]
    references: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    looked_up_at: datetime
    details: dict[str, Any]


class AiInvestigationOut(ORM):
    id: uuid.UUID
    incident_id: uuid.UUID
    status: str
    model: str
    prompt_version: str
    context_sha256: str | None
    context_stats: dict[str, Any]
    result: dict[str, Any] | None
    validation_errors: list[Any]
    injection_flags: list[Any]
    attempts: int
    requested_by: str
    error: str | None
    feedback: str | None
    duration_ms: int | None
    created_at: datetime
    completed_at: datetime | None


class FeedbackIn(BaseModel):
    feedback: Literal["helpful", "not_helpful"]


class UserOut(ORM):
    id: uuid.UUID
    email: str
    display_name: str
    role: str
    auth_provider: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class UserIn(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    display_name: str = Field(min_length=1, max_length=200)
    role: Literal["TENANT_ADMIN", "SECURITY_ANALYST", "IT_OPERATOR", "VIEWER", "SUPER_ADMIN"]
    password: str = Field(min_length=12, max_length=256)


class UserPatch(BaseModel):
    role: Literal["TENANT_ADMIN", "SECURITY_ANALYST", "IT_OPERATOR", "VIEWER", "SUPER_ADMIN"] | None = None
    is_active: bool | None = None
    display_name: str | None = Field(None, min_length=1, max_length=200)


class AuditOut(ORM):
    id: uuid.UUID
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    result: str
    details: dict[str, Any]
    source_ip: str | None
    request_id: str | None
    created_at: datetime


class ResponseActionIn(BaseModel):
    kind: Literal["task", "watchlist_ioc", "mark", "report"]
    title: str = Field(min_length=3, max_length=300)
    payload: dict[str, Any] = Field(default_factory=dict)


class ResponseActionOut(ORM):
    id: uuid.UUID
    kind: str
    status: str
    title: str
    payload: dict[str, Any]
    requested_by: str
    created_at: datetime
    completed_at: datetime | None
