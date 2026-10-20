"""SQLAlchemy ORM models - the PostgreSQL application schema.

Every tenant-owned table carries ``tenant_id`` and is protected by row-level security
(see migrations). API responses never expose these models directly; they go through
Pydantic schemas in ``sentinelx.api.schemas``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, list[str]: ARRAY(Text)}


def _uuid() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _tenant() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)


def _created() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = _uuid()
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default=text("'{}'"))
    created_at: Mapped[datetime] = _created()


class User(Base):
    """An operator of SentinelX (not a monitored identity - see ``Identity``)."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email"),)
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    email: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(32))
    password_hash: Mapped[str | None] = mapped_column(Text)
    auth_provider: Mapped[str] = mapped_column(String(16), default="local", server_default="local")
    external_id: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))


class IngestToken(Base):
    __tablename__ = "ingest_tokens"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = _created()
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "hostname"),)
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    hostname: Mapped[str] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(120))
    environment: Mapped[str | None] = mapped_column(String(60))
    ip_addresses: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, server_default="{}")
    criticality: Mapped[int] = mapped_column(Integer, default=2, server_default="2")
    owner: Mapped[str | None] = mapped_column(String(200))
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, server_default="{}")
    wazuh_agent_id: Mapped[str | None] = mapped_column(String(32))
    first_seen: Mapped[datetime] = _created()
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    risk_history: Mapped[list[Any]] = mapped_column(JSONB, default=list, server_default=text("'[]'"))


class Identity(Base):
    """A monitored user account seen in telemetry."""

    __tablename__ = "identities"
    __table_args__ = (UniqueConstraint("tenant_id", "username"),)
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    username: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320))
    department: Mapped[str | None] = mapped_column(String(120))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    first_seen: Mapped[datetime] = _created()
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    risk_history: Mapped[list[Any]] = mapped_column(JSONB, default=list, server_default=text("'[]'"))


class SecurityEvent(Base):
    """Canonical normalized event. ``id`` is a deterministic UUIDv5 (idempotent ingestion)."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_tenant_ts", "tenant_id", text("timestamp DESC")),
        Index("ix_events_host_ts", "tenant_id", "hostname", "timestamp"),
        Index("ix_events_user_ts", "tenant_id", "username", "timestamp"),
        Index("ix_events_src_ts", "tenant_id", "src_ip", "timestamp"),
        Index("ix_events_ts_brin", "timestamp", postgresql_using="brin"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = _created()
    source_type: Mapped[str] = mapped_column(String(16))
    event_type: Mapped[str] = mapped_column(String(32))
    event_action: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str | None] = mapped_column(String(16))
    severity: Mapped[int] = mapped_column(Integer, default=0)
    hostname: Mapped[str | None] = mapped_column(String(255))
    host_ip: Mapped[str | None] = mapped_column(String(64))
    os: Mapped[str | None] = mapped_column(String(60))
    username: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(64))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dest_ip: Mapped[str | None] = mapped_column(String(64))
    dest_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(32))
    bytes_out: Mapped[int | None] = mapped_column(BigInteger)
    bytes_in: Mapped[int | None] = mapped_column(BigInteger)
    process_name: Mapped[str | None] = mapped_column(String(255))
    process_path: Mapped[str | None] = mapped_column(Text)
    process_command_line: Mapped[str | None] = mapped_column(Text)
    parent_process_name: Mapped[str | None] = mapped_column(String(255))
    parent_process_path: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(512))
    url: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(Text)
    file_hash: Mapped[str | None] = mapped_column(String(128))
    event_category: Mapped[str | None] = mapped_column(String(120))
    rule_id: Mapped[str | None] = mapped_column(String(64))
    rule_name: Mapped[str | None] = mapped_column(Text)
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, server_default="{}")
    summary: Mapped[str] = mapped_column(Text, default="")
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)


class QuarantinedEvent(Base):
    __tablename__ = "quarantined_events"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    source_type: Mapped[str] = mapped_column(String(16))
    error: Mapped[str] = mapped_column(Text)
    payload: Mapped[str] = mapped_column(Text)
    received_at: Mapped[datetime] = _created()


class IngestionSource(Base):
    """Per-tenant per-source health and throughput counters."""

    __tablename__ = "ingestion_sources"
    __table_args__ = (UniqueConstraint("tenant_id", "source_type"),)
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    source_type: Mapped[str] = mapped_column(String(16))
    events_total: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    failures_total: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    duplicates_total: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ingest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


class IngestionCheckpoint(Base):
    __tablename__ = "ingestion_checkpoints"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    source_key: Mapped[str] = mapped_column(String(512), unique=True)
    position: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = _created()


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[uuid.UUID] = _uuid()
    rule_uid: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str | None] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(20))  # sigma | correlation | builtin | source | ml
    status: Mapped[str] = mapped_column(String(20), default="experimental")
    level: Mapped[str] = mapped_column(String(16), default="medium")
    severity: Mapped[int] = mapped_column(Integer, default=50)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    content: Mapped[str] = mapped_column(Text, default="")
    content_sha256: Mapped[str] = mapped_column(String(64), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    generates_alerts: Mapped[bool] = mapped_column(Boolean, default=True)
    source_path: Mapped[str | None] = mapped_column(Text)
    falsepositives: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    updated_at: Mapped[datetime] = _created()


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    id: Mapped[uuid.UUID] = _uuid()
    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = _created()
    created_by: Mapped[str | None] = mapped_column(String(320))


class RuleMatch(Base):
    """Lightweight record of a base-rule hit; input to Sigma correlation rules (short retention)."""

    __tablename__ = "rule_matches"
    __table_args__ = (Index("ix_rule_matches_lookup", "tenant_id", "rule_uid", "ts"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"))
    rule_uid: Mapped[str] = mapped_column(String(64))
    event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    fields: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "number"),
        Index("ix_incidents_open", "tenant_id", "status", "last_event_at"),
    )
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    number: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(60), default="suspicious_activity")
    severity: Mapped[str] = mapped_column(String(16), default="low")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_breakdown: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_factors: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    status: Mapped[str] = mapped_column(String(20), default="new")
    promoted: Mapped[bool] = mapped_column(Boolean, default=False)
    promotion_reason: Mapped[str | None] = mapped_column(Text)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    tactics: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    source_types: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    disposition: Mapped[str | None] = mapped_column(String(32))
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    merged_into: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _created()
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_created", "tenant_id", text("created_at DESC")),
        Index("ix_alerts_dedup", "tenant_id", "dedup_key", "last_event_at"),
    )
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    rule_uid: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(20))  # sigma | correlation | builtin | source | ml | ti
    severity: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")
    hostname: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(64))
    dest_ip: Mapped[str | None] = mapped_column(String(64))
    domain: Mapped[str | None] = mapped_column(String(512))
    process_name: Mapped[str | None] = mapped_column(String(255))
    file_hash: Mapped[str | None] = mapped_column(String(128))
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    source_types: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(300))
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = _created()


class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, index=True)
    tenant_id: Mapped[uuid.UUID] = _tenant()


class IncidentEntity(Base):
    __tablename__ = "incident_entities"
    __table_args__ = (Index("ix_incident_entities_lookup", "tenant_id", "kind", "value"),)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[str] = mapped_column(String(512), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alert_count: Mapped[int] = mapped_column(Integer, default=1)


class IncidentEvidence(Base):
    """Evidence snapshot: survives telemetry retention so incidents remain explainable."""

    __tablename__ = "incident_evidence"
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = _tenant()
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)


class IncidentActivity(Base):
    """Incident history visible in the UI (status changes, merges, notes, AI runs)."""

    __tablename__ = "incident_activity"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(320), default="system")
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = _created()


class AnalystNote(Base):
    __tablename__ = "analyst_notes"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    author_name: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(20), default="completed")
    title: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    requested_by: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = _created()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Indicator(Base):
    """Watchlist / feed indicator (IOC)."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("tenant_id", "type", "value", "source"),
        Index("ix_indicators_value", "tenant_id", "value"),
    )
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    type: Mapped[str] = mapped_column(String(16))  # ip | domain | hash | url
    value: Mapped[str] = mapped_column(String(1024))
    source: Mapped[str] = mapped_column(String(120))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    verdict: Mapped[str] = mapped_column(String(16), default="malicious")
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    description: Mapped[str | None] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()


class ThreatIntelResult(Base):
    __tablename__ = "threat_intel_results"
    __table_args__ = (UniqueConstraint("tenant_id", "indicator_type", "value", "provider"),)
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    indicator_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(1024), index=True)
    provider: Mapped[str] = mapped_column(String(60))
    verdict: Mapped[str] = mapped_column(String(16))  # malicious | suspicious | unknown | benign
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    references: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    looked_up_at: Mapped[datetime] = _created()
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class MitreTactic(Base):
    __tablename__ = "mitre_tactics"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    shortname: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    order: Mapped[int] = mapped_column(Integer)
    url: Mapped[str] = mapped_column(Text, default="")


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    tactics: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    platforms: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(Text, default="")
    detection: Mapped[str] = mapped_column(Text, default="")


class MlModel(Base):
    __tablename__ = "ml_models"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    name: Mapped[str] = mapped_column(String(80))
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="active")
    feature_names: Mapped[list[str]] = mapped_column(ARRAY(Text))
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    baseline: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    artifact: Mapped[bytes] = mapped_column(LargeBinary)
    trained_at: Mapped[datetime] = _created()


class MlPrediction(Base):
    __tablename__ = "ml_predictions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "model_id", "entity_id", "window_start"),
        Index("ix_ml_pred_entity", "tenant_id", "entity_id", "window_start"),
    )
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ml_models.id", ondelete="CASCADE"))
    entity_kind: Mapped[str] = mapped_column(String(16), default="host")
    entity_id: Mapped[str] = mapped_column(String(255))
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    anomaly_score: Mapped[float] = mapped_column(Float)
    raw_score: Mapped[float] = mapped_column(Float)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    top_contributors: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = _created()


class AiInvestigation(Base):
    __tablename__ = "ai_investigations"
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="queued")
    model: Mapped[str] = mapped_column(String(120))
    prompt_version: Mapped[str] = mapped_column(String(32))
    context_sha256: Mapped[str | None] = mapped_column(String(64))
    context_stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    validation_errors: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    injection_flags: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    requested_by: Mapped[str] = mapped_column(String(320))
    error: Mapped[str | None] = mapped_column(Text)
    feedback: Mapped[str | None] = mapped_column(String(16))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = _created()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    """Append-only (UPDATE/DELETE blocked by a database trigger)."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_tenant_ts", "tenant_id", text("created_at DESC")),)
    id: Mapped[uuid.UUID] = _uuid()
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(80))
    resource_type: Mapped[str] = mapped_column(String(60))
    resource_id: Mapped[str | None] = mapped_column(String(120))
    result: Mapped[str] = mapped_column(String(16), default="success")
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = _created()


class Job(Base):
    """PostgreSQL-backed job queue (FOR UPDATE SKIP LOCKED + LISTEN/NOTIFY). See ADR-003."""

    __tablename__ = "jobs"
    __table_args__ = (
        Index("ix_jobs_ready", "status", "run_after", postgresql_where=text("status = 'queued'")),
        Index("uq_jobs_dedup", "dedup_key", unique=True, postgresql_where=text("status IN ('queued','running')")),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    kind: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    dedup_key: Mapped[str | None] = mapped_column(String(200))
    run_after: Mapped[datetime] = _created()
    locked_by: Mapped[str | None] = mapped_column(String(80))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"
    worker_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    jobs_done: Mapped[int] = mapped_column(BigInteger, default=0)
    info: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


TENANT_TABLES = [
    "users",
    "sessions",
    "ingest_tokens",
    "assets",
    "identities",
    "security_events",
    "quarantined_events",
    "ingestion_sources",
    "ingestion_checkpoints",
    "rule_matches",
    "incidents",
    "alerts",
    "alert_events",
    "incident_entities",
    "incident_evidence",
    "incident_activity",
    "analyst_notes",
    "response_actions",
    "indicators",
    "threat_intel_results",
    "ml_models",
    "ml_predictions",
    "ai_investigations",
]
