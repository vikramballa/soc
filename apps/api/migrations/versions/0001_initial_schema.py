"""Initial schema: every table, index and constraint (generated from persistence/models.py).

Revision ID: 0001
Revises:
Create Date: 2026-10-06 16:35:49.017080

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("actor", sa.String(length=320), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("resource_type", sa.String(length=60), nullable=False),
        sa.Column("resource_id", sa.String(length=120), nullable=True),
        sa.Column("result", sa.String(length=16), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_audit_tenant_ts", "audit_logs", ["tenant_id", sa.literal_column("created_at DESC")], unique=False
    )
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("rule_uid", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("generates_alerts", sa.Boolean(), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=True),
        sa.Column("falsepositives", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_uid"),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("dedup_key", sa.String(length=200), nullable=True),
        sa.Column("run_after", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("locked_by", sa.String(length=80), nullable=True),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_jobs_ready", "jobs", ["status", "run_after"], unique=False, postgresql_where=sa.text("status = 'queued'")
    )
    op.create_index(
        "uq_jobs_dedup", "jobs", ["dedup_key"], unique=True, postgresql_where=sa.text("status IN ('queued','running')")
    )
    op.create_table(
        "mitre_tactics",
        sa.Column("id", sa.String(length=16), nullable=False),
        sa.Column("shortname", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("order", sa.Integer(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("shortname"),
    )
    op.create_table(
        "mitre_techniques",
        sa.Column("id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("tactics", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("platforms", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.Column("parent_id", sa.String(length=16), nullable=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("detection", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "tenants",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("settings", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_id", sa.String(length=80), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("jobs_done", sa.BigInteger(), nullable=False),
        sa.Column("info", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("worker_id"),
    )
    op.create_table(
        "assets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("os", sa.String(length=120), nullable=True),
        sa.Column("environment", sa.String(length=60), nullable=True),
        sa.Column("ip_addresses", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("criticality", sa.Integer(), server_default="2", nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("wazuh_agent_id", sa.String(length=32), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_score", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "risk_history", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'"), nullable=False
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "hostname"),
    )
    op.create_index(op.f("ix_assets_tenant_id"), "assets", ["tenant_id"], unique=False)
    op.create_table(
        "identities",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("department", sa.String(length=120), nullable=True),
        sa.Column("privileged", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_score", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "risk_history", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'"), nullable=False
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "username"),
    )
    op.create_index(op.f("ix_identities_tenant_id"), "identities", ["tenant_id"], unique=False)
    op.create_table(
        "indicators",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=1024), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("reference", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "type", "value", "source"),
    )
    op.create_index(op.f("ix_indicators_tenant_id"), "indicators", ["tenant_id"], unique=False)
    op.create_index("ix_indicators_value", "indicators", ["tenant_id", "value"], unique=False)
    op.create_table(
        "ingest_tokens",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_ingest_tokens_tenant_id"), "ingest_tokens", ["tenant_id"], unique=False)
    op.create_table(
        "ingestion_checkpoints",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("source_key", sa.String(length=512), nullable=False),
        sa.Column("position", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_key"),
    )
    op.create_index(op.f("ix_ingestion_checkpoints_tenant_id"), "ingestion_checkpoints", ["tenant_id"], unique=False)
    op.create_table(
        "ingestion_sources",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("events_total", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("failures_total", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("duplicates_total", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ingest_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "source_type"),
    )
    op.create_index(op.f("ix_ingestion_sources_tenant_id"), "ingestion_sources", ["tenant_id"], unique=False)
    op.create_table(
        "ml_models",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("feature_names", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("baseline", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("artifact", sa.LargeBinary(), nullable=False),
        sa.Column("trained_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ml_models_tenant_id"), "ml_models", ["tenant_id"], unique=False)
    op.create_table(
        "quarantined_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_quarantined_events_tenant_id"), "quarantined_events", ["tenant_id"], unique=False)
    op.create_table(
        "rule_matches",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("rule_uid", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=True),
        sa.Column("alert_id", sa.UUID(), nullable=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fields", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rule_matches_lookup", "rule_matches", ["tenant_id", "rule_uid", "ts"], unique=False)
    op.create_table(
        "rule_versions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("rule_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.ForeignKeyConstraint(["rule_id"], ["detection_rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "security_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("event_action", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=True),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("host_ip", sa.String(length=64), nullable=True),
        sa.Column("os", sa.String(length=60), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dest_ip", sa.String(length=64), nullable=True),
        sa.Column("dest_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=True),
        sa.Column("bytes_out", sa.BigInteger(), nullable=True),
        sa.Column("bytes_in", sa.BigInteger(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("process_path", sa.Text(), nullable=True),
        sa.Column("process_command_line", sa.Text(), nullable=True),
        sa.Column("parent_process_name", sa.String(length=255), nullable=True),
        sa.Column("parent_process_path", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(length=512), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("file_hash", sa.String(length=128), nullable=True),
        sa.Column("event_category", sa.String(length=120), nullable=True),
        sa.Column("rule_id", sa.String(length=64), nullable=True),
        sa.Column("rule_name", sa.Text(), nullable=True),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("raw_event", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_events_host_ts", "security_events", ["tenant_id", "hostname", "timestamp"], unique=False)
    op.create_index("ix_events_src_ts", "security_events", ["tenant_id", "src_ip", "timestamp"], unique=False)
    op.create_index(
        "ix_events_tenant_ts", "security_events", ["tenant_id", sa.literal_column("timestamp DESC")], unique=False
    )
    op.create_index("ix_events_ts_brin", "security_events", ["timestamp"], unique=False, postgresql_using="brin")
    op.create_index("ix_events_user_ts", "security_events", ["tenant_id", "username", "timestamp"], unique=False)
    op.create_table(
        "threat_intel_results",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=1024), nullable=False),
        sa.Column("provider", sa.String(length=60), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("references", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "indicator_type", "value", "provider"),
    )
    op.create_index(op.f("ix_threat_intel_results_tenant_id"), "threat_intel_results", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_threat_intel_results_value"), "threat_intel_results", ["value"], unique=False)
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("auth_provider", sa.String(length=16), server_default="local", nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("failed_logins", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index(op.f("ix_users_tenant_id"), "users", ["tenant_id"], unique=False)
    op.create_table(
        "incidents",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=60), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confidence_factors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("promoted", sa.Boolean(), nullable=False),
        sa.Column("promotion_reason", sa.Text(), nullable=True),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("tactics", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("source_types", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("disposition", sa.String(length=32), nullable=True),
        sa.Column("assigned_to", sa.UUID(), nullable=True),
        sa.Column("merged_into", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "number"),
    )
    op.create_index("ix_incidents_open", "incidents", ["tenant_id", "status", "last_event_at"], unique=False)
    op.create_index(op.f("ix_incidents_tenant_id"), "incidents", ["tenant_id"], unique=False)
    op.create_table(
        "ml_predictions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("model_id", sa.UUID(), nullable=False),
        sa.Column("entity_kind", sa.String(length=16), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), nullable=False),
        sa.Column("features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("top_contributors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["model_id"], ["ml_models.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "model_id", "entity_id", "window_start"),
    )
    op.create_index("ix_ml_pred_entity", "ml_predictions", ["tenant_id", "entity_id", "window_start"], unique=False)
    op.create_index(op.f("ix_ml_predictions_tenant_id"), "ml_predictions", ["tenant_id"], unique=False)
    op.create_table(
        "sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=300), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_sessions_tenant_id"), "sessions", ["tenant_id"], unique=False)
    op.create_table(
        "ai_investigations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=False),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column("context_sha256", sa.String(length=64), nullable=True),
        sa.Column("context_stats", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("validation_errors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("injection_flags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(length=320), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("feedback", sa.String(length=16), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ai_investigations_incident_id"), "ai_investigations", ["incident_id"], unique=False)
    op.create_index(op.f("ix_ai_investigations_tenant_id"), "ai_investigations", ["tenant_id"], unique=False)
    op.create_table(
        "alerts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("rule_uid", sa.String(length=64), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("dest_ip", sa.String(length=64), nullable=True),
        sa.Column("domain", sa.String(length=512), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("file_hash", sa.String(length=128), nullable=True),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("source_types", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("dedup_key", sa.String(length=300), nullable=False),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_dedup", "alerts", ["tenant_id", "dedup_key", "last_event_at"], unique=False)
    op.create_index(op.f("ix_alerts_incident_id"), "alerts", ["incident_id"], unique=False)
    op.create_index(
        "ix_alerts_tenant_created", "alerts", ["tenant_id", sa.literal_column("created_at DESC")], unique=False
    )
    op.create_index(op.f("ix_alerts_tenant_id"), "alerts", ["tenant_id"], unique=False)
    op.create_table(
        "analyst_notes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("author_id", sa.UUID(), nullable=True),
        sa.Column("author_name", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_analyst_notes_incident_id"), "analyst_notes", ["incident_id"], unique=False)
    op.create_index(op.f("ix_analyst_notes_tenant_id"), "analyst_notes", ["tenant_id"], unique=False)
    op.create_table(
        "incident_activity",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.String(length=320), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_incident_activity_incident_id"), "incident_activity", ["incident_id"], unique=False)
    op.create_index(op.f("ix_incident_activity_tenant_id"), "incident_activity", ["tenant_id"], unique=False)
    op.create_table(
        "incident_entities",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("incident_id", "kind", "value"),
    )
    op.create_index("ix_incident_entities_lookup", "incident_entities", ["tenant_id", "kind", "value"], unique=False)
    op.create_table(
        "incident_evidence",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("alert_id", sa.UUID(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("incident_id", "event_id"),
    )
    op.create_index(op.f("ix_incident_evidence_tenant_id"), "incident_evidence", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_incident_evidence_timestamp"), "incident_evidence", ["timestamp"], unique=False)
    op.create_table(
        "response_actions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("requested_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_response_actions_incident_id"), "response_actions", ["incident_id"], unique=False)
    op.create_index(op.f("ix_response_actions_tenant_id"), "response_actions", ["tenant_id"], unique=False)
    op.create_table(
        "alert_events",
        sa.Column("alert_id", sa.UUID(), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("alert_id", "event_id"),
    )
    op.create_index(op.f("ix_alert_events_event_id"), "alert_events", ["event_id"], unique=False)
    op.create_index(op.f("ix_alert_events_tenant_id"), "alert_events", ["tenant_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_alert_events_tenant_id"), table_name="alert_events")
    op.drop_index(op.f("ix_alert_events_event_id"), table_name="alert_events")
    op.drop_table("alert_events")
    op.drop_index(op.f("ix_response_actions_tenant_id"), table_name="response_actions")
    op.drop_index(op.f("ix_response_actions_incident_id"), table_name="response_actions")
    op.drop_table("response_actions")
    op.drop_index(op.f("ix_incident_evidence_timestamp"), table_name="incident_evidence")
    op.drop_index(op.f("ix_incident_evidence_tenant_id"), table_name="incident_evidence")
    op.drop_table("incident_evidence")
    op.drop_index("ix_incident_entities_lookup", table_name="incident_entities")
    op.drop_table("incident_entities")
    op.drop_index(op.f("ix_incident_activity_tenant_id"), table_name="incident_activity")
    op.drop_index(op.f("ix_incident_activity_incident_id"), table_name="incident_activity")
    op.drop_table("incident_activity")
    op.drop_index(op.f("ix_analyst_notes_tenant_id"), table_name="analyst_notes")
    op.drop_index(op.f("ix_analyst_notes_incident_id"), table_name="analyst_notes")
    op.drop_table("analyst_notes")
    op.drop_index(op.f("ix_alerts_tenant_id"), table_name="alerts")
    op.drop_index("ix_alerts_tenant_created", table_name="alerts")
    op.drop_index(op.f("ix_alerts_incident_id"), table_name="alerts")
    op.drop_index("ix_alerts_dedup", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index(op.f("ix_ai_investigations_tenant_id"), table_name="ai_investigations")
    op.drop_index(op.f("ix_ai_investigations_incident_id"), table_name="ai_investigations")
    op.drop_table("ai_investigations")
    op.drop_index(op.f("ix_sessions_tenant_id"), table_name="sessions")
    op.drop_table("sessions")
    op.drop_index(op.f("ix_ml_predictions_tenant_id"), table_name="ml_predictions")
    op.drop_index("ix_ml_pred_entity", table_name="ml_predictions")
    op.drop_table("ml_predictions")
    op.drop_index(op.f("ix_incidents_tenant_id"), table_name="incidents")
    op.drop_index("ix_incidents_open", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(op.f("ix_users_tenant_id"), table_name="users")
    op.drop_table("users")
    op.drop_index(op.f("ix_threat_intel_results_value"), table_name="threat_intel_results")
    op.drop_index(op.f("ix_threat_intel_results_tenant_id"), table_name="threat_intel_results")
    op.drop_table("threat_intel_results")
    op.drop_index("ix_events_user_ts", table_name="security_events")
    op.drop_index("ix_events_ts_brin", table_name="security_events", postgresql_using="brin")
    op.drop_index("ix_events_tenant_ts", table_name="security_events")
    op.drop_index("ix_events_src_ts", table_name="security_events")
    op.drop_index("ix_events_host_ts", table_name="security_events")
    op.drop_table("security_events")
    op.drop_table("rule_versions")
    op.drop_index("ix_rule_matches_lookup", table_name="rule_matches")
    op.drop_table("rule_matches")
    op.drop_index(op.f("ix_quarantined_events_tenant_id"), table_name="quarantined_events")
    op.drop_table("quarantined_events")
    op.drop_index(op.f("ix_ml_models_tenant_id"), table_name="ml_models")
    op.drop_table("ml_models")
    op.drop_index(op.f("ix_ingestion_sources_tenant_id"), table_name="ingestion_sources")
    op.drop_table("ingestion_sources")
    op.drop_index(op.f("ix_ingestion_checkpoints_tenant_id"), table_name="ingestion_checkpoints")
    op.drop_table("ingestion_checkpoints")
    op.drop_index(op.f("ix_ingest_tokens_tenant_id"), table_name="ingest_tokens")
    op.drop_table("ingest_tokens")
    op.drop_index("ix_indicators_value", table_name="indicators")
    op.drop_index(op.f("ix_indicators_tenant_id"), table_name="indicators")
    op.drop_table("indicators")
    op.drop_index(op.f("ix_identities_tenant_id"), table_name="identities")
    op.drop_table("identities")
    op.drop_index(op.f("ix_assets_tenant_id"), table_name="assets")
    op.drop_table("assets")
    op.drop_table("worker_heartbeats")
    op.drop_table("tenants")
    op.drop_table("mitre_techniques")
    op.drop_table("mitre_tactics")
    op.drop_index("uq_jobs_dedup", table_name="jobs", postgresql_where=sa.text("status IN ('queued','running')"))
    op.drop_index("ix_jobs_ready", table_name="jobs", postgresql_where=sa.text("status = 'queued'"))
    op.drop_table("jobs")
    op.drop_table("detection_rules")
    op.drop_index("ix_audit_tenant_ts", table_name="audit_logs")
    op.drop_table("audit_logs")
