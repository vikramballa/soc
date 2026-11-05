"""Platform hardening and hunting: MFA, scoped ingest tokens, tamper-evident audit chain,
telemetry liveness, entity prevalence and honeytokens.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

NEW_TENANT_TABLES = ["telemetry_sources", "entity_prevalence", "honeytokens"]
_TENANT_EXPR = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_BYPASS_EXPR = "coalesce(current_setting('app.rls_bypass', true), 'off') = 'on'"
GENESIS = "0" * 64

# The canonical text of an audit row. services/audit_chain.py recomputes the same string in Python, so a
# replaced database function cannot hide tampering from `sentinelx audit-verify`.
_HASH_FN = """
CREATE OR REPLACE FUNCTION sentinelx_audit_hash(prev text, r audit_logs) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(concat_ws('|',
    prev, r.seq::text, r.id::text, coalesce(r.tenant_id::text, ''), coalesce(r.actor_id::text, ''),
    r.actor, r.action, r.resource_type, coalesce(r.resource_id, ''), r.result, r.details::text,
    coalesce(r.source_ip, ''), coalesce(r.request_id, ''),
    to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
  ), 'UTF8')), 'hex')
$$;
"""

_CHAIN_TRIGGER_FN = """
CREATE OR REPLACE FUNCTION sentinelx_audit_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  head audit_chain_head%ROWTYPE;
BEGIN
  -- the row lock on the single head row serialises chain appends across transactions
  UPDATE audit_chain_head SET seq = seq + 1 WHERE id = 1 RETURNING * INTO head;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit chain head missing';
  END IF;
  NEW.created_at := coalesce(NEW.created_at, now());
  NEW.seq := head.seq;
  NEW.prev_hash := head.hash;
  NEW.row_hash := sentinelx_audit_hash(head.hash, NEW);
  UPDATE audit_chain_head SET hash = NEW.row_hash WHERE id = 1;
  RETURN NEW;
END;
$$;
"""


def upgrade() -> None:
    # --- MFA + step-up re-authentication
    op.add_column("users", sa.Column("mfa_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("mfa_last_step", sa.BigInteger(), nullable=True))
    op.add_column(
        "users",
        sa.Column("mfa_recovery_hashes", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
    )
    op.add_column("sessions", sa.Column("mfa_pending", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.add_column("sessions", sa.Column("reauth_at", sa.DateTime(timezone=True), nullable=True))

    # --- ingest token scope
    for col in ("allowed_sources", "allowed_cidrs", "known_ips"):
        op.add_column("ingest_tokens", sa.Column(col, postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False))
    op.add_column("ingest_tokens", sa.Column("last_used_ip", sa.String(length=64), nullable=True))

    # --- tamper-evident audit chain
    op.add_column("audit_logs", sa.Column("seq", sa.BigInteger(), nullable=True))
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_logs", sa.Column("row_hash", sa.String(length=64), nullable=True))
    op.create_unique_constraint("uq_audit_logs_seq", "audit_logs", ["seq"])
    op.create_table(
        "audit_chain_head",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(_HASH_FN)
    # Chain the rows that already exist, oldest first. The append-only trigger is lifted for this one
    # transaction only; RLS is bypassed because the chain spans every organization.
    op.execute("SELECT set_config('app.rls_bypass', 'on', true)")
    op.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_immutable")
    op.execute(
        f"""
        DO $$
        DECLARE r audit_logs%ROWTYPE; prev text := '{GENESIS}'; n bigint := 0;
        BEGIN
          FOR r IN SELECT * FROM audit_logs ORDER BY created_at, id LOOP
            n := n + 1;
            r.seq := n;
            UPDATE audit_logs SET seq = n, prev_hash = prev, row_hash = sentinelx_audit_hash(prev, r)
              WHERE id = r.id;
            prev := sentinelx_audit_hash(prev, r);
          END LOOP;
          INSERT INTO audit_chain_head (id, seq, hash) VALUES (1, n, prev);
        END $$;
        """
    )
    op.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_immutable")
    op.execute(_CHAIN_TRIGGER_FN)
    op.execute(
        "CREATE TRIGGER audit_logs_chain BEFORE INSERT ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION sentinelx_audit_chain()"
    )

    # --- telemetry liveness
    op.create_table(
        "telemetry_sources",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("avg_gap_seconds", sa.Float(), nullable=True),
        sa.Column("silent_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("muted_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mute_reason", sa.String(length=300), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "source_type", "hostname"),
    )
    op.create_index("ix_telemetry_sources_tenant_id", "telemetry_sources", ["tenant_id"])

    # --- prevalence (rarity / first seen)
    op.create_table(
        "entity_prevalence",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("seen_count", sa.BigInteger(), server_default="1", nullable=False),
        sa.Column("hosts", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "kind", "value"),
    )
    op.create_index("ix_entity_prevalence_tenant_id", "entity_prevalence", ["tenant_id"])
    op.create_index("ix_entity_prevalence_kind_first", "entity_prevalence", ["tenant_id", "kind", "first_seen"])

    # --- deception
    op.create_table(
        "honeytokens",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trigger_count", sa.Integer(), server_default="0", nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "kind", "value"),
    )
    op.create_index("ix_honeytokens_tenant_id", "honeytokens", ["tenant_id"])

    for table in NEW_TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_BYPASS_EXPR} OR tenant_id = {_TENANT_EXPR}) "
            f"WITH CHECK ({_BYPASS_EXPR} OR tenant_id = {_TENANT_EXPR})"
        )


def downgrade() -> None:
    for table in NEW_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
    op.drop_table("honeytokens")
    op.drop_table("entity_prevalence")
    op.drop_table("telemetry_sources")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_chain ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS sentinelx_audit_chain()")
    op.execute("DROP FUNCTION IF EXISTS sentinelx_audit_hash(text, audit_logs)")
    op.drop_table("audit_chain_head")
    op.drop_constraint("uq_audit_logs_seq", "audit_logs", type_="unique")
    for col in ("row_hash", "prev_hash", "seq"):
        op.drop_column("audit_logs", col)
    for col in ("last_used_ip", "known_ips", "allowed_cidrs", "allowed_sources"):
        op.drop_column("ingest_tokens", col)
    op.drop_column("sessions", "reauth_at")
    op.drop_column("sessions", "mfa_pending")
    for col in ("mfa_recovery_hashes", "mfa_last_step", "mfa_enabled_at", "mfa_secret"):
        op.drop_column("users", col)
