"""Row-level security, append-only audit log, job NOTIFY trigger.

Revision ID: 0002
Revises: 0001
"""

from alembic import op

from sentinelx.persistence.models import TENANT_TABLES

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_TENANT_EXPR = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_BYPASS_EXPR = "coalesce(current_setting('app.rls_bypass', true), 'off') = 'on'"


def upgrade() -> None:
    for table in [*TENANT_TABLES, "audit_logs"]:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_BYPASS_EXPR} OR tenant_id = {_TENANT_EXPR}) "
            f"WITH CHECK ({_BYPASS_EXPR} OR tenant_id = {_TENANT_EXPR})"
        )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION sentinelx_audit_immutable() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'audit_logs is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION sentinelx_audit_immutable()"
    )
    op.execute(
        "CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION sentinelx_audit_immutable()"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION sentinelx_job_notify() RETURNS trigger AS $$
        BEGIN
          PERFORM pg_notify('sentinelx_jobs', NEW.kind);
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute("CREATE TRIGGER jobs_notify AFTER INSERT ON jobs FOR EACH ROW EXECUTE FUNCTION sentinelx_job_notify()")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS jobs_notify ON jobs")
    op.execute("DROP FUNCTION IF EXISTS sentinelx_job_notify()")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS sentinelx_audit_immutable()")
    for table in [*TENANT_TABLES, "audit_logs"]:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
