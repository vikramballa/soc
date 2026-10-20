# Database migrations (Alembic)

Applied automatically by `sentinelx init` (or `sentinelx migrate`).

| Revision | What it does |
|---|---|
| `0001_initial_schema` | All tables (generated from `sentinelx/persistence/models.py`) |
| `0002_rls_audit_jobs` | Row-level security policies, append-only audit trigger, job NOTIFY trigger |

New migration after changing the models:

```bash
cd apps/api
PYTHONPATH=src uv run --no-sync alembic revision --autogenerate -m "describe the change"
```
Review the generated file before committing — autogenerate does not know about RLS policies or triggers.
