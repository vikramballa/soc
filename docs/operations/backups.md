# Backups

Everything SentinelX needs is in PostgreSQL (plus `.env` and your rule repository).

```bash
# backup (as a superuser or the sentinelx role)
pg_dump -Fc -d "postgresql://sentinelx:…@host:5432/sentinelx" -f sentinelx-$(date +%F).dump
# restore into an empty database
pg_restore -d "postgresql://sentinelx:…@host:5432/sentinelx" --no-owner sentinelx-2026-10-06.dump
```
Docker: `docker compose exec postgres pg_dump -U postgres -Fc sentinelx > sentinelx.dump`.

Encrypt backups at rest, store them off-host, and test restores. Retention of raw telemetry is set per
organization (Administration → Organization settings); incident evidence and audit logs are kept.
