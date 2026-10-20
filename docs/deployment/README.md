# Deployment

## Modes

| Mode | How | Notes |
|---|---|---|
| Demo / lab | `./scripts/setup.sh --demo` or `docker compose up -d` | Single machine, synthetic Demo Lab |
| SMB production | Docker Compose or native on a VM (4 vCPU, 8 GB RAM, SSD) behind HTTPS | Point Wazuh/Suricata/Zeek at it |
| MSSP / larger | Several organizations (tenants), extra `sentinelx worker` processes, OpenSearch sink, managed PostgreSQL | Add proxy rate limiting |

## Resource guide

| Component | RAM |
|---|---|
| SentinelX (API + worker) | 300–600 MB |
| PostgreSQL | 256 MB – 2 GB depending on volume |
| Ollama + 4B model (optional) | ~3–4 GB |
| OpenSearch (optional) | ≥ 1 GB |
| Keycloak (optional) | ~700 MB |

## Production checklist

1. Put SentinelX behind a TLS reverse proxy (Caddy, nginx, Traefik). Example (Caddy):
   ```
   soc.example.com {
       reverse_proxy 127.0.0.1:8000
   }
   ```
2. `.env`: `APP_ENV=production`, `APP_SECRET=$(openssl rand -hex 32)`, `APP_BASE_URL=https://soc.example.com`,
   `SESSION_COOKIE_SECURE=true`. SentinelX refuses to start in production with weak settings.
3. PostgreSQL: dedicated non-superuser role (created by `infra/postgres/init-sentinelx.sh` or `scripts/setup.sh`),
   TLS (`?ssl=require` in `DATABASE_URL`), backups (see operations/backups.md).
4. Run `sentinelx doctor` and fix every ✗.
5. Scale-out: run additional `sentinelx worker` processes (same `.env`, `EMBEDDED_WORKER=false` on the API).

## Docker Compose profiles

`core` (default: postgres + sentinelx) · `ai` (Ollama) · `observability` (Prometheus + Grafana with a
SentinelX dashboard) · `search` (OpenSearch) · `sso` (Keycloak with a pre-configured `sentinelx` realm) ·
`sensors` (Suricata + Zeek replaying `infra/pcaps`) · `full`.

Admin consoles bind to 127.0.0.1 only. Wazuh is not bundled — use the official single-node deployment
(<https://documentation.wazuh.com/current/deployment-options/docker/index.html>) and set `WAZUH_INDEXER_URL`.

## Upgrades

Pull the new version, then `sentinelx init` (idempotent: applies migrations, refreshes rules/MITRE).
