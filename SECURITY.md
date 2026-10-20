# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/vikramballa/soc/security/advisories/new) rather than a
public issue. Include the affected version, reproduction steps and impact. We aim to acknowledge within 3 business days.

## Supported versions

Security fixes are made on the latest release.

## Secure deployment checklist

- [ ] `APP_ENV=production`, a random 32+ byte `APP_SECRET` (startup refuses weak values)
- [ ] HTTPS via a reverse proxy, `SESSION_COOKIE_SECURE=true`, correct `APP_BASE_URL`
- [ ] PostgreSQL role used by SentinelX is **not** a superuser (`sentinelx doctor` verifies) and uses TLS
- [ ] Database not exposed publicly; regular encrypted backups (see docs/operations/backups.md)
- [ ] Change the bootstrap admin password and delete `.sentinelx-admin.txt`
- [ ] One ingest token per shipper; revoke unused tokens
- [ ] Wazuh / OpenSearch / Keycloak / Grafana consoles bound to internal networks only
- [ ] Choose a telemetry retention period that meets your legal obligations

Design details: [docs/security/threat-model.md](docs/security/threat-model.md).

## Responsible use

SentinelX is a defensive tool. Demo scenarios use synthetic data and documentation IP ranges only. Run
any simulation exclusively against systems you own or are explicitly authorized to test.
