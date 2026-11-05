# SentinelX threat model (STRIDE)

SentinelX processes attacker-influenced data and holds sensitive security information, so it is itself a
target. Scope: the SentinelX application (API, worker, UI), its PostgreSQL database, integrations (Ollama,
MISP, OpenSearch, Keycloak, Wazuh indexer) and ingestion paths.

## Assets
Telemetry and evidence · incidents and analyst notes · credentials/tokens (sessions, ingest tokens,
integration secrets) · detection rules · ML baselines · audit trail · tenant boundaries.

## Trust boundaries
1. Browser ↔ API (users) 2. Shippers ↔ ingest API (tokens) 3. API/worker ↔ PostgreSQL 4. Worker ↔
external integrations (MISP, OpenSearch, Wazuh indexer, Ollama) 5. **Telemetry content ↔ everything**
(all fields are attacker-controllable).

## Threats and mitigations

| STRIDE | Threat | Mitigations (implemented) |
|---|---|---|
| **S**poofing | Stolen/guessed passwords | Argon2id hashing, per-IP + per-account rate limits, lockout after 8 failures, generic error messages, TOTP two-step verification (required for admins in production, replay-protected, recovery codes), optional Keycloak SSO; failed sign-ins and wrong second factors feed SentinelX's own detection rules |
| S | Session hijack / CSRF | Opaque random session tokens (SHA-256 stored), HttpOnly + SameSite=Lax cookies (Secure required in production), custom-header CSRF check on writes, revocation on logout / password change / deactivation / MFA reset; **step-up re-authentication** (password + code within 15 min) for rule, role, setting, token, decoy and mute changes |
| S | Forged telemetry from the network | Per-tenant ingest tokens (hashed, revocable, last-used tracking) **scoped to sources and networks**; out-of-scope use and use from a new address raise alerts; file/indexer ingestion only from configured paths/URLs |
| **T**ampering | Audit log tampering | `audit_logs` UPDATE/DELETE/TRUNCATE blocked by trigger **and** by missing privileges (runtime role owns nothing, ADR-013); rows hash-chained and verified hourly + by `sentinelx audit-verify`; head hash can be anchored externally |
| T | Disabling security controls from a compromised app | Runtime role is not the schema owner: cannot `DISABLE TRIGGER`, `NO FORCE ROW LEVEL SECURITY`, `DROP POLICY` or `TRUNCATE` (tested) |
| T | Blinding the SOC (rules off, sensors stopped, alert floods) | Self-monitoring events + platform tamper rules that cannot be disabled; telemetry-silence alerts per sender (high after a detection); alert-storm detection; mutes are audited and alerted |
| T | Rule tampering | Rule files versioned (SHA-256 + `rule_versions`); reload restricted to SUPER_ADMIN; per-tenant enable/disable audited |
| T | **Telemetry poisoning / ML baseline poisoning** | Hours containing incident evidence excluded from training; ML capped at 10 risk points and cannot promote alone; deterministic rules remain primary |
| T | Risk-score manipulation | Scores computed only from deterministic inputs with caps; AI cannot change them; asset criticality set by people |
| T | TI poisoning | Results weighted by provider confidence; a single source never proves maliciousness; feeds import audited and attributed |
| **R**epudiation | Denied actions | Audit records for logins, changes, AI requests, reports, response actions, authorization denials (actor, IP, request id) |
| **I**nformation disclosure | Cross-tenant access | Explicit tenant filters **and** PostgreSQL row-level security (`FORCE`), app role is not a superuser (checked by `sentinelx doctor`), tenant header honoured only for SUPER_ADMIN, tests cover this |
| I | Secrets in logs / prompts | Structured-log redaction of sensitive keys; plain tracebacks (no local variables); secret redaction before any LLM call; `.env` never committed |
| I | Verbose errors | Generic 500 bodies with request id; validation errors without internals |
| I | **Prompt injection via logs** | Telemetry passed as escaped JSON in an untrusted block; instruction-like fields withheld and flagged; grounding validator; *likely benign* rejected when injection detected; no tool execution by the LLM; detection rule for AI-directed text |
| I | SSRF via integrations | Integration URLs only from admin configuration (env), scheme allow-list, no embedded credentials, redirects disabled |
| I | XSS | React escaping; JSON viewer escapes before highlighting; HTML reports escape all values; strict CSP (`script-src 'self'`) |
| **D**enial of service | Ingestion floods / huge bodies | Body-size and per-request event limits, per-tenant ingest rate limit, streaming body read, bounded queues, batch inserts |
| D | Expensive searches | Time ranges capped at 31 days, keyset pagination, capped counts |
| D | Malicious parser input | Pydantic validation, quarantine instead of crash, no eval/pickle of input (joblib only loads SentinelX-produced artifacts from its own DB) |
| **E**levation of privilege | Role escalation | Server-side RBAC on every endpoint; admins cannot grant roles above their own or change their own role |
| E | Response abuse | Only safe actions (tasks, watchlist, reports); **no remote command execution exists** |
| E | Path traversal (static UI) | Resolved paths must stay inside the UI build directory |

## Detection evasion (attacker vs. SentinelX's detections)
| Evasion | Counter |
|---|---|
| Avoid known signatures, live off the land | First-seen lineages / TLS fingerprints / user agents, lateral first-logon, LOLBin and Sysmon-based rules, SigmaHQ import |
| Low-and-slow C2 over TLS | Beacon scoring (interval regularity, persistence, size regularity), JA3/JA4 watchlists |
| DNS tunnelling | Unique long-subdomain volume per host and domain |
| Stop or kill the agent | Telemetry silence alerts; agent-stop command rules |
| Use stolen credentials quietly | Honeytokens, Kerberoasting / DCSync / pass-the-hash rules |
| Wait out short correlation windows | Kill-chain progression contributor; hunts look back 24 h |

## Residual risks / operator responsibilities
- `app.rls_bypass` is a session setting the runtime role can set (needed for login and worker routing);
  a SQL injection could use it to read across tenants. Queries are built only via SQLAlchemy.
- Someone holding the *owner* credentials can rewrite the audit chain consistently; anchor the head hash
  outside SentinelX to detect that.
- Serve over HTTPS in production (reverse proxy) and set `SESSION_COOKIE_SECURE=true` (enforced).
- The in-process rate limiter is per instance; add proxy-level limits for multi-instance deployments.
- Secure the hosts running Wazuh/Suricata/Zeek; do not expose their consoles publicly.
- Back up PostgreSQL; protect `.env` and backups.
- LLM output can be wrong — it is labelled as AI-generated and must be verified.
