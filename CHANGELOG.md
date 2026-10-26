# Changelog

## Unreleased
- Access control: incidents can only be assigned to people whose role can work them (viewers are
  read-only); completed watchlist/mark response actions can no longer be toggled back to "open"; rule
  dry-runs need `event:read` because they return event samples; internal service addresses (Ollama,
  MISP, OpenSearch, Keycloak) are shown only to administrators.
- Administration: reset a user's password (also unlocks and signs them out everywhere) and unlock
  locked accounts; locked accounts are flagged in the user list.
- My account page: role, what it allows in plain language, active sessions with sign-out per session or
  for all other sessions.
- Incidents: "Assigned to me" / "Unassigned" owner filter (`assignee` query parameter); the dashboard links
  to the incidents you own.
- Fix: the synthetic Zeek `conn.log` test fixture was excluded by `.gitignore` and is now tracked.

## 0.1.0 — 2026-10-06
First release.
- Ingestion: Wazuh (indexer polling, alerts.json, push), Suricata EVE JSON, Zeek JSON/TSV; canonical
  event model with deterministic ids; quarantine; source health; optional OpenSearch sink.
- Detection: 23 Sigma rules + 7 Sigma correlation rules, behavioral evaluators (new login source, DGA,
  IOC match), sensor pass-through, per-organization rule toggles, dry-run.
- Correlation into incidents with hub suppression and merging; explainable risk; deterministic promotion.
- MITRE ATT&CK v19.2 catalog and matrix; threat intel (feeds, watchlist, MISP).
- ML: Isolation Forest host baseline with explanations.
- Local AI analyst (Ollama) with evidence references, grounding validator, prompt-injection defences and
  an evaluation harness.
- Web UI, RBAC, multi-tenancy with PostgreSQL row-level security, append-only audit log, reports.
- Docker Compose with profiles, native setup scripts, Synthetic Demo Lab.
