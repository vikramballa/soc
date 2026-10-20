# Changelog

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
