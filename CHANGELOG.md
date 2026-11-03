# Changelog

## Unreleased
- Detection: Sigma v2 filters for per-organization exclusions without editing shared rules; a regression
  corpus (`security/detection-tests`) with true-positive and near-miss cases for every bundled rule.
- Interoperability (ADR-013): OCSF 1.3 export of incidents (Incident Finding) and alerts (Detection
  Finding, NDJSON); ATT&CK Navigator layers for rule coverage and observed techniques; TAXII 2.1 pulls.
- Threat intel: revoked/expired STIX indicators and non-STIX patterns are skipped, compound patterns are
  fully imported, and `valid_until` sets the indicator expiry.
- Supply chain: GitHub Actions pinned to commit SHAs (replacing the `trivy-action@0.28.0` tag affected by
  CVE-2026-33634), pip-audit and npm audit in CI, Dependabot, OpenSSF Scorecard; certifi, dnspython and
  opentelemetry-api upgraded past published advisories.
- Docs: AI analyst controls mapped to the OWASP Top 10 for LLM Applications (2026).
- Fix: the synthetic Zeek `conn.log` test fixture was excluded by `.gitignore`, breaking fresh clones.

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
