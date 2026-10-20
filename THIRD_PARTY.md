# Third-party components and licenses

SentinelX is Apache-2.0. It integrates with (network APIs / files — not linked into SentinelX):

| Component | License | Use |
|---|---|---|
| Wazuh | GPLv2 | Endpoint telemetry source |
| Suricata | GPLv2 | Network IDS telemetry source |
| Zeek | BSD-3-Clause | Network telemetry source |
| MISP | AGPLv3 | Optional threat-intel provider |
| OpenSearch | Apache-2.0 | Optional search sink |
| Keycloak | Apache-2.0 | Optional SSO |
| Ollama | MIT | Local LLM runtime (model licenses vary — check before commercial use) |
| PostgreSQL | PostgreSQL License | Database |
| Prometheus / Grafana | Apache-2.0 / AGPLv3 | Optional observability |

Bundled data:
- MITRE ATT&CK® (`security/mitre-data`) — © The MITRE Corporation, ATT&CK Terms of Use.
- SentinelX Sigma rules (`security/sigma-rules`) are original works under Apache-2.0. If you add SigmaHQ
  rules, respect the Detection Rule License (DRL 1.1, attribution required).

Libraries: Python dependencies are listed in `apps/api/pyproject.toml` / `uv.lock` (FastAPI MIT, SQLAlchemy
MIT, scikit-learn BSD-3, pySigma LGPL-2.1 — test-only, …); web dependencies in `apps/web/package.json`
(React MIT, TanStack Query MIT, lucide ISC, Tailwind MIT, Inter/JetBrains Mono OFL-1.1). Generate an SBOM
with `syft dir:. -o spdx-json` (also produced in CI).
