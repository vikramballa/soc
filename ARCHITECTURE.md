# SentinelX architecture

SentinelX is a **modular monolith** (ADR-001): one Python package (`apps/api/src/sentinelx`) that runs as the
API, as background workers, or both in one process, plus a React web UI served by the same process.

```
 Wazuh ───┐  indexer poll / alerts.json tail / HTTP push
 Suricata ┼──► Ingestion ──► Normalizer ──► security_events (PostgreSQL)  ──► optional OpenSearch sink
 Zeek ────┘    (validate, quarantine,     (canonical model,             │
                deterministic ids)         asset/identity discovery)    ▼ job queue (process_events)
                                                                    Detection engine
                                     Sigma rules · Sigma correlations · behavioral evaluators · sensor pass-through
                                                                         │ alerts (de-duplicated)
                                                                         ▼
                                                                Correlation engine ──► incidents
                                                   entity weights · hub suppression · merge · promotion policy
                                                                         │
                                   ┌────────────────┬────────────────────┼──────────────────┐
                                   ▼                ▼                    ▼                  ▼
                              Risk engine     MITRE ATT&CK        Threat intel        ML (Isolation Forest)
                              (explainable)   (rule-backed)   (local feeds, MISP)    (behavioral signal)
                                                                         │
                                                                         ▼
                                                     Evidence snapshots · timeline · reports
                                                                         │
                                                       AI analyst (Ollama, local) — on request,
                                                       grounded & validated, never required
```

## Source-of-truth boundaries

| Component | Role |
|---|---|
| Wazuh / Suricata / Zeek | Telemetry sources — never re-implemented |
| Sigma | Detection rule format (`security/sigma-rules`, versioned in DB) |
| MITRE ATT&CK | Technique taxonomy (official STIX data → `security/mitre-data`) |
| Threat intel | Indicator context (local feeds/watchlist, MISP) |
| ML | Behavioral anomaly *signal*; cannot create a serious incident alone |
| Ollama | Investigation assistant; cannot act, cannot change scores |
| PostgreSQL | Application state **and** default event store (ADR-005) |
| OpenSearch | Optional high-volume search sink (ADR-006) |
| SentinelX | Correlation, risk, incident workflow, analyst experience |

## Code map

| Path | Purpose |
|---|---|
| `ingestion/parsers/{wazuh,suricata,zeek}.py` | Native format → `CanonicalEvent` |
| `ingestion/pipeline.py` | Validation, quarantine, idempotent bulk insert, asset/identity upsert |
| `processing.py` | Runs on stored events: detection → correlation → threat-intel enrichment → risk |
| `ingestion/{tailer,wazuh_indexer,opensearch_sink}.py` | File tailing, indexer polling, search sink |
| `detection/sigma/` | Sigma loader, compiler (modifiers, conditions), correlation rules |
| `detection/{engine,builtin,alerts}.py` | Detection pipeline, stateful evaluators, alert de-duplication |
| `correlation/{engine,incidents}.py` | Alert→incident correlation; incident builder (risk, evidence, promotion) |
| `risk/engine.py` | Transparent risk model |
| `threat_intel/` | Provider abstraction, local + MISP providers, feed import |
| `ml/` | Feature extraction (SQL), Isolation Forest, explanations |
| `ai/` | Context builder, sanitization, prompt policy, Ollama client, grounding validator, evaluation |
| `jobs/` | PostgreSQL job queue + worker (lanes, scheduler, heartbeat) |
| `api/` | FastAPI routers, auth/RBAC dependencies, schemas |
| `security/` | Passwords, RBAC, OIDC, rate limiting |
| `persistence/` | ORM models, tenant-scoped sessions (RLS) |
| `services/` | Audit trail, first-run bootstrap, retention, dashboard figures |
| `apps/api/tests/` | unit · integration · security · e2e tests; `fixtures/` holds synthetic Wazuh/Suricata/Zeek samples |
| `apps/web/src` | React UI (pages, components) |

## Request & data flow

1. **Ingestion** (`POST /api/v1/ingest/{source}`, tailers, indexer poll) parses each record; failures go to
   `quarantined_events`. Event ids are `uuid5(tenant | source | native key)` — replays are no-ops.
2. New event ids are queued as a `process_events` job (PostgreSQL `jobs` table, `LISTEN/NOTIFY` wake-up).
3. The worker takes a per-tenant advisory lock and runs detection → correlation → local TI enrichment →
   risk recompute in one transaction. Typical latency on a laptop: tens of milliseconds per batch.
4. Incidents are **promoted** (shown to people) only by deterministic policy: a high-severity detection, a
   risk score over the threshold, or several detections across ATT&CK tactics. Everything else stays a
   low-signal correlation group (counted in the noise-reduction funnel).
5. Evidence is **snapshotted** into `incident_evidence`, so incidents stay explainable after raw telemetry
   ages out of retention.
6. The AI analyst runs only on request, in a separate worker lane, with no database transaction held open.

## Tenancy & security

Every tenant-owned table has `tenant_id` + a PostgreSQL RLS policy (`FORCE ROW LEVEL SECURITY`). Each
request/job transaction sets `app.tenant_id`; queries additionally filter on tenant explicitly. The app
connects with a non-superuser role (superusers bypass RLS — `sentinelx doctor` checks this). See
[docs/security/threat-model.md](docs/security/threat-model.md).

## Performance notes

- Sigma rules are compiled once into Python predicates and indexed by event type; common wildcard shapes
  use plain string operations instead of regular expressions.
- Inserts are multi-row `INSERT … ON CONFLICT DO NOTHING RETURNING` in 500-row chunks.
- Correlation uses an indexed `(tenant, kind, value)` entity table; Sigma correlations query an indexed
  `rule_matches` table with short retention.
- Event search is bounded by time range with keyset pagination; counts are capped.
- The UI is code-split per page (~80 KB gzipped initial JS) and served with immutable caching.
