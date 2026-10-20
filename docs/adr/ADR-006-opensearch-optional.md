# ADR-006: OpenSearch as optional high-volume search sink

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
Large tenants need long-range hunting over high event volumes.

## Decision
When `OPENSEARCH_URL` is set, accepted events are bulk-indexed into daily `sentinelx-events-*` indices with a typed template; every document carries `tenant_id`, and any search over these indices (e.g. from OpenSearch Dashboards) must filter on it — give each organization its own OpenSearch role restricted to its `tenant_id` (document-level security). Failures never block ingestion.

## Consequences
PostgreSQL remains the system of record for detection and evidence; OpenSearch adds scale for search.
