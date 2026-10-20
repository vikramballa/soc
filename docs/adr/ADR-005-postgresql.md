# ADR-005: PostgreSQL for application state and as the default event store

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
OpenSearch is the usual choice for security telemetry, but small deployments must run on any laptop or small VM.

## Decision
PostgreSQL stores application state and normalized events (BRIN + composite indexes, bounded queries, retention job). Incident evidence is snapshotted so it survives retention. OpenSearch is an optional sink (ADR-006).

## Consequences
One required datastore, transactional detection/correlation. Very large telemetry volumes should enable the OpenSearch sink and shorter PostgreSQL retention.
