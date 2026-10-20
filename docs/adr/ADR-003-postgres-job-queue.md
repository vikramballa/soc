# ADR-003: PostgreSQL job queue instead of a separate broker

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
Workers are needed for detection, enrichment, ML and AI; small deployments should not need Redis/RabbitMQ.

## Decision
`jobs` table claimed with `FOR UPDATE SKIP LOCKED`, `LISTEN/NOTIFY` wake-ups, retries with exponential backoff, dedup keys and once-per-period schedules. Two lanes: fast (detection, enrichment, ML) and AI (one slot) so slow LLM calls never delay detection. A per-tenant advisory lock serializes correlation.

## Consequences
One fewer service; transactional enqueue with the data it refers to. At very high throughput a dedicated broker may be introduced behind the same `enqueue` interface.
