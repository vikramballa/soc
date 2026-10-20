# ADR-001: Modular monolith first

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
SentinelX must be easy to run for small teams on one machine, yet able to grow.

## Decision
One Python package with clear internal modules (ingestion, detection, correlation, risk, threat_intel, ml, ai, api, jobs). The same code runs as API, worker, or both in one process (`EMBEDDED_WORKER`).

## Consequences
One deployable artifact; simple local runs; modules can be extracted later along existing boundaries. Scaling is horizontal by running more worker processes against the same database.
