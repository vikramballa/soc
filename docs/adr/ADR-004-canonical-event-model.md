# ADR-004: Canonical event model with deterministic ids

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
Wazuh, Suricata and Zeek emit different schemas; detection and correlation need one model.

## Decision
A flat canonical model (the core fields plus `event_action`, `outcome`, process/parent paths, bytes) validated by Pydantic. Event id = UUIDv5(tenant | source | native key). Raw events are preserved. Network events are attributed to hosts through the asset IP map.

## Consequences
Idempotent ingestion (replays are no-ops); Sigma field mapping is a small table; evidence links are stable.
