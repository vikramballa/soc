# ADR-002: Integrate the open-source security stack instead of rebuilding it

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
Endpoint agents, IDS and network analysis are mature open-source products.

## Decision
Wazuh is the endpoint telemetry source (indexer polling, alerts.json tailing or push); Suricata EVE JSON is the network IDS source; Zeek JSON/TSV logs are the network visibility source. SentinelX never captures packets or runs agents itself. Sensors in the lab replay pcaps offline (works on Docker Desktop where containers cannot sniff host traffic).

## Consequences
Less code, trusted telemetry; SentinelX's value concentrates on normalization, correlation, risk and workflow.
