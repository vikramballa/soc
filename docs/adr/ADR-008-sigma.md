# ADR-008: Sigma as the rule format with an in-process evaluator

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
pySigma converts rules to backend query languages; SentinelX needs to evaluate rules on events as they stream in.

## Decision
Rules are standard Sigma YAML (validated against pySigma in tests). SentinelX compiles the detection logic into Python predicates (modifiers, wildcards, conditions) with a field-mapping table from Sigma taxonomy to canonical fields, and implements Sigma correlation rules (event_count, value_count, temporal, temporal_ordered). Unsupported constructs are rejected loudly at load time.

## Consequences
Portable rules, low latency, no external engine. Only the documented subset of modifiers is supported.
