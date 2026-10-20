# ADR-011: Evidence-grounding strategy for the AI analyst

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
LLMs fabricate and can be manipulated by attacker-controlled text.

## Decision
Minimum context with short evidence references; secret redaction; withholding of instruction-like fields; versioned prompt policy; schema validation; grounding validator (references, techniques, indicators, action claims, injection-aligned verdicts) with up to three attempts; full audit metadata; evaluation harness (`sentinelx ai-eval`).

## Consequences
Unsupported output is never shown as fact; some answers are rejected, which is the intended trade-off.
