# ADR-007: Ollama for the local AI runtime; cloud models refused

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
Telemetry must not leave the customer's network; AI must not be a required dependency.

## Decision
Ollama HTTP API with JSON-schema structured output. Only locally installed models are selectable (models with `:cloud`/remote hosts are rejected). AI runs only on request in its own worker lane.

## Consequences
Private by default; works offline; quality depends on the chosen model, hence the validator and evaluation harness (ADR-011).
