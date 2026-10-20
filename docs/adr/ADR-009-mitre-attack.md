# ADR-009: MITRE ATT&CK from official STIX data

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
Technique mappings must be accurate and current.

## Decision
`scripts/build_mitre_dataset.py` derives a compact dataset from the official enterprise STIX bundle (currently v19.2, where defense-evasion is split into stealth and defense-impairment). Techniques on incidents come only from rule tags/sensor metadata validated against the catalog; AI suggestions are labelled hypotheses.

## Consequences
No invented technique ids; refresh is one command.
