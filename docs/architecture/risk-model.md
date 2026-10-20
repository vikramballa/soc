# Risk model

`Risk = Σ capped contributors`, clipped to 0–100. Every contributor is stored with its value,
cap and reason and shown on the incident page. **Weights are SentinelX product decisions, not an industry
standard** — they live in `apps/api/src/sentinelx/risk/engine.py` and are covered by unit tests.

| Contributor | Max | Computation |
|---|---|---|
| Detection severity | 30 | 0.30 × highest non-ML alert severity (0–100) |
| Event volume | 10 | 2 × log2(1 + evidence events) |
| Asset criticality | 10 | criticality 1→0, 2→2.5, 3→5, 4→7.5, 5→10 |
| User context | 10 | +6 privileged account involved, +4 login from a never-seen source |
| Threat intelligence | 20 | 20 × confidence of the strongest match (malicious ×1, suspicious ×0.5) |
| Correlation strength | 15 | 4 × (distinct detections − 1) + 3 × (distinct telemetry sources − 1) |
| Behavioral anomaly | 10 | 10 × highest ML anomaly score on affected hosts during the incident |
| ATT&CK stage | 10 | highest tactic weight (impact/exfiltration 10, C2/credential access/lateral movement 8 …) |

Caps sum to 115, so several strong, independent signals saturate at 100 while one signal alone cannot.

## Bands (UI categories, not a standard)

| Score | Band |
|---|---|
| 0–25 | Informational |
| 26–50 | Low |
| 51–75 | Medium |
| 76–90 | High |
| 91–100 | Critical |

## Confidence

A separate, deterministic heuristic (0.05–0.95): base 0.35, +0.15 per additional independent telemetry
source (max 2), +0.08 per additional distinct detection (max 3), +0.10 if threat intelligence corroborates,
−0.15 if based only on a behavioral anomaly. Factors are listed on the incident.

## Manipulation resistance

Scores come only from deterministic inputs: the AI cannot change them; ML is capped at 10 points; threat
intel at 20 and weighted by provider confidence; asset criticality is set by people, not telemetry.
