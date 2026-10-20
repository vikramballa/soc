# Behavioral analytics (ML)

Additive to rules: ML raises risk and surfaces unusual behaviour; it never closes, suppresses
or (by default) creates a serious incident on its own.

## Features (per host, per hour — computed in SQL)

events, failed / successful logins, distinct users, process starts, distinct programs, PowerShell starts,
DNS queries, distinct domains, connections, distinct destination IPs / ports, connections on unusual ports,
bytes sent, file changes. Counts are `log1p`-transformed (telemetry is heavy-tailed).

## Model

- `IsolationForest(n_estimators=200, contamination="auto")` per organization, retrained daily on the last
  14 days, versioned in `ml_models` (artifact, parameters, metrics, baseline medians).
- **Poisoning resistance**: host-hours that contain incident evidence are excluded from training.
- Minimum baseline: 24 host-hours; otherwise the UI explains that a baseline is still being built.

## Score and explanation

`anomaly_score = 0.5 × isolation percentile + 0.5 × deviation score`, where the deviation score is
`1 − exp(−(z_max − 2)/3)` from the largest **robust z-score** (median/MAD, scale floored at 0.5 on the log
scale) of any feature *above* its baseline. A window is flagged when the score ≥ 0.80 **and** a feature is
≥ 4 robust σ above normal. Rationale:

- the isolation percentile alone was unstable on small baselines (near-empty hours look "rare");
- only *increases* matter for security — an unusually quiet hour is not a threat;
- the z-scores give a human explanation: "failed logins: 43 (usually ~0)".

Flagged hours become low-severity *Behavioral anomaly* alerts linked to the events behind the top
deviating features, and add up to 10 risk points to overlapping incidents.

## Evaluation

`tests/unit/test_risk_ml_ti.py::test_isolation_forest_ranks_abnormal_above_normal` checks ranking quality
(ROC-AUC > 0.95 on synthetic data) and that explanations name the injected features; the end-to-end test
checks the Demo Lab anomaly is detected while benign noise is not.
