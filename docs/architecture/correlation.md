# Correlation: from alerts to incidents

Correlation is the core SentinelX-owned component. It turns de-duplicated alerts into a small
number of incidents without gluing unrelated activity together.

## 1. Alert de-duplication (noise reduction, step 1)

Repeated hits of the same rule on the same entities within the window update **one** alert (event count,
first/last seen, observed values) instead of creating many. Keys:

| Detection type | De-duplication key |
|---|---|
| Sigma rule | rule + host (or source IP) + user |
| Sigma correlation | rule + group-by values |
| IOC match | indicator + host |
| DGA / ML | host |
| Sensor pass-through | signature + source + destination |

## 2. Sigma correlation rules (multi-event detections)

Building-block rules (e.g. *Failed Logon*) record lightweight `rule_matches`; correlation rules evaluate
them over a time span, grouped by fields — exactly the [Sigma correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html):

- `event_count` — e.g. ≥ 10 failed logons for one account on one host in 10 min (brute force)
- `value_count` — e.g. ≥ 20 distinct ports from one source to one target in 2 min (port scan)
- `temporal_ordered` — e.g. *brute force* followed by *successful logon* for the same user in 30 min

Correlations can reference other correlations (chaining); they are evaluated in dependency order.

## 3. Incident correlation

For each new alert:

1. **Entities** are extracted with weights: host, user, file hash → 1.0; external IP, domain → 0.6;
   internal IP → 0.4. If the alert has no known host, its *source* IP identifies the actor → 1.0.
2. **Candidates** are open incidents sharing at least one entity whose activity overlaps the alert within
   the correlation window (default 60 min, per-organization setting, 5 min – 24 h).
3. **Hub suppression**: an entity already present in ≥ 8 open incidents (DNS server, proxy, shared admin
   account) contributes 0. Organizations can list entities to always ignore (`ip:10.0.0.2`).
4. If the shared-entity weight reaches **1.0**, the alert joins the best (oldest) candidate; if it links
   several incidents, they are **merged** (alerts, entities and evidence move; the history records it).
5. Otherwise a new correlation group is opened.

A per-tenant PostgreSQL advisory lock serializes correlation, so concurrent workers never race.

## 4. Promotion policy (deterministic)

A correlation group becomes a visible **incident** when any of these holds:

- a non-ML detection with severity ≥ 70 (`INCIDENT_PROMOTE_SEVERITY`)
- risk score ≥ 50 (`INCIDENT_PROMOTE_RISK`) with at least one non-ML detection
- ≥ 2 distinct non-ML detections spanning ≥ 2 ATT&CK tactics

ML anomalies alone never promote unless `ML_ALONE_CAN_PROMOTE=true`. Non-promoted groups remain visible
via *Show low-signal groups* and are counted in the dashboard funnel.

## 5. Naming

Incidents are classified deterministically from ATT&CK techniques/tactics and detection types
(e.g. T1110 + T1078 → *Possible account compromise*; only discovery/reconnaissance → *Network
reconnaissance*) and titled with the primary user/host/source. Wording is deliberately cautious ("Possible…").
