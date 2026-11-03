# ADR-013: Exchange data through open standards (OCSF, ATT&CK Navigator, TAXII, Sigma filters)

- **Status:** Accepted
- **Date:** 2026-11-03

## Context
SentinelX is usually one tool among several: findings have to reach a SIEM, data lake, SOAR or ticketing
system; detection coverage is reviewed against threat reports; threat intel arrives from sharing
communities; and every organization needs to tune shared rules without forking them. Each of these has
an open, vendor-neutral standard that most tools already speak:

- **OCSF** (Open Cybersecurity Schema Framework, Linux Foundation): the common schema for security events
  and findings, natively supported by major SIEM, cloud and data-lake products.
- **ATT&CK Navigator layers**: the format teams use to share and compare technique coverage.
- **TAXII 2.1 / STIX 2.1** (OASIS): the transport and format of most threat-intel sharing.
- **Sigma v2 filters**: the Sigma specification's way of adding local exclusions to shared rules.

Custom formats or per-tool connectors would mean one integration per tool and per version.

## Decision
1. **OCSF is an export view, not the internal model.** The canonical event model (ADR-004) stays the
   source of truth. Alerts export as *Detection Finding* (class 2004, NDJSON for pipelines) and incidents
   as *Incident Finding* (class 2005), targeting OCSF 1.3. Values without an OCSF attribute (risk score
   breakdown, promotion reason) go under `unmapped.sentinelx`, so nothing is silently dropped.
2. **Navigator layers** (layer format 4.5) are generated for enabled-rule coverage and for observed
   techniques. Exports only contain technique ids present in the current ATT&CK catalog.
3. **TAXII 2.1** is pulled from one collection configured by the administrator (environment, never request
   input), through the existing integration-URL SSRF guard, with incremental cursors and hard page and
   object limits. STIX indicators that are revoked, expired or use another pattern language are skipped.
   Indicators feed the existing local provider; reputation stays context, not proof.
4. **Sigma filters** are compiled like rules and ANDed onto the rules they reference. They are versioned,
   switchable per organization, and visible on both the filter and the rule, so an exclusion is never
   hidden from analysts.
5. Exports are read-only and audited; they require `report:generate` (incidents/alerts) or the read
   permission of the data they summarize (layers).

## Consequences
- Findings, coverage and intel move to and from other tools without SentinelX-specific connectors.
- OCSF mapping must be revisited when the schema version is raised; `OCSF_VERSION` in
  `export/ocsf.py` is the single place that declares it.
- TAXII pulls are on request (one button / one API call). A scheduled pull can be added to the job
  scheduler later without changing the client.
- Response automation standards (OASIS CACAO, OpenC2) were considered and **not** adopted for execution:
  SentinelX never runs remote commands. CACAO may later be supported as an import format that produces
  tasks and notes only.
