# Threat intelligence

- **Watchlist:** add IPs, domains, hashes or URLs (Threat Intel → Add indicator, or *Watch IOC* on an
  incident). Optional expiry.
- **Feeds:** Threat Intel → Import feed — plain text (one per line, `#` comments), CSV (`value` column plus
  optional type/confidence/verdict/tags/description) or STIX 2.1 bundles. Use only feeds whose license
  permits your use (e.g. abuse.ch terms, commercial use restrictions).
- **TAXII 2.1:** set `TAXII_COLLECTION_URL` (the collection URL, e.g.
  `https://taxii.example/api1/collections/<id>`) and either `TAXII_USERNAME`/`TAXII_PASSWORD` or
  `TAXII_API_TOKEN`. Threat Intel → Sources then shows **Pull new indicators** (requires
  `threatintel:manage`, recorded in the audit log). Pulls are incremental per organization; revoked and
  expired STIX indicators and non-STIX patterns (Snort, YARA) are skipped, and `valid_until` becomes the
  indicator's expiry. A pull reads at most 50 pages / 100,000 objects; pull again to continue.
- **MISP:** set `MISP_URL` and `MISP_API_KEY`; lookups use `/attributes/restSearch` with warning lists,
  results are cached for `TI_CACHE_HOURS` (24 h). `to_ids` attributes count as malicious (0.8), others as
  suspicious (0.5).

Every new event is checked against indicators (*Known malicious indicator observed* alerts), and every
incident's external IPs, domains and hashes are enriched. Reputation is shown with its source and
confidence and capped in the risk score — it is context, not proof.
