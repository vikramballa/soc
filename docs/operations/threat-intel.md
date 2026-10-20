# Threat intelligence

- **Watchlist:** add IPs, domains, hashes or URLs (Threat Intel → Add indicator, or *Watch IOC* on an
  incident). Optional expiry.
- **Feeds:** Threat Intel → Import feed — plain text (one per line, `#` comments), CSV (`value` column plus
  optional type/confidence/verdict/tags/description) or STIX 2.1 bundles. Use only feeds whose license
  permits your use (e.g. abuse.ch terms, commercial use restrictions).
- **MISP:** set `MISP_URL` and `MISP_API_KEY`; lookups use `/attributes/restSearch` with warning lists,
  results are cached for `TI_CACHE_HOURS` (24 h). `to_ids` attributes count as malicious (0.8), others as
  suspicious (0.5).

Every new event is checked against indicators (*Known malicious indicator observed* alerts), and every
incident's external IPs, domains and hashes are enriched. Reputation is shown with its source and
confidence and capped in the risk score — it is context, not proof.
