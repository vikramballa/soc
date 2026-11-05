# Connecting telemetry

## Wazuh
Choose one:
- **Indexer polling (recommended):** create a read-only Wazuh indexer user with access to `wazuh-alerts-*`, set
  `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD`. SentinelX polls every ~10 s with
  `search_after` checkpoints (no gaps, no duplicates) and ingests alerts of level ≥ 3 as telemetry.
- **alerts.json tailing** (SentinelX on the Wazuh manager host): `WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json`.
- **Push** from Filebeat/Fluent Bit to `POST /api/v1/ingest/wazuh`.

Recommended Wazuh agent sources: Windows Security log (4624/4625/4720/4728/4732/4756/1102), Sysmon (events
1, 3, 22), Linux auth logs and sudo, syscheck (FIM). Native Wazuh alerts at or above `WAZUH_MIN_ALERT_LEVEL`
(default 10) that no SentinelX rule covers are passed through as alerts.

## Suricata
Enable EVE JSON with `alert, dns (version 3), http, tls, flow, fileinfo, ssh, anomaly`. Then either tail
(`SURICATA_EVE_PATH=/var/log/suricata/eve.json`) or ship with Fluent Bit (snippet in the app under
*Integrations*). Rotation and truncation are handled (inode + offset checkpoints).

## Zeek
JSON logs are preferred (`@load policy/tuning/json-logs.zeek` or `LogAscii::use_json=T`); the default TSV
format is also supported. Set `ZEEK_LOG_DIR` to the current log directory (conn, dns, http, ssl, ssh,
files, notice), or push with `?log_type=conn` etc.

## HTTP ingest API
`POST /api/v1/ingest/{wazuh|suricata|zeek|sentinelx}` with `Authorization: Bearer sxi_…` (create under
Administration → Ingest tokens). Body: JSON array, single object, NDJSON, or Zeek TSV. Limits: 10 MB and
5,000 events per request. Response: `accepted / duplicates / quarantined`. Malformed records are quarantined
(Integrations page) — never silently dropped.

## Asset context
Assets are discovered automatically. Set **criticality**, owner and environment on the Assets page — they
feed the risk score. Mark admin accounts as **privileged** on the Users page.

## Telemetry health (sensor tamper detection)
Every sender (Wazuh agent, Suricata or Zeek sensor) is tracked with its usual gap between deliveries.
Once a sender has at least 2 hours of history, a gap longer than `max(SILENCE_MIN_MINUTES, 6 × usual gap)`
raises **Telemetry Stopped Arriving**. It is raised to high when the host had a detection just before
going quiet. For planned work, mute the sender on the **Telemetry Health** page. Mutes are audited and
produce a low-severity platform alert.

## Canarytokens
Create an ingest token limited to the `canarytokens` source and set the Canarytokens webhook to
`https://<sentinelx>/api/v1/ingest/canarytokens?token=sxi_...`. Every trigger becomes a critical incident.
Built-in honeytokens (decoy accounts, hosts, IPs, files, credentials) are managed on the **Deception** page.

## Ingest token scope
Limit each token to the sources and networks it needs (Administration → Ingest tokens). A request outside
the scope is refused and raises **SentinelX Ingest Token Used Outside Its Scope**. The first use from a new
address raises a medium alert.
