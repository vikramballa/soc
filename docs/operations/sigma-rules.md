# Detection rules (Sigma)

Rules live in `security/sigma-rules/<area>/*.yml` and follow the
[Sigma specification](https://sigmahq.io/sigma-specification/). After editing, a super-admin clicks
**Reload from repository** (or run `sentinelx sync-rules`); each change creates a new rule version.

## Field names
Use standard Sigma taxonomy fields — they are mapped to canonical fields:
`Image→process_path`, `CommandLine→process_command_line`, `ParentImage→parent_process_path`,
`TargetUserName/User→username`, `IpAddress/SourceIp→src_ip`, `DestinationIp→dest_ip`,
`DestinationPort→dest_port`, `QueryName→domain`, `TargetFilename→file_path`, `EventID→metadata.windows_event_id`,
`c-useragent→metadata.user_agent`. Canonical names (`event_action`, `outcome`, `hostname` …) work directly.

## Log sources
`category`: process_creation, network_connection, dns / dns_query, file_change / file_event,
authentication (SentinelX), user_management (SentinelX), webserver / proxy, ids_alert.
`product`: windows / linux / macos (matched against host OS when known), zeek / suricata / wazuh (source).

## Supported modifiers
`contains, startswith, endswith, all, re (+i/m/s), cidr, gt, gte, lt, lte, exists, windash, cased`.
Conditions: `and, or, not, ( ), 1 of x*, any of, all of x*, them`. Anything else is rejected at load time
(listed on the Detection Rules page) instead of silently never matching.

## Correlation rules
`event_count`, `value_count`, `temporal`, `temporal_ordered` with `group-by` and `timespan`. Referenced
building-block rules default to `generate: false` (they feed the correlation without alerting).

## Tuning
Open a rule → **Dry-run on last 24h** to see how often it would fire and on which hosts. Disable noisy
rules per organization with the toggle, or add the source to *Never correlate on* in organization settings.
Always add `falsepositives` — they are shown to analysts.
