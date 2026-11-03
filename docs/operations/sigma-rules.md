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

## Filters (local exclusions)
Use a [Sigma v2 filter](https://sigmahq.io/sigma-specification/) to exclude known-benign activity from a
rule without editing the rule itself, so bundled rules stay generic and upgradeable:

```yaml
title: Ignore certutil downloads by the patching account
id: 7d0c1e2a-1b2c-4d3e-8f90-1122334455f1
logsource: {category: process_creation, product: windows}
filter:
  rules:
    - 7d0c1e2a-1b2c-4d3e-8f90-112233445566   # rule id or name; several allowed
  selection:
    User|endswith: '\svc_patch'
  condition: not selection
```

The filter's condition is ANDed onto each referenced rule. A filter is rejected as a whole if a reference
is unknown, points at a correlation rule, or its `logsource` contradicts the rule's. Filters are versioned
like rules, can be added as custom rules, and are switchable per organization. Turning one off makes the
rule see the excluded events again immediately. The rule's detail page lists the filters applied to it.

## Detection tests
Every bundled rule needs test cases in `security/detection-tests/cases.yml`: at least one event it must
fire on (`match`) and one realistic near-miss it must ignore (`no_match`), written with canonical field
names. `make test` runs them through the production compiler and fails on a rule without cases, so a change
that silently stops detecting, or starts firing on benign activity, is caught before release.

## Tuning
Open a rule → **Dry-run on last 24h** to see how often it would fire and on which hosts. Disable noisy
rules per organization with the toggle, or add the source to *Never correlate on* in organization settings.
Always add `falsepositives` — they are shown to analysts.
