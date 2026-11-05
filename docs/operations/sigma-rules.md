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

## Importing SigmaHQ rules
SentinelX does not download anything itself. Clone the community repository and import from it:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma ~/src/sigma
cd apps/api
PYTHONPATH=src uv run --no-sync python -m sentinelx.cli sigma-import ~/src/sigma/rules/windows \
  --min-status test --min-level high --dry-run      # report only
PYTHONPATH=src uv run --no-sync python -m sentinelx.cli sigma-import ~/src/sigma/rules/windows --min-level high
```

Each rule is compiled by the same in-process compiler as the bundled rules. Rules that need unsupported
log sources or modifiers are reported, never half-imported. Imported rules become custom rules with an
attribution header (Detection Rule License 1.1) and a `source.sigmahq` tag. Re-running the command
updates changed rules and skips unchanged ones. Use `--disabled` to import everything switched off and
enable rules after review.

Windows fields that have no explicit mapping fall back to the original EventData field that Wazuh ships
(`ScriptBlockText` → `data.win.eventdata.scriptBlockText`), so most Windows rules work unchanged.

## Tamper-protection rules
Rules under `platform/` (logsource `product: sentinelx_platform`) watch SentinelX itself: rules switched
off, administrator roles granted, ingest tokens misused, two-step verification removed, the audit chain
broken. They, and the honeytoken, Canarytokens, telemetry-silence and alert-storm built-ins, cannot be
disabled per organization, because disabling the alarm is the first thing an intruder in the console would do.

## Proving detections: adversary replay
`security/attack-replay/*.json` holds synthetic attack telemetry for each covered technique, in native
Wazuh, Zeek, Suricata or Canarytokens format, together with the rule titles that must fire. Every test
run replays them through the real pipeline (`tests/e2e/test_attack_replay.py`), and so does
`sentinelx validate-detections`. When you add a detection for a new technique, add a scenario; the
ATT&CK page then marks the technique as proven.
