# Changelog

## 0.2.0 — 2026-11-05
Hardening against skilled attackers. An intruder who knows the usual detections avoids the
signatures, blinds the sensors, and goes after the SOC console itself; this release adds signals for
each of those moves.

**Protecting SentinelX itself**
- Least-privilege database roles (ADR-013): migrations run as `sentinelx_owner` and the app role owns
  nothing, so it cannot disable the audit triggers or row-level security. Existing installs:
  `PGUSER=<superuser> ./scripts/harden-db.sh`. Docker users add `SENTINELX_OWNER_DB_PASSWORD`; a new
  data volume creates both roles, and an existing volume is converted with `harden-db.sh`.
- Tamper-evident audit trail: every record is hash-chained; `sentinelx audit-verify`, an hourly
  check, and a status line in Administration → Audit log.
- Two-step verification (TOTP, recovery codes, replay protection). It is required for admins in
  production (`MFA_REQUIRED_FOR_ADMINS`), and admins can reset it for a user who lost their phone.
- Step-up re-authentication: changing rules, roles, settings, tokens, decoys or telemetry mutes needs
  a password check from the last 15 minutes, so a stolen session cookie alone is not enough.
- Ingest tokens can be limited to sources and networks. Out-of-scope use and use from a new address
  raise alerts.
- Self-monitoring: sign-ins, wrong second factors, rule changes, role grants, token use, decoy and mute
  changes become `sentinelx_platform` events, and 14 new rules watch them. These tamper rules cannot
  be switched off.
- Rule files added by an upgrade are now registered at startup. Previously they stayed inactive until
  someone ran `sentinelx sync-rules`.

**Detecting attackers who avoid signatures**
- Beacon scoring in the style of RITA: interval regularity and symmetry, persistence, payload size.
- DNS tunnelling: many long, unique subdomains of one domain from one host.
- Telemetry silence: per-agent/sensor cadence; an alert when a sender goes quiet, raised to high when
  the silence follows a detection on that host; maintenance mutes; a new Telemetry Health page.
- Alert storms (flooding the SOC to bury the real intrusion).
- First-seen signals: process lineage, JA4/JA3 TLS fingerprints, HTTP user agents (once a 7-day
  baseline exists). They only raise risk and never promote an incident on their own.
- Lateral movement: first network logon by an account to a host it has never used.
- Deception: honeytokens (accounts, hosts, IPs, DNS names, files, credentials, URLs) and a
  Canarytokens webhook source. Any touch is a critical incident.
- Risk: new "attack progression" contributor for incidents that span several intrusion phases.

**Detection content and proof**
- 58 new Sigma rules (79 detections + 9 correlations in total, up from 23 + 7). They cover Kerberoasting,
  AS-REP roasting, DCSync (event log and network), LSASS access, SAM/NTDS theft, PsExec/WMI/WinRM/
  admin-share lateral movement, pass-the-hash, persistence (tasks, Run keys, services, WMI, cron,
  systemd, SSH keys, launch agents, web shells), defense impairment (security agents stopped,
  Defender off, logs cleared, Sysmon unloaded, auditd off, history cleared, firewall off), LOLBins,
  reverse shells, download cradles, rclone exfiltration, tunnels and remote-access tools.
- Parsers: Zeek `kerberos`, `ntlm`, `smb_mapping`, `smb_files`, `dce_rpc`, `rdp`; JA4 from Zeek and
  Suricata; Windows 4768/4769/4662/7045/4698/4104 and Sysmon 7/8/10/11/12-14. **Fix:** Sysmon file,
  registry and image-load events were being filed as process starts.
- Sigma fields without a mapping fall back to the original Windows EventData field, so SigmaHQ rules
  work on Wazuh data. `sentinelx sigma-import <dir>` imports community rules with validation and
  DRL 1.1 attribution.
- Adversary replay: 24 synthetic attack scenarios (`security/attack-replay`) run through the real
  pipeline in CI and in `sentinelx validate-detections`. The ATT&CK page marks techniques proven by a
  replay test.

## 0.1.0 — 2026-10-06
First release.
- Ingestion: Wazuh (indexer polling, alerts.json, push), Suricata EVE JSON, Zeek JSON/TSV; canonical
  event model with deterministic ids; quarantine; source health; optional OpenSearch sink.
- Detection: 23 Sigma rules + 7 Sigma correlation rules, behavioral evaluators (new login source, DGA,
  IOC match), sensor pass-through, per-organization rule toggles, dry-run.
- Correlation into incidents with hub suppression and merging; explainable risk; deterministic promotion.
- MITRE ATT&CK v19.2 catalog and matrix; threat intel (feeds, watchlist, MISP).
- ML: Isolation Forest host baseline with explanations.
- Local AI analyst (Ollama) with evidence references, grounding validator, prompt-injection defences and
  an evaluation harness.
- Web UI, RBAC, multi-tenancy with PostgreSQL row-level security, append-only audit log, reports.
- Docker Compose with profiles, native setup scripts, Synthetic Demo Lab.
