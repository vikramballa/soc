"""Built-in stateful evaluators that Sigma cannot express on a single event.

* ``sx-new-source-logon``  - successful login from a source never seen for that account (needs history)
* ``sx-new-host-logon``    - an account signs in over the network to a host it has never used (lateral)
* ``sx-dga-domain``        - DNS query for a high-entropy, algorithmically generated-looking domain
* ``sx-ioc-match``         - event observable matches a watchlist / threat-intel feed indicator
* ``sx-honeytoken``        - a decoy account, host, address, file or credential was touched
* ``sx-canarytoken``       - a Canarytokens tripwire fired
* ``sx-rare-*``            - first time this organization has ever seen a process lineage, TLS client
                             fingerprint or HTTP user agent (only once a baseline exists)
* ``sx-source-*``          - pass-through of native Suricata / Wazuh / Zeek detections not already
                             covered by a SentinelX rule

Periodic network/telemetry analytics (beaconing, DNS tunnelling, silence, alert storms) live in
``sentinelx.hunting``; their rule entries are listed here so they appear in the rule catalogue.
"""

from __future__ import annotations

import math
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, literal_column, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.detection.alerts import AlertSpec, entities_from_event, observed_from_event
from sentinelx.domain.events import extract_indicators, is_private_ip
from sentinelx.persistence.models import EntityPrevalence, Honeytoken, Identity, Indicator, SecurityEvent

NEW_SOURCE_RULE = "sx-new-source-logon"
DGA_RULE = "sx-dga-domain"
IOC_RULE = "sx-ioc-match"
SURICATA_RULE = "sx-source-suricata"
WAZUH_RULE = "sx-source-wazuh"
ZEEK_RULE = "sx-source-zeek"
NEW_HOST_RULE = "sx-new-host-logon"
HONEYTOKEN_RULE = "sx-honeytoken"
CANARY_RULE = "sx-canarytoken"
RARE_LINEAGE_RULE = "sx-rare-process-lineage"
RARE_TLS_RULE = "sx-rare-tls-fingerprint"
RARE_UA_RULE = "sx-rare-user-agent"
BEACON_RULE = "sx-beaconing"
DNS_TUNNEL_RULE = "sx-dns-tunnel"
SILENCE_RULE = "sx-telemetry-silence"
STORM_RULE = "sx-alert-storm"

# Deception and anti-tampering evaluators cannot be switched off per organization.
PROTECTED_BUILTINS = {HONEYTOKEN_RULE, CANARY_RULE, SILENCE_RULE, STORM_RULE}

BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "rule_uid": NEW_SOURCE_RULE,
        "title": "Login From a New Source Address",
        "level": "medium",
        "description": "A successful login came from an address never used by this account in the last 30 days. "
        "Only evaluated once the account has an established login history.",
        "techniques": ["T1078"],
        "falsepositives": ["Travel, new VPN exit node, new home network"],
    },
    {
        "rule_uid": DGA_RULE,
        "title": "Possible Algorithmically Generated Domain",
        "level": "medium",
        "description": "A DNS query for a domain whose name has very high character entropy and few vowels, "
        "typical of malware domain-generation algorithms (DGA).",
        "techniques": ["T1568.002"],
        "falsepositives": ["CDN or tracking domains with random-looking names"],
    },
    {
        "rule_uid": IOC_RULE,
        "title": "Known Malicious Indicator Observed",
        "level": "high",
        "description": "An IP address, domain, URL or file hash in the telemetry matches a threat-intelligence "
        "feed or analyst watchlist entry. Reputation alone is not proof of compromise.",
        "techniques": [],
        "falsepositives": ["Stale or overly broad feed entries"],
    },
    {
        "rule_uid": SURICATA_RULE,
        "title": "Suricata IDS Alert",
        "level": "medium",
        "description": "Native Suricata signature alert, passed through when no SentinelX rule already covers it.",
        "techniques": [],
        "falsepositives": ["Depends on the signature"],
    },
    {
        "rule_uid": WAZUH_RULE,
        "title": "Wazuh High-Level Alert",
        "level": "medium",
        "description": "Native Wazuh alert at or above the configured level, passed through when no SentinelX "
        "rule already covers it.",
        "techniques": [],
        "falsepositives": ["Depends on the Wazuh rule"],
    },
    {
        "rule_uid": "sx-ml-host-anomaly",
        "title": "Behavioral Anomaly (Isolation Forest)",
        "level": "low",
        "description": "A host-hour of activity departs strongly from the host population's learned baseline. "
        "Raises incident risk; never creates a serious incident on its own (deterministic policy).",
        "techniques": [],
        "falsepositives": ["New software rollout, unusual but legitimate workload"],
    },
    {
        "rule_uid": ZEEK_RULE,
        "title": "Zeek Notice",
        "level": "medium",
        "description": "Zeek notice framework event, passed through when no SentinelX rule already covers it.",
        "techniques": [],
        "falsepositives": ["Depends on the notice"],
    },
    {
        "rule_uid": NEW_HOST_RULE,
        "title": "Account Signed In to a Host It Has Never Used",
        "level": "medium",
        "description": "A network or remote-desktop logon from an internal address to a host this account has not "
        "signed in to in the last 30 days. Attackers moving laterally with stolen credentials produce exactly "
        "this pattern. Only evaluated for accounts with an established logon history.",
        "techniques": ["T1021", "T1078"],
        "falsepositives": ["New server assignment", "Helpdesk staff working on a new machine"],
    },
    {
        "rule_uid": HONEYTOKEN_RULE,
        "title": "Decoy (Honeytoken) Touched",
        "level": "critical",
        "description": "Telemetry references a decoy account, host, address, file or credential that nothing "
        "legitimate uses. Near-certain sign of an intruder exploring or using harvested credentials.",
        "techniques": [],
        "falsepositives": ["A decoy was placed somewhere routine tooling scans (e.g. an inventory job)"],
    },
    {
        "rule_uid": CANARY_RULE,
        "title": "Canarytoken Triggered",
        "level": "critical",
        "description": "A Canarytokens tripwire (URL, DNS name, document, cloud key...) was opened or used.",
        "techniques": [],
        "falsepositives": ["Mail or link scanners opening a token URL"],
    },
    {
        "rule_uid": RARE_LINEAGE_RULE,
        "title": "Process Lineage Never Seen Before",
        "level": "low",
        "description": "First time any host in this organization started this child process from this parent. "
        "A weak signal on its own that raises the risk of incidents it joins.",
        "techniques": ["T1059"],
        "falsepositives": ["New software installed or updated"],
    },
    {
        "rule_uid": RARE_TLS_RULE,
        "title": "TLS Client Fingerprint Never Seen Before",
        "level": "low",
        "description": "First appearance of a JA4/JA3 TLS client fingerprint in this organization. Custom implants "
        "and C2 frameworks often use TLS stacks no ordinary software here uses.",
        "techniques": ["T1573", "T1071.001"],
        "falsepositives": ["New browser or application version"],
    },
    {
        "rule_uid": RARE_UA_RULE,
        "title": "HTTP User Agent Never Seen Before",
        "level": "low",
        "description": "First appearance of an HTTP user-agent string in this organization.",
        "techniques": ["T1071.001"],
        "falsepositives": ["New software or update agents"],
    },
    {
        "rule_uid": BEACON_RULE,
        "title": "Possible Command-and-Control Beaconing",
        "level": "high",
        "description": "A host connects to the same destination at very regular intervals with consistent payload "
        "sizes over hours - the heartbeat of malware checking in with its operator. Scored on interval "
        "regularity, size regularity and persistence (inspired by the open-source RITA project).",
        "techniques": ["T1071", "T1573"],
        "falsepositives": ["Update checkers, monitoring agents and telemetry clients with fixed schedules"],
    },
    {
        "rule_uid": DNS_TUNNEL_RULE,
        "title": "Possible DNS Tunnelling",
        "level": "high",
        "description": "One host queried many unique, long subdomains of a single domain in a short time, "
        "consistent with data or commands being carried inside DNS queries.",
        "techniques": ["T1071.004", "T1048"],
        "falsepositives": ["Security products that use DNS for reputation lookups", "Some CDNs"],
    },
    {
        "rule_uid": SILENCE_RULE,
        "title": "Telemetry Stopped Arriving",
        "level": "medium",
        "description": "An agent or sensor that sends regularly has gone quiet for much longer than usual. "
        "Attackers stop or blind security agents before acting; raised to high when the silence follows a "
        "detection on the same host.",
        "techniques": ["T1685"],
        "falsepositives": ["Reboot, maintenance or network outage (mute the source for planned work)"],
    },
    {
        "rule_uid": STORM_RULE,
        "title": "Alert Storm",
        "level": "medium",
        "description": "Far more alerts than usual in a short period. Flooding a SOC with noise is a known way to "
        "bury a real intrusion; review what started the storm and what else happened during it.",
        "techniques": [],
        "falsepositives": ["A newly enabled noisy rule", "A real large-scale incident"],
    },
]

_TWO_LEVEL_SUFFIXES = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "org.uk", "ac.uk", "gov.uk", "com.cn"}
_VOWELS = set("aeiou")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def registrable_label(domain: str) -> str:
    labels = [x for x in domain.lower().strip(".").split(".") if x]
    if len(labels) < 2:
        return labels[0] if labels else ""
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


def dga_score(domain: str) -> tuple[bool, dict[str, float]]:
    """Heuristic DGA classifier: entropy + length + vowel/digit ratios of the registrable label."""
    label = registrable_label(domain)
    letters = [c for c in label if c.isalpha()]
    ent = shannon_entropy(label)
    vowel_ratio = (sum(c in _VOWELS for c in letters) / len(letters)) if letters else 0.0
    digit_ratio = sum(c.isdigit() for c in label) / len(label) if label else 0.0
    suspicious = len(label) >= 12 and ent >= 3.5 and (vowel_ratio < 0.25 or digit_ratio > 0.25)
    return suspicious, {
        "entropy": round(ent, 2),
        "length": len(label),
        "vowel_ratio": round(vowel_ratio, 2),
        "digit_ratio": round(digit_ratio, 2),
    }


def _spec(
    rule: dict[str, Any],
    ev: dict[str, Any],
    severity: int,
    key: str,
    window_s: int,
    title: str | None = None,
    extra: dict[str, Any] | None = None,
    techniques: list[str] | None = None,
) -> AlertSpec:
    return AlertSpec(
        rule_uid=rule["rule_uid"],
        title=title or rule["title"],
        description=rule["description"],
        source="source" if rule["rule_uid"].startswith("sx-source") else "builtin",
        severity=severity,
        dedup_key=f"{rule['rule_uid']}|{key}",
        window_s=window_s,
        first_ts=ev["timestamp"],
        last_ts=ev["timestamp"],
        event_ids=[ev["id"]],
        techniques=techniques if techniques is not None else list(rule["techniques"]),
        entities=entities_from_event(ev),
        source_types=[ev["source_type"]],
        details={"observed": observed_from_event(ev), **(extra or {})},
    )


_RULES = {r["rule_uid"]: r for r in BUILTIN_RULES}


async def evaluate_builtins(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    events: list[dict[str, Any]],
    sigma_matched: set[uuid.UUID],
    enabled: set[str],
) -> list[AlertSpec]:
    """Run every enabled built-in evaluator on a batch of events."""
    window = get_settings().correlation_window_minutes * 60
    specs = _sensor_passthrough(events, sigma_matched, enabled, window)
    if DGA_RULE in enabled:
        specs += _dga_domains(events, window)
    if IOC_RULE in enabled:
        specs += await _ioc_matches(session, tenant_id, events, window)
    if NEW_SOURCE_RULE in enabled:
        specs += await _new_login_sources(session, tenant_id, events, window)
    if NEW_HOST_RULE in enabled:
        specs += await _new_host_logons(session, tenant_id, events, window)
    if HONEYTOKEN_RULE in enabled:
        specs += await _honeytoken_hits(session, tenant_id, events, window)
    if CANARY_RULE in enabled:
        specs += _canarytoken_hits(events, window)
    specs += await _prevalence(session, tenant_id, events, enabled)
    return specs


def _sensor_passthrough(
    events: list[dict[str, Any]], sigma_matched: set[uuid.UUID], enabled: set[str], window: int
) -> list[AlertSpec]:
    """Native Suricata / Wazuh / Zeek detections that no SentinelX rule already covers."""
    min_wazuh_level = get_settings().wazuh_min_alert_level
    specs: list[AlertSpec] = []
    for ev in events:
        if ev["id"] in sigma_matched:
            continue
        source, rule_id = ev["source_type"], ev.get("rule_id")
        techniques = ev.get("mitre_techniques") or []
        if source == "suricata" and ev["event_type"] == "alert" and SURICATA_RULE in enabled:
            specs.append(
                _spec(
                    _RULES[SURICATA_RULE],
                    ev,
                    max(20, min(90, ev["severity"])),
                    f"{rule_id}|{ev.get('src_ip')}|{ev.get('dest_ip')}",
                    window,
                    title=f"Suricata: {ev.get('rule_name') or 'IDS alert'}",
                    extra={"signature_id": rule_id, "category": ev.get("event_category")},
                    techniques=techniques,
                )
            )
        elif source == "wazuh" and WAZUH_RULE in enabled:
            level = (ev.get("metadata") or {}).get("wazuh_level", 0)
            if level >= min_wazuh_level:
                specs.append(
                    _spec(
                        _RULES[WAZUH_RULE],
                        ev,
                        ev["severity"],
                        f"{rule_id}|{ev.get('hostname')}",
                        window,
                        title=f"Wazuh: {ev.get('rule_name') or 'alert'}",
                        extra={"wazuh_rule_id": rule_id, "wazuh_level": level},
                        techniques=techniques,
                    )
                )
        elif source == "zeek" and ev["event_type"] == "alert" and ZEEK_RULE in enabled:
            specs.append(
                _spec(
                    _RULES[ZEEK_RULE], ev, 50, f"{rule_id}|{ev.get('src_ip')}", window, title=f"Zeek notice: {rule_id}"
                )
            )
    return specs


def _dga_domains(events: list[dict[str, Any]], window: int) -> list[AlertSpec]:
    """DNS lookups for random-looking (algorithmically generated) domains."""
    specs: list[AlertSpec] = []
    for ev in events:
        if ev["event_type"] != "dns" or not ev.get("domain"):
            continue
        suspicious, features = dga_score(ev["domain"])
        if suspicious:
            who = ev.get("hostname") or ev.get("src_ip")
            specs.append(_spec(_RULES[DGA_RULE], ev, 45, f"{who}", window, extra={"dga_features": features}))
    return specs


async def _ioc_matches(
    session: AsyncSession, tenant_id: uuid.UUID, events: list[dict[str, Any]], window: int
) -> list[AlertSpec]:
    """Events containing an IP, domain, hash or URL from a threat feed or the watchlist."""
    events_by_value: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        for _, value in extract_indicators(ev):
            events_by_value[value].append(ev)
    if not events_by_value:
        return []
    now = datetime.now(UTC)
    indicators = await session.execute(
        select(Indicator).where(
            Indicator.tenant_id == tenant_id,
            Indicator.value.in_(list(events_by_value)),
            or_(Indicator.expires_at.is_(None), Indicator.expires_at > now),
        )
    )
    specs: list[AlertSpec] = []
    for ind in indicators.scalars():
        severity = int(50 + 40 * max(0.0, min(1.0, ind.confidence)))
        details = {
            "type": ind.type,
            "value": ind.value,
            "source": ind.source,
            "confidence": ind.confidence,
            "tags": ind.tags,
        }
        for ev in events_by_value[ind.value]:
            who = ev.get("hostname") or ev.get("src_ip")
            specs.append(
                _spec(
                    _RULES[IOC_RULE],
                    ev,
                    severity,
                    f"{ind.value}|{who}",
                    window,
                    title=f"Known malicious {ind.type} observed: {ind.value}",
                    extra={"indicator": details},
                )
            )
    return specs


async def _new_login_sources(
    session: AsyncSession, tenant_id: uuid.UUID, events: list[dict[str, Any]], window: int
) -> list[AlertSpec]:
    """Successful logins from an address the account has never used in the last 30 days.

    Only judged once the account has at least 3 earlier logins - without history every address is "new".
    """
    logins = [
        e
        for e in events
        if e["event_type"] in ("authentication", "ssh")
        and e.get("outcome") == "success"
        and e.get("username")
        and e.get("src_ip")
    ]
    if not logins:
        return []
    users = sorted({e["username"] for e in logins})
    earliest = min(e["timestamp"] for e in logins)
    history = await session.execute(
        select(SecurityEvent.username, SecurityEvent.src_ip, func.count())
        .where(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.username.in_(users),
            SecurityEvent.event_type.in_(["authentication", "ssh"]),
            SecurityEvent.outcome == "success",
            SecurityEvent.timestamp >= earliest - timedelta(days=30),
            SecurityEvent.timestamp < earliest - timedelta(seconds=1),
        )
        .group_by(SecurityEvent.username, SecurityEvent.src_ip)
    )
    known_sources: dict[str, set[str]] = defaultdict(set)
    login_counts: Counter[str] = Counter()
    for user, ip, count in history.all():
        if user is None:
            continue
        if ip:
            known_sources[user].add(ip)
        login_counts[user] += count
    privileged = set(
        (
            await session.execute(
                select(Identity.username).where(
                    Identity.tenant_id == tenant_id, Identity.username.in_(users), Identity.privileged.is_(True)
                )
            )
        ).scalars()
    )

    specs: list[AlertSpec] = []
    for ev in logins:
        user, ip = ev["username"], ev["src_ip"]
        if login_counts[user] < 3 or ip in known_sources[user]:
            continue
        severity = 45 + (0 if is_private_ip(ip) else 10) + (10 if user in privileged else 0)
        specs.append(
            _spec(
                _RULES[NEW_SOURCE_RULE],
                ev,
                severity,
                f"{user}|{ip}",
                window,
                title=f"Login from a new source address for {user}",
                extra={"baseline_logins": login_counts[user], "known_sources": sorted(known_sources[user])[:10]},
            )
        )
    return specs


# --- lateral movement ------------------------------------------------------------------------------

_REMOTE_LOGON_TYPES = {None, "", "3", "8", "9", "10"}


def _is_remote_logon(ev: dict[str, Any]) -> bool:
    """A successful logon recorded *on the target host* (Windows 4624, sshd) from somewhere else.

    Network-sensor events are excluded: their hostname is attributed from the client address, so it
    names the source of the logon, not its target."""
    meta = ev.get("metadata") or {}
    if ev.get("event_action") != "logon" or meta.get("hostname_source") == "asset_ip_map":
        return False
    return ev.get("outcome") == "success" and str(meta.get("logon_type") or "") in _REMOTE_LOGON_TYPES


async def _new_host_logons(
    session: AsyncSession, tenant_id: uuid.UUID, events: list[dict[str, Any]], window: int
) -> list[AlertSpec]:
    """Network logons from an internal address to a host the account has never signed in to."""
    logons = [
        e
        for e in events
        if e["event_type"] in ("authentication", "ssh")
        and e.get("username")
        and e.get("hostname")
        and e.get("src_ip")
        and is_private_ip(e["src_ip"])
        and not str(e["src_ip"]).startswith("127.")
        and e.get("src_ip") != e.get("host_ip")
        and e.get("event_category") != "sentinelx_platform"
        and _is_remote_logon(e)
    ]
    if not logons:
        return []
    users = sorted({e["username"] for e in logons})
    earliest = min(e["timestamp"] for e in logons)
    history = await session.execute(
        select(SecurityEvent.username, SecurityEvent.hostname, func.count())
        .where(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.username.in_(users),
            SecurityEvent.event_type.in_(["authentication", "ssh"]),
            SecurityEvent.outcome == "success",
            SecurityEvent.timestamp >= earliest - timedelta(days=30),
            SecurityEvent.timestamp < earliest - timedelta(seconds=1),
        )
        .group_by(SecurityEvent.username, SecurityEvent.hostname)
    )
    hosts_by_user: dict[str, set[str]] = defaultdict(set)
    total: Counter[str] = Counter()
    for user, host, n in history.all():
        if user is None:
            continue
        if host:
            hosts_by_user[user].add(host.lower())
        total[user] += n
    privileged = set(
        (
            await session.execute(
                select(Identity.username).where(
                    Identity.tenant_id == tenant_id, Identity.username.in_(users), Identity.privileged.is_(True)
                )
            )
        ).scalars()
    )
    specs: list[AlertSpec] = []
    for ev in logons:
        user, host = ev["username"], ev["hostname"]
        if total[user] < 5 or host.lower() in hosts_by_user[user]:
            continue
        specs.append(
            _spec(
                _RULES[NEW_HOST_RULE],
                ev,
                45 + (15 if user in privileged else 0),
                f"{user}|{host}",
                window,
                title=f"{user} signed in to {host} for the first time (from {ev['src_ip']})",
                extra={
                    "baseline_logins": total[user],
                    "known_hosts": sorted(hosts_by_user[user])[:10],
                    "logon_type": (ev.get("metadata") or {}).get("logon_type"),
                },
            )
        )
    return specs


# --- deception ----------------------------------------------------------------------------------------

_HONEYTOKEN_TECHNIQUES = {
    "account": ["T1078"],
    "credential": ["T1552.001", "T1078"],
    "host": ["T1018"],
    "ip": ["T1018"],
    "domain": ["T1018"],
    "file": ["T1083"],
    "url": [],
}


def honeytoken_matches(token: dict[str, Any], ev: dict[str, Any]) -> str | None:
    """Field of ``ev`` that touches the decoy, if any."""
    kind, value = token["kind"], str(token["value"]).lower()
    if not value:
        return None

    def low(k: str) -> str:
        v = ev.get(k)
        return str(v).lower() if v is not None else ""

    if kind == "account":
        target = str((ev.get("metadata") or {}).get("target_user") or "").lower()
        if low("username") == value or target == value:
            return "username"
        return "process_command_line" if value in low("process_command_line").split() else None
    if kind == "host":
        if low("hostname") == value or low("domain") == value or low("domain").startswith(value + "."):
            return "hostname"
        return None
    if kind == "ip":
        return next((f for f in ("src_ip", "dest_ip", "host_ip") if low(f) == value), None)
    if kind == "domain":
        d = low("domain")
        return "domain" if d and (d == value or d.endswith("." + value)) else None
    for f in ("file_path", "process_command_line", "url"):
        if value in low(f):
            return f
    return None


async def _honeytoken_hits(
    session: AsyncSession, tenant_id: uuid.UUID, events: list[dict[str, Any]], window: int
) -> list[AlertSpec]:
    tokens: list[dict[str, Any]] = [
        {"id": t.id, "kind": t.kind, "value": t.value, "description": t.description}
        for t in (
            await session.execute(
                select(Honeytoken).where(Honeytoken.tenant_id == tenant_id, Honeytoken.enabled.is_(True))
            )
        ).scalars()
    ]
    if not tokens:
        return []
    specs: list[AlertSpec] = []
    triggered: Counter[uuid.UUID] = Counter()
    for ev in events:
        if ev.get("event_category") == "sentinelx_platform":
            continue
        for tok in tokens:
            field_hit = honeytoken_matches(tok, ev)
            if field_hit is None:
                continue
            triggered[tok["id"]] += 1
            who = ev.get("hostname") or ev.get("src_ip") or "-"
            specs.append(
                _spec(
                    _RULES[HONEYTOKEN_RULE],
                    ev,
                    95,
                    f"{tok['id']}|{who}",
                    window,
                    title=f"Decoy {tok['kind']} '{tok['value']}' was touched",
                    extra={
                        "honeytoken": {
                            "kind": tok["kind"],
                            "value": tok["value"],
                            "field": field_hit,
                            "description": tok["description"],
                        }
                    },
                    techniques=_HONEYTOKEN_TECHNIQUES.get(tok["kind"], []),
                )
            )
    for tid, n in triggered.items():
        await session.execute(
            update(Honeytoken)
            .where(Honeytoken.id == tid)
            .values(last_triggered_at=datetime.now(UTC), trigger_count=Honeytoken.trigger_count + n)
        )
    return specs


def _canarytoken_hits(events: list[dict[str, Any]], window: int) -> list[AlertSpec]:
    specs: list[AlertSpec] = []
    for ev in events:
        if ev["source_type"] != "canarytokens":
            continue
        meta = ev.get("metadata") or {}
        specs.append(
            _spec(
                _RULES[CANARY_RULE],
                ev,
                95,
                f"{ev.get('rule_id')}|{ev.get('src_ip')}",
                window,
                title=ev.get("rule_name") or "Canarytoken triggered",
                extra={"canarytoken": {k: meta.get(k) for k in ("memo", "channel", "token_type", "user_agent")}},
            )
        )
    return specs


# --- prevalence (first seen in this organization) ----------------------------------------------------

_RARITY_KINDS = {
    "process_lineage": RARE_LINEAGE_RULE,
    "tls_fingerprint": RARE_TLS_RULE,
    "user_agent": RARE_UA_RULE,
}


def prevalence_keys(ev: dict[str, Any]) -> list[tuple[str, str]]:
    meta = ev.get("metadata") or {}
    out: list[tuple[str, str]] = []
    if ev["event_type"] == "process" and ev.get("process_name") and ev.get("parent_process_name"):
        out.append(("process_lineage", f"{ev['parent_process_name']} > {ev['process_name']}".lower()[:512]))
    for k in ("ja4", "ja3"):
        if isinstance(meta.get(k), str) and meta[k]:
            out.append(("tls_fingerprint", f"{k}:{meta[k].lower()}"[:512]))
            break
    ua = meta.get("user_agent")
    if ev["event_type"] == "http" and isinstance(ua, str) and ua.strip():
        out.append(("user_agent", ua.strip()[:512]))
    return out


async def _prevalence(
    session: AsyncSession, tenant_id: uuid.UUID, events: list[dict[str, Any]], enabled: set[str]
) -> list[AlertSpec]:
    """Record how common lineages / fingerprints / user agents are; alert on first sightings."""
    obs: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in events:
        if ev.get("event_category") == "sentinelx_platform":
            continue
        for key in prevalence_keys(ev):
            o = obs.setdefault(key, {"n": 0, "hosts": set(), "events": []})
            o["n"] += 1
            if ev.get("hostname") and len(o["hosts"]) < 10:
                o["hosts"].add(ev["hostname"])
            if len(o["events"]) < 10:
                o["events"].append(ev)
    if not obs:
        return []
    baselines = dict(
        (
            await session.execute(
                select(EntityPrevalence.kind, func.min(EntityPrevalence.first_seen))
                .where(EntityPrevalence.tenant_id == tenant_id)
                .group_by(EntityPrevalence.kind)
            )
        ).all()
    )
    rows = [
        {
            "id": uuid.uuid4(),
            "tenant_id": tenant_id,
            "kind": kind,
            "value": value,
            "seen_count": o["n"],
            "hosts": sorted(o["hosts"]),
        }
        for (kind, value), o in obs.items()
    ]
    new: set[tuple[str, str]] = set()
    for i in range(0, len(rows), 500):
        ins = pg_insert(EntityPrevalence).values(rows[i : i + 500])
        upsert = ins.on_conflict_do_update(
            index_elements=["tenant_id", "kind", "value"],
            set_={
                "last_seen": func.now(),
                "seen_count": EntityPrevalence.seen_count + ins.excluded.seen_count,
                "hosts": literal_column(
                    "CASE WHEN cardinality(entity_prevalence.hosts) >= 10 THEN entity_prevalence.hosts ELSE "
                    "coalesce((SELECT array_agg(h) FROM (SELECT DISTINCT h FROM "
                    "unnest(entity_prevalence.hosts || excluded.hosts) AS h LIMIT 10) AS x), '{}') END"
                ),
            },
        )
        result: Any = await session.execute(
            upsert.returning(EntityPrevalence.kind, EntityPrevalence.value, literal_column("(xmax = 0)"))
        )
        for kind, value, inserted in result.all():
            if inserted:
                new.add((kind, value))
    if not new:
        return []
    mature_before = datetime.now(UTC) - timedelta(days=get_settings().rarity_min_baseline_days)
    specs: list[AlertSpec] = []
    for kind, value in sorted(new):
        rule_uid = _RARITY_KINDS[kind]
        first = baselines.get(kind)
        if rule_uid not in enabled or first is None or first > mature_before:
            continue  # no baseline yet: everything is "new" while SentinelX is still learning
        o = obs[(kind, value)]
        ev = o["events"][0]
        spec = _spec(
            _RULES[rule_uid],
            ev,
            35,
            f"{value}",
            86400,
            title=f"{_RULES[rule_uid]['title']}: {value[:120]}",
            extra={"prevalence": {"kind": kind, "value": value, "hosts": sorted(o["hosts"])}},
        )
        spec.event_ids = [e["id"] for e in o["events"]]
        specs.append(spec)
    return specs
