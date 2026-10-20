"""Built-in stateful evaluators that Sigma cannot express on a single event.

* ``sx-new-source-logon``  - successful login from a source never seen for that account (needs history)
* ``sx-dga-domain``        - DNS query for a high-entropy, algorithmically generated-looking domain
* ``sx-ioc-match``         - event observable matches a watchlist / threat-intel feed indicator
* ``sx-source-*``          - pass-through of native Suricata / Wazuh / Zeek detections not already
                             covered by a SentinelX rule
"""

from __future__ import annotations

import math
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.detection.alerts import AlertSpec, entities_from_event, observed_from_event
from sentinelx.domain.events import extract_indicators, is_private_ip
from sentinelx.persistence.models import Identity, Indicator, SecurityEvent

NEW_SOURCE_RULE = "sx-new-source-logon"
DGA_RULE = "sx-dga-domain"
IOC_RULE = "sx-ioc-match"
SURICATA_RULE = "sx-source-suricata"
WAZUH_RULE = "sx-source-wazuh"
ZEEK_RULE = "sx-source-zeek"

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
