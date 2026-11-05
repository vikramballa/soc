"""Canarytokens (Thinkst, open source, self-hostable) webhook alerts -> canonical events.

A canarytoken is a tripwire: a URL, DNS name, document, AWS key or similar placed where only an
intruder would touch it. Any trigger is therefore treated as high-confidence evidence.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sentinelx.domain.events import CanonicalEvent, deterministic_event_id, parse_timestamp


class ParseError(ValueError):
    pass


def _time(value: Any) -> datetime:
    if not value:
        return datetime.now(UTC)
    s = str(value).replace("(UTC)", "").strip()
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return parse_timestamp(s)


def parse(rec: dict[str, Any], tenant_id: uuid.UUID) -> CanonicalEvent:
    if not any(k in rec for k in ("token", "manage_url", "memo")):
        raise ParseError("not a canarytokens alert: missing token/memo")
    extra = rec.get("additional_data") or {}
    if not isinstance(extra, dict):
        extra = {}
    src_ip = rec.get("src_ip") or extra.get("src_ip")
    memo = str(rec.get("memo") or "canarytoken")[:500]
    channel = rec.get("channel")
    token_type = rec.get("token_type") or (rec.get("additional_data") or {}).get("token_type")
    ts = _time(rec.get("time"))
    native = hashlib.sha256(
        json.dumps([rec.get("token"), rec.get("time"), src_ip, channel], default=str).encode()
    ).hexdigest()
    ev = CanonicalEvent(
        event_id=deterministic_event_id(tenant_id, "canarytokens", native),
        tenant_id=tenant_id,
        timestamp=ts,
        source_type="canarytokens",
        event_type="alert",
        event_action="canarytoken_triggered",
        severity=95,
        src_ip=src_ip,
        rule_id=str(rec.get("token") or "")[:64] or None,
        rule_name=f"Canarytoken triggered: {memo}",
        event_category="deception",
        raw_event=rec,
        metadata={
            "memo": memo,
            "channel": channel,
            "token_type": token_type,
            "user_agent": extra.get("useragent") or rec.get("useragent"),
            "manage_url_present": bool(rec.get("manage_url")),
        },
    )
    ev.summary = (
        f"Canarytoken '{memo}' triggered"
        + (f" from {src_ip}" if src_ip else "")
        + (f" via {channel}" if channel else "")
    )
    return ev
