"""Threat-intel enrichment with caching, and feed import."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.persistence.models import Indicator, ThreatIntelResult
from sentinelx.threat_intel.providers import LocalIndicatorProvider, TIResult, configured_providers

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$", re.I)


def classify_indicator(value: str) -> str | None:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(v):
        return "hash"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


def normalize_indicator(itype: str, value: str) -> str:
    v = value.strip()
    if itype in ("domain", "hash"):
        return v.lower().rstrip(".")
    if itype == "ip":
        return str(ipaddress.ip_address(v))
    return v


async def _store(session: AsyncSession, tenant_id: uuid.UUID, r: TIResult) -> None:
    values = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "indicator_type": r.indicator_type,
        "value": r.value,
        "provider": r.provider,
        "verdict": r.verdict,
        "confidence": r.confidence,
        "tags": r.tags,
        "references": r.references,
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
        "details": r.details,
        "looked_up_at": datetime.now(UTC),
    }
    stmt = pg_insert(ThreatIntelResult).values(**values)
    update = {
        k: stmt.excluded[k]
        for k in ("verdict", "confidence", "tags", "references", "first_seen", "last_seen", "details", "looked_up_at")
    }
    await session.execute(
        stmt.on_conflict_do_update(index_elements=["tenant_id", "indicator_type", "value", "provider"], set_=update)
    )


async def enrich(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    indicators: list[tuple[str, str]],
    local_only: bool = False,
    force: bool = False,
) -> list[TIResult]:
    """Look indicators up in all providers, using cached results younger than ``ti_cache_hours``."""
    s = get_settings()
    providers = [LocalIndicatorProvider()] if local_only else configured_providers()
    out: list[TIResult] = []
    cutoff = datetime.now(UTC) - timedelta(hours=s.ti_cache_hours)
    for itype, value in dict.fromkeys(indicators):
        for p in providers:
            cached = None
            if not force and p.name != "local":
                cached = (
                    await session.execute(
                        select(ThreatIntelResult).where(
                            ThreatIntelResult.tenant_id == tenant_id,
                            ThreatIntelResult.value == value,
                            ThreatIntelResult.provider == p.name,
                            ThreatIntelResult.looked_up_at >= cutoff,
                        )
                    )
                ).scalar_one_or_none()
            if cached is not None:
                continue
            r = await p.lookup(session, tenant_id, itype, value)
            if r is not None:
                await _store(session, tenant_id, r)
                out.append(r)
    return out


# STIX 2.1 patterning: only plain equality comparisons on observable types SentinelX can match on.
_STIX_COMPARISON = re.compile(
    r"(ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|file:hashes\.(?:'[\w-]+'|[\w-]+))"
    r"\s*=\s*'((?:[^'\\]|\\.)*)'"
)
_STIX_TYPES = {"ipv4-addr:value": "ip", "ipv6-addr:value": "ip", "domain-name:value": "domain", "url:value": "url"}


def _stix_time(v: Any) -> datetime | None:
    if not isinstance(v, str):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def stix_indicator_items(objects: list[Any], now: datetime | None = None) -> list[dict[str, Any]]:
    """Feed items from STIX 2.1 ``indicator`` objects.

    Revoked and expired indicators are skipped (an IOC its producer withdrew must not keep raising risk),
    non-STIX pattern languages (Snort, YARA, ...) are ignored, every value in a compound ``OR`` pattern is
    imported, and ``valid_until`` becomes the indicator's expiry."""
    now = now or datetime.now(UTC)
    out: list[dict[str, Any]] = []
    for o in objects:
        if not isinstance(o, dict) or o.get("type") != "indicator" or o.get("revoked") is True:
            continue
        if (o.get("pattern_type") or "stix") != "stix":
            continue
        valid_until = _stix_time(o.get("valid_until"))
        if valid_until is not None and valid_until <= now:
            continue
        refs = [r.get("url") for r in o.get("external_references") or [] if isinstance(r, dict) and r.get("url")]
        conf = o.get("confidence")
        for path, raw in _STIX_COMPARISON.findall(str(o.get("pattern") or "")):
            value = re.sub(r"\\(.)", r"\1", raw)
            item: dict[str, Any] = {
                "value": value,
                "type": _STIX_TYPES.get(path),  # hashes: classified (and validated) by length below
                "description": o.get("name") or o.get("description"),
                "confidence": (conf if isinstance(conf, int | float) else 60) / 100,
                "tags": [str(x) for x in (o.get("indicator_types") or o.get("labels") or [])],
                "reference": refs[0] if refs else None,
            }
            if valid_until is not None:
                item["expires_at"] = valid_until
            out.append(item)
    return out


def parse_feed(content: str, fmt: str, default_source: str, default_confidence: float = 0.6) -> list[dict[str, Any]]:
    """Parse indicator feeds.

    * ``csv``  - header with at least ``value`` (optional: type, confidence, verdict, tags, description, reference)
    * ``txt``  - one indicator per line, ``#`` comments (abuse.ch-style plain lists)
    * ``json`` - list of objects with the CSV columns, or a STIX 2.1 bundle of ``indicator`` objects
    """
    items: list[dict[str, Any]] = []
    if fmt == "txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.append({"value": line.split()[0]})
    elif fmt == "csv":
        reader = csv.DictReader(io.StringIO(content))
        items = [dict(r) for r in reader]
    elif fmt == "json":
        data = json.loads(content)
        if isinstance(data, dict) and data.get("type") == "bundle":
            items = stix_indicator_items(data.get("objects") or [])
        elif isinstance(data, list):
            items = data
    else:
        raise ValueError(f"unsupported feed format {fmt!r}")
    return normalize_feed_items(items, default_source, default_confidence)


def normalize_feed_items(
    items: list[dict[str, Any]], default_source: str, default_confidence: float = 0.6
) -> list[dict[str, Any]]:
    """Validate, classify and normalize raw feed items; anything SentinelX cannot match on is dropped."""
    out: list[dict[str, Any]] = []
    for it in items:
        value = str(it.get("value", "")).strip()
        itype = (it.get("type") or classify_indicator(value) or "").lower()
        if itype not in ("ip", "domain", "hash", "url"):
            continue
        try:
            value = normalize_indicator(itype, value)
        except ValueError:
            continue
        tags = it.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in re.split(r"[;,|]", tags) if t.strip()]
        try:
            conf = float(it.get("confidence") or default_confidence)
        except (TypeError, ValueError):
            conf = default_confidence
        if conf > 1:
            conf = conf / 100
        verdict = str(it.get("verdict") or "malicious").lower()
        out.append(
            {
                "type": itype,
                "value": value[:1024],
                "source": str(it.get("source") or default_source)[:120],
                "confidence": max(0.0, min(1.0, conf)),
                "verdict": verdict if verdict in ("malicious", "suspicious", "benign") else "malicious",
                "tags": [str(t)[:60] for t in tags][:20],
                "description": (str(it.get("description") or "")[:2000] or None),
                "reference": (str(it.get("reference") or "")[:1000] or None),
                "expires_at": it.get("expires_at") if isinstance(it.get("expires_at"), datetime) else None,
            }
        )
    return out


async def import_indicators(
    session: AsyncSession, tenant_id: uuid.UUID, items: list[dict[str, Any]], expires_days: int | None = None
) -> int:
    now = datetime.now(UTC)
    default_expiry = now + timedelta(days=expires_days) if expires_days else None
    rows = [
        {
            **it,
            "id": uuid.uuid4(),
            "tenant_id": tenant_id,
            "first_seen": now,
            "last_seen": now,
            # the feed's own validity wins when it is sooner than the import-wide default
            "expires_at": min((d for d in (it.get("expires_at"), default_expiry) if d is not None), default=None),
        }
        for it in items
    ]
    n = 0
    for i in range(0, len(rows), 1000):
        chunk = rows[i : i + 1000]
        stmt = pg_insert(Indicator).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=["tenant_id", "type", "value", "source"],
            set_={
                "confidence": stmt.excluded.confidence,
                "verdict": stmt.excluded.verdict,
                "tags": stmt.excluded.tags,
                "description": stmt.excluded.description,
                "last_seen": stmt.excluded.last_seen,
                "expires_at": stmt.excluded.expires_at,
            },
        )
        await session.execute(stmt)
        n += len(chunk)
    return n
