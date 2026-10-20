"""Threat-intelligence provider abstraction.

Providers return normalized ``TIResult`` objects; SentinelX never treats a single reputation result as
proof of maliciousness - results feed the risk engine with their confidence, and are shown with source.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.logging import get_logger
from sentinelx.metrics import TI_FAILURES, TI_REQUESTS
from sentinelx.persistence.models import Indicator

log = get_logger(__name__)


@dataclass
class TIResult:
    indicator_type: str
    value: str
    provider: str
    verdict: str  # malicious | suspicious | unknown | benign
    confidence: float
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ThreatIntelProvider:
    """Base class for a threat-intelligence source.

    Subclasses implement ``lookup``; the typed helpers below are the public interface from the spec.
    """

    name = "base"

    async def lookup(self, session: AsyncSession, tenant_id: uuid.UUID, itype: str, value: str) -> TIResult | None:
        raise NotImplementedError

    async def lookup_ip(self, session: AsyncSession, tenant_id: uuid.UUID, value: str) -> TIResult | None:
        return await self.lookup(session, tenant_id, "ip", value)

    async def lookup_domain(self, session: AsyncSession, tenant_id: uuid.UUID, value: str) -> TIResult | None:
        return await self.lookup(session, tenant_id, "domain", value)

    async def lookup_hash(self, session: AsyncSession, tenant_id: uuid.UUID, value: str) -> TIResult | None:
        return await self.lookup(session, tenant_id, "hash", value)

    async def lookup_url(self, session: AsyncSession, tenant_id: uuid.UUID, value: str) -> TIResult | None:
        return await self.lookup(session, tenant_id, "url", value)


class LocalIndicatorProvider(ThreatIntelProvider):
    """Feeds imported from files (CSV/JSON/STIX-lite) plus analyst watchlist entries, stored per tenant."""

    name = "local"

    async def lookup(self, session: AsyncSession, tenant_id: uuid.UUID, itype: str, value: str) -> TIResult | None:
        TI_REQUESTS.labels(provider=self.name).inc()
        now = datetime.now(UTC)
        rows = (
            (
                await session.execute(
                    select(Indicator).where(
                        Indicator.tenant_id == tenant_id,
                        Indicator.value == value,
                        or_(Indicator.expires_at.is_(None), Indicator.expires_at > now),
                    )
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            return None
        best = max(rows, key=lambda r: r.confidence)
        return TIResult(
            indicator_type=best.type,
            value=value,
            provider=f"local:{best.source}",
            verdict=best.verdict,
            confidence=best.confidence,
            tags=sorted({t for r in rows for t in r.tags}),
            references=[r.reference for r in rows if r.reference],
            first_seen=best.first_seen,
            last_seen=best.last_seen,
            details={"sources": sorted({r.source for r in rows}), "description": best.description},
        )


_MISP_TYPES = {
    "ip": ["ip-src", "ip-dst", "ip-dst|port", "ip-src|port"],
    "domain": ["domain", "hostname", "domain|ip"],
    "hash": ["md5", "sha1", "sha256", "filename|md5", "filename|sha256"],
    "url": ["url", "uri"],
}


def validate_integration_url(url: str, allow_http: bool) -> str:
    """SSRF guard for admin-configured integration URLs: scheme allow-list, no credentials in URL."""
    p = urlparse(url)
    if p.scheme not in (("https", "http") if allow_http else ("https",)):
        raise ValueError("integration URL must use https")
    if not p.hostname or p.username or p.password:
        raise ValueError("integration URL must have a host and no embedded credentials")
    return url.rstrip("/")


class MispProvider(ThreatIntelProvider):
    """MISP ``/attributes/restSearch`` (https://www.misp-project.org/openapi/)."""

    name = "misp"

    def __init__(
        self,
        url: str,
        api_key: str,
        verify_tls: bool = True,
        timeout: float = 8.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        s = get_settings()
        self.url = validate_integration_url(url, allow_http=not s.is_production)
        self.api_key = api_key
        self.verify = verify_tls
        self.timeout = timeout
        self.transport = transport

    async def lookup(self, session: AsyncSession, tenant_id: uuid.UUID, itype: str, value: str) -> TIResult | None:
        TI_REQUESTS.labels(provider=self.name).inc()
        body = {
            "returnFormat": "json",
            "value": value,
            "type": _MISP_TYPES.get(itype, []),
            "limit": 20,
            "includeEventTags": True,
            "enforceWarninglist": True,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify, follow_redirects=False, transport=self.transport
            ) as client:
                r = await client.post(
                    f"{self.url}/attributes/restSearch",
                    json=body,
                    headers={"Authorization": self.api_key, "Accept": "application/json"},
                )
                r.raise_for_status()
                data = r.json()
        except (httpx.HTTPError, ValueError) as e:
            TI_FAILURES.labels(provider=self.name).inc()
            log.warning("misp_lookup_failed", error=type(e).__name__)
            return None
        attrs = ((data or {}).get("response") or {}).get("Attribute") or []
        if not attrs:
            return TIResult(itype, value, self.name, "unknown", 0.0)
        to_ids = any(a.get("to_ids") for a in attrs)
        tags = sorted({t.get("name") for a in attrs for t in (a.get("Tag") or []) if t.get("name")})
        events = sorted({str(a.get("event_id")) for a in attrs if a.get("event_id")})
        ts = [
            datetime.fromtimestamp(int(a["timestamp"]), tz=UTC) for a in attrs if str(a.get("timestamp", "")).isdigit()
        ]
        return TIResult(
            indicator_type=itype,
            value=value,
            provider=self.name,
            verdict="malicious" if to_ids else "suspicious",
            confidence=0.8 if to_ids else 0.5,
            tags=tags[:20],
            references=[f"{self.url}/events/view/{e}" for e in events[:10]],
            first_seen=min(ts) if ts else None,
            last_seen=max(ts) if ts else None,
            details={"misp_events": events[:10], "attribute_count": len(attrs)},
        )


def configured_providers() -> list[ThreatIntelProvider]:
    s = get_settings()
    providers: list[ThreatIntelProvider] = [LocalIndicatorProvider()]
    if s.misp_url and s.misp_api_key:
        providers.append(MispProvider(s.misp_url, s.misp_api_key.get_secret_value(), s.misp_verify_tls))
    return providers
