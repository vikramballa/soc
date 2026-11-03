"""Pull STIX 2.1 indicators from a TAXII 2.1 collection (``GET {collection}/objects/``).

The collection URL is admin configuration only, never request input, and goes through the same SSRF guard as
MISP. Pulls are incremental (``added_after`` cursor) and bounded, so a large or hostile server cannot exhaust
memory or keep a worker busy indefinitely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from sentinelx.config import get_settings
from sentinelx.logging import get_logger
from sentinelx.threat_intel.providers import validate_integration_url

log = get_logger(__name__)

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
MAX_PAGES = 50
MAX_OBJECTS = 100_000
PAGE_SIZE = 1000


class TaxiiError(RuntimeError):
    pass


@dataclass
class TaxiiPull:
    objects: list[dict[str, Any]] = field(default_factory=list)
    pages: int = 0
    added_after: str | None = None  # cursor for the next incremental pull
    truncated: bool = False


class TaxiiClient:
    def __init__(
        self,
        collection_url: str,
        *,
        username: str | None = None,
        password: str | None = None,
        api_token: str | None = None,
        verify_tls: bool = True,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        s = get_settings()
        self.url = validate_integration_url(collection_url, allow_http=not s.is_production)
        self.auth = httpx.BasicAuth(username, password or "") if username else None
        self.headers = {"Accept": TAXII_MEDIA_TYPE}
        if api_token:
            self.headers["Authorization"] = f"Bearer {api_token}"
        self.verify = verify_tls
        self.timeout = timeout
        self.transport = transport

    async def pull_indicators(self, added_after: str | None = None) -> TaxiiPull:
        out = TaxiiPull(added_after=added_after)
        params: dict[str, str] = {"match[type]": "indicator", "limit": str(PAGE_SIZE)}
        if added_after:
            params["added_after"] = added_after
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify,
            follow_redirects=False,
            transport=self.transport,
            auth=self.auth,
            headers=self.headers,
        ) as client:
            while True:
                try:
                    r = await client.get(f"{self.url}/objects/", params=params)
                    r.raise_for_status()
                    envelope = r.json()
                except (httpx.HTTPError, ValueError) as e:
                    raise TaxiiError(f"TAXII request failed: {type(e).__name__}") from e
                if not isinstance(envelope, dict):
                    raise TaxiiError("TAXII server returned an unexpected response")
                out.pages += 1
                objs = [o for o in envelope.get("objects") or [] if isinstance(o, dict)]
                room = MAX_OBJECTS - len(out.objects)
                if len(objs) > room:
                    # Keep the previous cursor so the next pull re-reads this page instead of skipping the rest.
                    out.objects.extend(objs[:room])
                    out.truncated = True
                    break
                out.objects.extend(objs)
                # X-TAXII-Date-Added-Last marks the newest object in this page: resume after it next time.
                last = r.headers.get("X-TAXII-Date-Added-Last")
                if last:
                    out.added_after = last
                more = bool(envelope.get("more"))
                nxt = envelope.get("next")
                if not more:
                    break
                if len(out.objects) >= MAX_OBJECTS or out.pages >= MAX_PAGES:
                    out.truncated = True
                    break
                if nxt:
                    params["next"] = str(nxt)
                elif last:
                    params["added_after"] = last
                else:
                    raise TaxiiError("TAXII server reported more data without a 'next' token or date header")
        log.info("taxii_pull", pages=out.pages, objects=len(out.objects), truncated=out.truncated)
        return out


def configured_taxii(transport: httpx.AsyncBaseTransport | None = None) -> TaxiiClient | None:
    s = get_settings()
    if not s.taxii_collection_url:
        return None
    return TaxiiClient(
        s.taxii_collection_url,
        username=s.taxii_username,
        password=s.taxii_password.get_secret_value() if s.taxii_password else None,
        api_token=s.taxii_api_token.get_secret_value() if s.taxii_api_token else None,
        verify_tls=s.taxii_verify_tls,
        transport=transport,
    )
