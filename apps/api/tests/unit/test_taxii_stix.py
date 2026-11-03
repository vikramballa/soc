"""STIX 2.1 indicator parsing and the TAXII 2.1 client (mocked server)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from sentinelx.threat_intel import taxii
from sentinelx.threat_intel.service import normalize_feed_items, stix_indicator_items
from sentinelx.threat_intel.taxii import TaxiiClient, TaxiiError

NOW = datetime(2026, 11, 1, tzinfo=UTC)


def _ind(pattern: str, **kw: Any) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--{abs(hash(pattern))}",
        "pattern": pattern,
        "pattern_type": "stix",
        **kw,
    }


def test_stix_indicators_respect_revocation_expiry_and_pattern_language() -> None:
    objs = [
        _ind("[ipv4-addr:value = '198.51.100.7'] OR [domain-name:value = 'bad.example.net']", confidence=90),
        _ind("[url:value = 'http://198.51.100.8/it\\'s']", valid_until="2027-01-01T00:00:00Z"),
        _ind("[ipv4-addr:value = '198.51.100.9']", revoked=True),
        _ind("[ipv4-addr:value = '198.51.100.10']", valid_until="2026-10-01T00:00:00Z"),
        _ind("alert tcp any any -> any any (msg:x;)", pattern_type="snort"),
        _ind("[file:hashes.'SHA-256' = 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789']"),
        _ind("[file:hashes.MD5 = 'not-a-hash']"),
        _ind("[ipv4-addr:value = '198.51.100.0/24']"),
        {"type": "malware", "id": "malware--1", "name": "x"},
    ]
    items = normalize_feed_items(stix_indicator_items(objs, now=NOW), "taxii")
    got = {(i["type"], i["value"]) for i in items}
    assert got == {
        ("ip", "198.51.100.7"),
        ("domain", "bad.example.net"),
        ("url", "http://198.51.100.8/it's"),
        ("hash", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
    }
    by_value = {i["value"]: i for i in items}
    assert by_value["198.51.100.7"]["confidence"] == 0.9
    assert by_value["http://198.51.100.8/it's"]["expires_at"] == datetime(2027, 1, 1, tzinfo=UTC)
    assert by_value["198.51.100.7"]["expires_at"] is None


def _server(pages: list[dict[str, Any]], seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        idx = int(request.url.params.get("next", "0"))
        page = pages[idx]
        return httpx.Response(
            200,
            content=json.dumps(page["body"]),
            headers={"Content-Type": taxii.TAXII_MEDIA_TYPE, "X-TAXII-Date-Added-Last": page["last"]},
        )

    return httpx.MockTransport(handler)


async def test_taxii_pagination_auth_and_cursor() -> None:
    pages = [
        {"body": {"more": True, "next": "1", "objects": [_ind("[ipv4-addr:value = '198.51.100.1']")]}, "last": "t1"},
        {"body": {"more": False, "objects": [_ind("[ipv4-addr:value = '198.51.100.2']")]}, "last": "t2"},
    ]
    seen: list[httpx.Request] = []
    client = TaxiiClient(
        "https://taxii.example.test/api1/collections/abc/", api_token="tok", transport=_server(pages, seen)
    )
    pulled = await client.pull_indicators(added_after="t0")
    assert len(pulled.objects) == 2 and pulled.pages == 2 and pulled.added_after == "t2" and not pulled.truncated
    first = seen[0]
    assert str(first.url).startswith("https://taxii.example.test/api1/collections/abc/objects/?")
    assert first.headers["accept"] == taxii.TAXII_MEDIA_TYPE and first.headers["authorization"] == "Bearer tok"
    assert first.url.params["added_after"] == "t0" and first.url.params["match[type]"] == "indicator"
    assert seen[1].url.params["next"] == "1"


async def test_taxii_bounds_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        {"body": {"more": True, "next": "1", "objects": [_ind("[ipv4-addr:value = '198.51.100.1']")]}, "last": "t1"},
        {"body": {"more": True, "next": "2", "objects": [_ind("[ipv4-addr:value = '198.51.100.2']")]}, "last": "t2"},
    ]
    monkeypatch.setattr(taxii, "MAX_PAGES", 1)
    pulled = await TaxiiClient("https://taxii.example.test/c", transport=_server(pages, [])).pull_indicators()
    assert pulled.truncated and pulled.added_after == "t1" and len(pulled.objects) == 1

    monkeypatch.setattr(taxii, "MAX_PAGES", 50)
    monkeypatch.setattr(taxii, "MAX_OBJECTS", 1)
    big = [{"body": {"more": False, "objects": [_ind("[ipv4-addr:value = '198.51.100.3']")] * 2}, "last": "t9"}]
    pulled = await TaxiiClient("https://taxii.example.test/c", transport=_server(big, [])).pull_indicators("t0")
    assert pulled.truncated and len(pulled.objects) == 1 and pulled.added_after == "t0"  # page will be re-read

    failing = httpx.MockTransport(lambda r: httpx.Response(401))
    with pytest.raises(TaxiiError):
        await TaxiiClient("https://taxii.example.test/c", transport=failing).pull_indicators()
    with pytest.raises(ValueError):
        TaxiiClient("https://user:pw@taxii.example.test/c")
    with pytest.raises(ValueError):
        TaxiiClient("file:///etc/passwd")
