"""TAXII 2.1 pull endpoint: incremental import into the caller's organization only, audited."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from sentinelx.api.routes import threat_intel as ti_routes
from sentinelx.security.ratelimit import limiter
from sentinelx.threat_intel.taxii import TAXII_MEDIA_TYPE, TaxiiClient
from tests.helpers import make_tenant, signed_in


@pytest.fixture(autouse=True)
def _reset() -> None:
    limiter.reset()


def _ind(value: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--{value}",
        "pattern": f"[ipv4-addr:value = '{value}']",
        "pattern_type": "stix",
        "confidence": 85,
        "name": "C2 server",
    }


async def test_taxii_pull_is_incremental_and_tenant_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        newer = request.url.params.get("added_after") == "2026-10-01T00:00:00Z"
        objs = [_ind("198.51.100.77")] if newer else [_ind("198.51.100.66"), {"type": "malware", "id": "malware--1"}]
        last = "2026-10-02T00:00:00Z" if newer else "2026-10-01T00:00:00Z"
        return httpx.Response(
            200,
            content=json.dumps({"more": False, "objects": objs}),
            headers={"Content-Type": TAXII_MEDIA_TYPE, "X-TAXII-Date-Added-Last": last},
        )

    tid, other = await make_tenant("Taxii"), await make_tenant("TaxiiOther")
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        monkeypatch.setattr(ti_routes, "configured_taxii", lambda: None)
        r = await c.post("/api/v1/threat-intel/taxii/pull", json={})
        assert r.status_code == 409

        def configured() -> TaxiiClient:
            return TaxiiClient("https://taxii.example.test/api1/collections/c1", transport=httpx.MockTransport(handler))

        monkeypatch.setattr(ti_routes, "configured_taxii", configured)
        r = await c.post("/api/v1/threat-intel/taxii/pull", json={})
        assert r.status_code == 200 and r.json()["objects"] == 2 and r.json()["imported"] == 1, r.text
        assert "added_after" not in seen[-1].url.params
        r = await c.post("/api/v1/threat-intel/taxii/pull", json={})
        assert r.json()["imported"] == 1 and seen[-1].url.params["added_after"] == "2026-10-01T00:00:00Z"
        r = await c.post("/api/v1/threat-intel/taxii/pull", json={"full": True})
        assert "added_after" not in seen[-1].url.params

        values = {i["value"] for i in (await c.get("/api/v1/threat-intel/indicators")).json()["items"]}
        assert {"198.51.100.66", "198.51.100.77"} <= values
        status = (await c.get("/api/v1/threat-intel/taxii")).json()
        assert status["last_imported"] == 1 and status["last_pull_at"]

        def broken() -> TaxiiClient:
            return TaxiiClient(
                "https://taxii.example.test/c", transport=httpx.MockTransport(lambda r: httpx.Response(500))
            )

        monkeypatch.setattr(ti_routes, "configured_taxii", broken)
        assert (await c.post("/api/v1/threat-intel/taxii/pull", json={})).status_code == 502

    async with signed_in(other, "SECURITY_ANALYST") as c:
        values = {i["value"] for i in (await c.get("/api/v1/threat-intel/indicators")).json()["items"]}
        assert not values & {"198.51.100.66", "198.51.100.77"}
