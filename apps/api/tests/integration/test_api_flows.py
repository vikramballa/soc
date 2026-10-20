"""Integration: API ingestion -> worker -> detection -> correlation -> incident APIs, AI (mocked), reports."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from sentinelx.jobs.worker import AI_KINDS, FAST_KINDS, Worker, _handle
from sentinelx.security.ratelimit import limiter
from tests.helpers import FIXTURES, make_tenant, signed_in


async def drain_jobs(kinds: list[str] | None = None) -> int:
    w = Worker()
    n = 0
    while True:
        job = await w._claim(kinds or FAST_KINDS + AI_KINDS)
        if job is None:
            return n
        await _handle(job["kind"], job["tenant_id"], job["payload"] or {})
        await w._finish(job["id"], True, None, job["attempts"], job["max_attempts"])
        n += 1


@pytest.fixture(autouse=True)
def _reset() -> None:
    limiter.reset()


@pytest.fixture
async def org() -> dict[str, Any]:
    tid = await make_tenant("Acme")
    async with signed_in(tid, "TENANT_ADMIN") as c:
        for src, path, lt in (
            ("wazuh", "wazuh/alerts.json", None),
            ("suricata", "suricata/eve.json", None),
            ("zeek", "zeek/conn.log", "conn"),
            ("zeek", "zeek/dns.json", "dns"),
            ("zeek", "zeek/notice.json", "notice"),
        ):
            r = await c.post(
                f"/api/v1/ingest/{src}",
                params={"log_type": lt} if lt else None,
                content=(FIXTURES / path).read_bytes(),
                headers={"content-type": "text/plain"},
            )
            assert r.status_code == 200 and r.json()["quarantined"] == 0, r.text
        await c.post(
            "/api/v1/threat-intel/feeds/import",
            json={"content": (FIXTURES / "threat_intel/feed.csv").read_text(), "format": "csv", "source": "test-feed"},
        )
    assert await drain_jobs() >= 1
    return {"tenant_id": tid}


async def test_pipeline_produces_alerts_incidents_and_dashboard(org: dict[str, Any]) -> None:
    async with signed_in(org["tenant_id"], "SECURITY_ANALYST") as c:
        alerts = (await c.get("/api/v1/alerts", params={"limit": 200})).json()
        titles = {a["title"] for a in alerts["items"]}
        assert "Suspicious PowerShell Command Line" in titles
        assert "Account Added to a Privileged Group" in titles
        assert any(t.startswith("Known malicious") for t in titles)
        dash = (await c.get("/api/v1/dashboard/summary")).json()
        f = dash["funnel"]
        # timestamps of fixtures are fixed (Oct 2026) so look at an all-encompassing window
        dash = (await c.get("/api/v1/dashboard/summary", params={"hours": 24 * 90})).json()
        f = dash["funnel"]
        assert f["raw_events"] >= f["security_events"] >= 1
        assert f["alerts"] >= f["incidents"] >= 1
        assert dash["system"]["core_detection"] == "operational"
        assert dash["system"]["ai"]["available"] is False  # Ollama unreachable in tests -> core still works
        incs = (await c.get("/api/v1/incidents")).json()
        assert incs["total"] >= 1


async def test_incident_lifecycle_timeline_and_report(org: dict[str, Any]) -> None:
    async with signed_in(org["tenant_id"], "SECURITY_ANALYST") as c:
        inc = (await c.get("/api/v1/incidents")).json()["items"][0]
        iid = inc["id"]
        tl = (await c.get(f"/api/v1/incidents/{iid}/timeline")).json()
        assert tl["entries"] and all(e["event_ids"] for e in tl["entries"])
        ev_id = tl["entries"][0]["event_ids"][0]
        ev = (await c.get(f"/api/v1/incidents/{iid}/evidence/{ev_id}")).json()
        assert ev["snapshot"]["id"] == ev_id  # timeline entry links to the source event
        ctx = (await c.get(f"/api/v1/incidents/{iid}/context")).json()
        assert ctx["graph"]["nodes"] and ctx["entities"]

        assert (await c.patch(f"/api/v1/incidents/{iid}", json={"status": "investigating"})).status_code == 200
        r = await c.patch(f"/api/v1/incidents/{iid}", json={"status": "closed"})
        assert r.status_code == 422  # disposition required
        xss = "<script>alert('x')</script><img src=x onerror=alert(1)>"
        assert (await c.post(f"/api/v1/incidents/{iid}/notes", json={"body": xss})).status_code == 201
        r = await c.post(
            f"/api/v1/incidents/{iid}/responses",
            json={"kind": "watchlist_ioc", "title": "Watch C2", "payload": {"value": "198.51.100.23"}},
        )
        assert r.status_code == 201
        r = await c.patch(f"/api/v1/incidents/{iid}", json={"status": "closed", "disposition": "true_positive"})
        assert r.status_code == 200 and r.json()["resolved_at"]
        r = await c.patch(f"/api/v1/incidents/{iid}", json={"status": "investigating"})
        assert r.status_code == 200 and r.json()["resolved_at"] is None  # reopened
        acts = (await c.get(f"/api/v1/incidents/{iid}/activity")).json()
        assert any("Reopened" in a["message"] for a in acts)

        html = (await c.get(f"/api/v1/incidents/{iid}/report", params={"fmt": "html"})).text
        assert "<script>alert" not in html and "&lt;script&gt;" in html
        for section in (
            "Observed evidence",
            "Automated inference",
            "AI-generated interpretation",
            "Analyst conclusion",
        ):
            assert section in html


async def test_ai_investigation_paths(org: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelx.ai import ollama

    replies: list[str] = []

    async def fake_chat(
        self: Any, model: str, messages: list[dict[str, str]], schema: dict[str, Any], num_ctx: int = 8192
    ) -> tuple[str, dict[str, Any]]:
        telemetry = json.loads(messages[1]["content"].split("<telemetry>\n", 1)[1].rsplit("\n</telemetry>", 1)[0])
        first_ref = telemetry["evidence_events"][0]["ref"]
        reply = replies.pop(0).replace("{REF}", first_ref)
        return reply, {"model": model}

    monkeypatch.setattr(ollama.OllamaClient, "chat_json", fake_chat)
    good = json.dumps(
        {
            "summary": "Suspicious activity observed.",
            "verdict": "suspicious",
            "severity_assessment": "Medium.",
            "evidence": [{"event_id": "{REF}", "claim": "seen"}],
            "mitre_assessment": [],
            "possible_benign_explanations": ["admin work"],
            "recommended_investigation_steps": ["Review the host"],
            "indicators_to_search": [],
            "confidence": 0.5,
        }
    )
    invented = good.replace("{REF}", "E99")

    async with signed_in(org["tenant_id"], "SECURITY_ANALYST") as c:
        iid = (await c.get("/api/v1/incidents")).json()["items"][0]["id"]

        replies[:] = [good]
        inv = (await c.post(f"/api/v1/incidents/{iid}/investigate")).json()
        assert inv["status"] == "queued"
        await drain_jobs(AI_KINDS)
        done = (await c.get(f"/api/v1/ai/investigations/{inv['id']}")).json()
        assert done["status"] == "completed", done
        assert uuid.UUID(done["result"]["evidence"][0]["event_id"])  # mapped back to a real event id
        assert done["prompt_version"] and done["context_sha256"]

        replies[:] = [invented, invented, invented]  # every attempt invents evidence
        inv = (await c.post(f"/api/v1/incidents/{iid}/investigate")).json()
        await drain_jobs(AI_KINDS)
        rej = (await c.get(f"/api/v1/ai/investigations/{inv['id']}")).json()
        assert rej["status"] == "rejected" and rej["result"] is None
        assert any("E99" in e for e in rej["validation_errors"])

    monkeypatch.undo()  # real client -> Ollama unreachable (tests point it at a closed port)
    async with signed_in(org["tenant_id"], "SECURITY_ANALYST") as c:
        inv = (await c.post(f"/api/v1/incidents/{iid}/investigate")).json()
        await drain_jobs(AI_KINDS)
        failed = (await c.get(f"/api/v1/ai/investigations/{inv['id']}")).json()
        assert failed["status"] == "failed" and "Ollama" in failed["error"]
        assert (await c.get(f"/api/v1/incidents/{iid}")).status_code == 200  # core unaffected


async def test_rule_toggle_is_per_tenant(org: dict[str, Any]) -> None:
    other = await make_tenant("Other")
    uid = "ee71e69d-9a6d-45ba-b784-e94261bb0053"  # Suspicious PowerShell
    async with signed_in(org["tenant_id"], "TENANT_ADMIN") as c:
        r = await c.patch(f"/api/v1/detections/{uid}", json={"enabled": False})
        assert r.status_code == 200 and r.json()["enabled"] is False
        rules = (await c.get("/api/v1/detections")).json()["items"]
        assert next(r for r in rules if r["rule_uid"] == uid)["enabled"] is False
    async with signed_in(other, "TENANT_ADMIN") as c:
        rules = (await c.get("/api/v1/detections")).json()["items"]
        assert next(r for r in rules if r["rule_uid"] == uid)["enabled"] is True
        assert (await c.post("/api/v1/detections/sync")).status_code == 403  # installation-wide -> super admin


async def test_mitre_matrix_and_threat_intel_lookup(org: dict[str, Any]) -> None:
    async with signed_in(org["tenant_id"], "SECURITY_ANALYST") as c:
        m = (await c.get("/api/v1/mitre/matrix", params={"days": 365})).json()
        observed = [t["id"] for tac in m["tactics"] for t in tac["techniques"] if t["observed"]]
        assert "T1059" in observed  # PowerShell sub-technique rolls up to its parent
        r = (await c.get("/api/v1/threat-intel/lookup/198.51.100.23")).json()
        assert r["overall"] == "malicious" and r["sightings"]["events_30d"] >= 0
        r = await c.get("/api/v1/threat-intel/lookup/not-an-indicator")
        assert r.status_code == 422
