"""Risk scoring, ML evaluation, DGA heuristic, threat-intel feed parsing and MISP provider."""

from __future__ import annotations

import uuid

import httpx
import numpy as np

from sentinelx.detection.builtin import dga_score, registrable_label
from sentinelx.ml.model import evaluate, explain, score, train
from sentinelx.risk.engine import RiskInputs, band, confidence, score_incident
from sentinelx.threat_intel.providers import MispProvider, validate_integration_url
from sentinelx.threat_intel.service import classify_indicator, parse_feed
from tests.helpers import FIXTURES


def test_risk_is_explained_bounded_and_monotonic() -> None:
    low = score_incident(
        RiskInputs(max_alert_severity=30, alert_count=1, event_count=1, distinct_rules=1, distinct_sources=1)
    )
    high = score_incident(
        RiskInputs(
            max_alert_severity=90,
            alert_count=8,
            event_count=60,
            distinct_rules=6,
            distinct_sources=3,
            max_asset_criticality=5,
            privileged_users=["admin"],
            new_source_logon=True,
            ti_matches=[{"value": "198.51.100.23", "verdict": "malicious", "confidence": 0.9, "provider": "local"}],
            ml_max_score=0.99,
            tactics=["credential-access", "execution", "command-and-control"],
        )
    )
    assert 0 <= low.score < high.score <= 100
    assert high.severity in ("high", "critical")
    assert {c.key for c in high.contributors} == {
        "detection_severity",
        "event_volume",
        "asset_criticality",
        "identity_context",
        "threat_intel",
        "correlation_strength",
        "behavioral_anomaly",
        "attack_stage",
    }
    for c in high.contributors:
        assert 0 <= c.value <= c.max and c.reason
    assert round(sum(c.value for c in high.contributors)) >= high.score  # clipped at 100, never inflated


def test_bands_and_confidence() -> None:
    assert [band(x) for x in (10, 30, 60, 80, 95)] == ["informational", "low", "medium", "high", "critical"]
    c1, _ = confidence(1, 1, False, False)
    c2, factors = confidence(3, 4, True, False)
    c_ml, _ = confidence(1, 1, False, True)
    assert c_ml < c1 < c2 <= 0.95 and len(factors) >= 3


def test_isolation_forest_ranks_abnormal_above_normal() -> None:
    """synthetic abnormal behaviour scores higher than baseline."""
    rng = np.random.default_rng(1)
    n_feat = 6
    normal = np.column_stack([rng.poisson(lam, 400) for lam in (20, 1, 15, 30, 8, 2)]).astype(float)
    model = train(normal, [f"f{i}" for i in range(n_feat)])
    test_normal = np.column_stack([rng.poisson(lam, 50) for lam in (20, 1, 15, 30, 8, 2)]).astype(float)
    abnormal = test_normal.copy()
    abnormal[:, 1] = rng.poisson(40, 50)  # failed logins spike
    abnormal[:, 3] = rng.poisson(200, 50)  # dns spike
    metrics = evaluate(model, test_normal, abnormal)
    assert metrics["auc"] > 0.95 and metrics["mean_abnormal"] > metrics["mean_normal"]
    _, _, z = score(model, abnormal[:1])
    top = explain(model, abnormal[0], z[0])
    assert {t["feature"] for t in top[:2]} == {"f1", "f3"}
    assert all(t["direction"] == "higher than usual" for t in top)


def test_dga_heuristic() -> None:
    assert dga_score("xkqzvbtrwplmn8z2.info")[0]
    for benign in ("login.microsoftonline.com", "www.google.com", "github.com", "bbc.co.uk"):
        assert not dga_score(benign)[0], benign
    assert registrable_label("a.b.example.co.uk") == "example"


def test_feed_parsing_csv_and_stix() -> None:
    items = parse_feed((FIXTURES / "threat_intel/feed.csv").read_text(), "csv", "test-feed")
    by_value = {i["value"]: i for i in items}
    assert by_value["198.51.100.23"]["confidence"] == 0.9  # 90 -> 0.9
    assert by_value["203.0.113.77"]["type"] == "ip" and by_value["203.0.113.77"]["verdict"] == "suspicious"
    assert "not an indicator" not in by_value
    stix = parse_feed((FIXTURES / "threat_intel/stix_bundle.json").read_text(), "json", "stix")
    vals = {i["value"] for i in stix}
    assert "198.51.100.99" in vals and any(len(v) == 64 for v in vals)
    assert classify_indicator("https://x.example/a") == "url" and classify_indicator("nope") is None


async def test_misp_provider_parsing_and_ssrf_guard() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "k"
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {"event_id": "17", "to_ids": True, "timestamp": "1791000000", "Tag": [{"name": "tlp:amber"}]}
                    ]
                }
            },
        )

    p = MispProvider("https://misp.example", "k", transport=httpx.MockTransport(handler))
    r = await p.lookup(None, uuid.uuid4(), "ip", "198.51.100.23")  # type: ignore[arg-type]
    assert r is not None and r.verdict == "malicious" and r.confidence == 0.8 and "tlp:amber" in r.tags
    assert r.references == ["https://misp.example/events/view/17"]

    failing = MispProvider("https://misp.example", "k", transport=httpx.MockTransport(lambda _: httpx.Response(500)))
    assert await failing.lookup(None, uuid.uuid4(), "ip", "1.2.3.4") is None  # type: ignore[arg-type]

    for bad in ("file:///etc/passwd", "gopher://x", "https://user:pw@host"):
        try:
            validate_integration_url(bad, allow_http=True)
            raise AssertionError(bad)
        except ValueError:
            pass


async def test_opensearch_sink_bulk_indexes_with_tenant(monkeypatch) -> None:
    import json as _json

    from sentinelx.config import get_settings
    from sentinelx.ingestion import opensearch_sink
    from sentinelx.ingestion.parsers import suricata

    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.test:9200")
    get_settings.cache_clear()
    opensearch_sink._template_ready = False
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_bulk"):
            seen["bulk"] = request.content.decode()
            return httpx.Response(200, json={"items": [{"index": {"status": 201}}]})
        seen["template"] = request.url.path
        return httpx.Response(200, json={"acknowledged": True})

    tid = uuid.uuid4()
    rec = _json.loads((FIXTURES / "suricata/eve.json").read_text().splitlines()[0])
    try:
        n = await opensearch_sink.index_events([suricata.parse(rec, tid)], transport=httpx.MockTransport(handler))
    finally:
        monkeypatch.delenv("OPENSEARCH_URL")
        get_settings.cache_clear()
    assert n == 1 and seen["template"] == "/_index_template/sentinelx-events"
    action, doc = (_json.loads(x) for x in seen["bulk"].strip().splitlines())
    assert action["index"]["_index"].startswith("sentinelx-events-2026.10.")
    assert doc["tenant_id"] == str(tid) and "raw_event" not in doc
