"""End-to-end: synthetic attack telemetry -> ingestion -> detection -> correlation -> risk -> MITRE -> incident."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from sentinelx.demo.loader import load_demo
from sentinelx.persistence.db import tenant_session
from sentinelx.persistence.models import Alert, Incident, IncidentEvidence, MlPrediction


@pytest.fixture(scope="module")
async def demo() -> dict:
    return await load_demo(reset=True)


async def _incidents(tenant_id: str) -> list[Incident]:
    async with tenant_session(tenant_id) as s:
        return list(
            (
                await s.execute(
                    select(Incident)
                    .where(Incident.promoted.is_(True), Incident.status != "merged")
                    .order_by(Incident.risk_score.desc())
                )
            )
            .scalars()
            .all()
        )


async def test_demo_ingests_without_quarantine(demo: dict) -> None:
    assert demo["accepted"] > 5000
    assert demo["quarantined"] == 0


async def test_account_compromise_is_one_high_incident(demo: dict) -> None:
    incs = await _incidents(demo["tenant_id"])
    acct = [i for i in incs if i.category == "account_compromise"]
    assert len(acct) == 1, [(i.title, i.category) for i in incs]
    inc = acct[0]
    assert inc.severity in ("high", "critical"), inc.risk_breakdown
    assert inc.risk_score >= 76
    for t in ("T1110", "T1078", "T1059.001"):
        assert t in inc.mitre_techniques
    assert {"wazuh", "zeek", "suricata"} <= set(inc.source_types)
    contributors = {c["key"]: c for c in inc.risk_breakdown}
    assert contributors["threat_intel"]["value"] > 0
    assert sum(c["value"] for c in inc.risk_breakdown) >= inc.risk_score - 1
    async with tenant_session(demo["tenant_id"]) as s:
        n_evidence = (
            await s.execute(
                select(func.count()).select_from(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id)
            )
        ).scalar_one()
        titles = set((await s.execute(select(Alert.title).where(Alert.incident_id == inc.id))).scalars())
    assert n_evidence >= 45
    assert "Successful Logon After Repeated Failures" in titles
    assert "Suspicious PowerShell Command Line" in titles
    assert any(t.startswith("Login from a new source") for t in titles)
    assert contributors["identity_context"]["value"] > 0


async def test_reconnaissance_incident(demo: dict) -> None:
    incs = await _incidents(demo["tenant_id"])
    recon = [i for i in incs if i.category == "reconnaissance"]
    assert len(recon) == 1, [(i.title, i.category) for i in incs]
    assert "T1046" in recon[0].mitre_techniques


async def test_noise_is_not_promoted(demo: dict) -> None:
    async with tenant_session(demo["tenant_id"]) as s:
        groups = (await s.execute(select(Incident).where(Incident.status != "merged"))).scalars().all()
    unpromoted = [g for g in groups if not g.promoted]
    assert unpromoted, "benign low-severity activity should remain an un-promoted correlation group"
    assert all("bakery" not in g.title for g in groups if g.promoted)


async def test_behavioral_anomaly_detected(demo: dict) -> None:
    assert demo["ml"]["train"]["status"] == "trained"
    async with tenant_session(demo["tenant_id"]) as s:
        anomalies = (await s.execute(select(MlPrediction).where(MlPrediction.is_anomaly.is_(True)))).scalars().all()
    assert any(a.entity_id == "WS-017" for a in anomalies)
    incs = await _incidents(demo["tenant_id"])
    ws17 = [i for i in incs if "WS-017" in i.title]
    assert ws17 and any(c["key"] == "behavioral_anomaly" and c["value"] > 0 for c in ws17[0].risk_breakdown)
