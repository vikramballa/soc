"""Adversary replay: every synthetic attack scenario in security/attack-replay must be detected by the
rule(s) it names. This is the evidence behind the "tested" marks on the ATT&CK coverage page."""

from __future__ import annotations

import pytest

from sentinelx.detection.replay import load_scenarios, replayed_techniques, run_all
from sentinelx.mitre.catalog import get_catalog

SCENARIOS = load_scenarios()


def test_scenarios_are_well_formed() -> None:
    assert len(SCENARIOS) >= 20
    ids = [s["id"] for s in SCENARIOS]
    assert len(ids) == len(set(ids))
    catalog = get_catalog()
    for sc in SCENARIOS:
        assert sc["expect"], sc["id"]
        for t in sc["techniques"]:
            assert catalog.exists(t), (sc["id"], t)
    assert {"T1558.003", "T1003.006", "T1071", "T1685"} <= replayed_techniques()


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
async def test_attack_is_detected(scenario: dict) -> None:
    [result] = await run_all([scenario])
    assert result.passed, f"{scenario['name']}: missing {result.missing}; fired {result.fired}"
