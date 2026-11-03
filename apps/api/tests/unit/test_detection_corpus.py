"""Detection regression corpus: every bundled Sigma rule fires on its true positives and stays quiet on its
near-misses (security/detection-tests/cases.yml). Adding a rule without test cases fails here."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelx.config import REPO_ROOT, get_settings
from sentinelx.detection.sigma.rules import SigmaRule, load_rules

CORPUS = REPO_ROOT / "security" / "detection-tests" / "cases.yml"


def _rules() -> dict[str, SigmaRule]:
    rs = load_rules(get_settings().sigma_rules_dir)
    assert not rs.errors, rs.errors
    return {r.uid: r for r in rs.rules}


def _cases(path: Path = CORPUS) -> list[dict[str, Any]]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _event(fields: dict[str, Any]) -> dict[str, Any]:
    return {"source_type": "sentinelx", "metadata": {}, "raw_event": {}, **fields}


def test_every_bundled_rule_has_positive_and_negative_cases() -> None:
    rules = _rules()
    cases = _cases()
    by_rule = {c["rule"]: c for c in cases}
    assert len(by_rule) == len(cases), "duplicate rule entries in the corpus"
    assert not set(by_rule) - set(rules), f"corpus references unknown rules: {set(by_rule) - set(rules)}"
    missing = sorted(f"{r.uid} ({r.title})" for r in rules.values() if r.uid not in by_rule)
    assert not missing, f"rules without detection test cases: {missing}"
    for c in cases:
        assert c.get("match") and c.get("no_match"), f"{c['rule']} needs both match and no_match events"


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["rule"][:8])
def test_rule_behaviour(case: dict[str, Any]) -> None:
    rule = _rules()[case["rule"]]
    for fields in case["match"]:
        assert rule.matches(_event(fields)), f"{rule.title} should fire on {fields}"
    for fields in case["no_match"]:
        assert not rule.matches(_event(fields)), f"{rule.title} should not fire on {fields}"
