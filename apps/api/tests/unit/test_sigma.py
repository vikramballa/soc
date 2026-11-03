"""Sigma compiler / evaluator and rule repository validation."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from sentinelx.config import get_settings
from sentinelx.detection.sigma.compiler import SigmaCompileError, compile_detection
from sentinelx.detection.sigma.rules import load_rules, parse_timespan
from sentinelx.mitre.catalog import get_catalog


def ev(**kw: Any) -> dict[str, Any]:
    base = {"event_type": "process", "source_type": "wazuh", "metadata": {}, "raw_event": {}}
    base.update(kw)
    return base


def det(d: str) -> Any:
    return compile_detection(yaml.safe_load(d))


def test_modifiers_and_case_insensitivity() -> None:
    p = det("""
sel:
  Image|endswith: '\\powershell.exe'
  CommandLine|contains|all: [' -nop', 'hidden']
condition: sel
""")
    assert p(ev(process_path=r"C:\WINDOWS\System32\PowerShell.EXE", process_command_line="x -NOP -w HIDDEN"))
    assert not p(ev(process_path=r"C:\x\cmd.exe", process_command_line="x -nop hidden"))
    assert not p(ev(process_path=r"C:\x\powershell.exe", process_command_line="x -nop"))


def test_wildcards_escapes_and_lists() -> None:
    p = det("""
sel:
  CommandLine: ['*whoami /all*', 'net user\\*']
condition: sel
""")
    assert p(ev(process_command_line="cmd /c whoami /all"))
    assert p(ev(process_command_line="net user*"))
    assert not p(ev(process_command_line="net users"))


def test_condition_grammar() -> None:
    p = det("""
a: {event_action: x}
b: {outcome: failure}
filter_1: {username: svc}
condition: (a or b) and not 1 of filter_*
""")
    assert p(ev(event_action="x", username="bob"))
    assert p(ev(outcome="failure"))
    assert not p(ev(outcome="failure", username="svc"))
    q = det("""
sel_a: {event_action: x}
sel_b: {outcome: failure}
condition: all of sel_*
""")
    assert q(ev(event_action="x", outcome="failure")) and not q(ev(event_action="x"))


def test_numeric_cidr_regex_exists_windash_null() -> None:
    assert det("s: {bytes_out|gte: 100}\ncondition: s")(ev(bytes_out=150))
    assert not det("s: {bytes_out|gte: 100}\ncondition: s")(ev(bytes_out="abc"))
    assert det("s: {DestinationIp|cidr: 10.0.0.0/8}\ncondition: s")(ev(dest_ip="10.1.2.3"))
    assert not det("s: {DestinationIp|cidr: 10.0.0.0/8}\ncondition: s")(ev(dest_ip="11.1.2.3"))
    assert det("s: {QueryName|re: '^[a-z]{3}\\.'}\ncondition: s")(ev(domain="abc.example"))
    assert det("s: {username|exists: false}\ncondition: s")(ev())
    assert det("s: {CommandLine|windash|contains: ' -enc '}\ncondition: s")(ev(process_command_line="ps /enc AAA"))
    # reverse direction: rule written with '/', event logs the '-' form
    assert det("s: {CommandLine|windash|contains: ' /enc '}\ncondition: s")(ev(process_command_line="ps -enc AAA"))
    # mixed: two switches, each using a different dash char independently
    assert det("s: {CommandLine|windash|contains: ' -a /b '}\ncondition: s")(ev(process_command_line="ps /a -b AAA"))
    assert det("s: {username: null}\ncondition: s")(ev(username=None))
    assert det("s: {metadata.group|contains: admin}\ncondition: s")(ev(metadata={"group": "Domain Admins"}))


def test_keywords() -> None:
    p = det("keywords: ['mimikatz', 'sekurlsa']\ncondition: keywords")
    assert p(ev(process_command_line="run sekurlsa::logonpasswords"))
    assert not p(ev(process_command_line="notepad"))


@pytest.mark.parametrize(
    "bad",
    [
        "s: {x|base64offset: a}\ncondition: s",
        "s: {x: 1}\ncondition: s | count() > 5",
        "s: {x: 1}\ncondition: missing",
        "s: {x: 1}\ncondition: (s",
    ],
)
def test_unsupported_constructs_fail_loudly(bad: str) -> None:
    with pytest.raises(SigmaCompileError):
        det(bad)


def test_repository_rules_all_load_and_map_to_real_attack_ids() -> None:
    rs = load_rules(get_settings().sigma_rules_dir)
    assert not rs.errors, rs.errors
    assert len(rs.rules) >= 20 and len(rs.correlations) >= 7
    cat = get_catalog()
    for r in [*rs.rules, *rs.correlations]:
        for t in r.techniques:
            assert cat.exists(t), f"{r.title}: {t} is not a current ATT&CK technique"
    # chained correlation is ordered after its dependency
    order = [c.name for c in rs.correlations]
    assert order.index("brute_force_logon") < order.index("logon_after_brute_force")


def test_repository_rules_validate_with_reference_pysigma() -> None:
    """Cross-check the rule files with the reference Sigma parser (pySigma)."""
    from sigma.collection import SigmaCollection

    for path in get_settings().sigma_rules_dir.rglob("*.yml"):
        coll = SigmaCollection.from_yaml(path.read_text())
        assert not coll.errors, (path, coll.errors)


def test_timespan() -> None:
    assert parse_timespan("10m") == 600 and parse_timespan("1h") == 3600 and parse_timespan("2d") == 172800
    with pytest.raises(SigmaCompileError):
        parse_timespan("10 minutes")


# Sigma v2 filters ------------------------------------------------------------------------------------

_BASE_RULE = """title: Whoami Execution
id: 0b6d6b6e-0000-4000-8000-000000000001
name: whoami_exec
logsource: {category: process_creation, product: windows}
detection:
  sel: {Image|endswith: '\\\\whoami.exe'}
  condition: sel
level: medium
"""

_FILTER = """title: Ignore inventory service account
id: 0b6d6b6e-0000-4000-8000-0000000000f1
logsource: {category: process_creation, product: windows}
filter:
  rules: [whoami_exec]
  selection: {User|startswith: 'svc_inventory'}
  condition: not selection
"""


def _load(*docs: str) -> Any:
    return load_rules(None, [(f"t{i}", d) for i, d in enumerate(docs)])


def test_filter_excludes_matching_events_and_is_switchable() -> None:
    rs = _load(_BASE_RULE, _FILTER)
    assert not rs.errors and len(rs.filters) == 1
    rule = rs.rules[0]
    flt = rs.filters[0]
    assert flt.resolved_refs == [rule.uid] and rule.filters == [flt]
    hit = ev(process_path=r"C:\Windows\System32\whoami.exe", username="alice")
    benign = ev(process_path=r"C:\Windows\System32\whoami.exe", username="svc_inventory01")
    assert rule.matches(hit) and not rule.matches(benign)
    # switched off for this organization -> the rule sees everything again
    assert rule.matches(benign, enabled={rule.uid})
    assert not rule.matches(benign, enabled={rule.uid, flt.uid})


def test_filter_rejections() -> None:
    unknown = _load(_BASE_RULE, _FILTER.replace("[whoami_exec]", "[no_such_rule]"))
    assert unknown.filters == [] and "unknown rules" in unknown.errors[0][1]
    assert unknown.rules[0].filters == []
    mismatch = _load(_BASE_RULE, _FILTER.replace("product: windows", "product: linux"))
    assert mismatch.filters == [] and "logsource does not match" in mismatch.errors[0][1]
    no_refs = _load(_BASE_RULE, _FILTER.replace("rules: [whoami_exec]", "rules: []"))
    assert no_refs.filters == [] and "at least one referenced rule" in no_refs.errors[0][1]
    corr = """title: c
id: 0b6d6b6e-0000-4000-8000-0000000000c1
name: corr1
correlation: {type: event_count, rules: [whoami_exec], group-by: [Computer], timespan: 5m, condition: {gte: 3}}
"""
    on_corr = _load(_BASE_RULE, corr, _FILTER.replace("[whoami_exec]", "[corr1]"))
    assert on_corr.filters == [] and any("not correlations" in e for _, e in on_corr.errors)


def test_bundled_filters_are_valid() -> None:
    rs = load_rules(get_settings().sigma_rules_dir)
    assert not rs.errors
    for f in rs.filters:
        assert f.resolved_refs, f.uid
