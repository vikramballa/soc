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
