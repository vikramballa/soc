"""Parsers / normalizers: each source fixture becomes a correct canonical event."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from sentinelx.domain.events import deterministic_event_id, extract_indicators, parse_timestamp
from sentinelx.ingestion.parsers import suricata, wazuh, zeek
from tests.helpers import FIXTURES

T = uuid.UUID("00000000-0000-0000-0000-000000000001")


def _lines(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


def test_wazuh_linux_ssh_failure() -> None:
    ev = wazuh.parse(_lines(FIXTURES / "wazuh/alerts.json")[0], T)
    assert ev.event_type == "authentication" and ev.outcome == "failure"
    assert ev.username == "root" and ev.src_ip == "203.0.113.9" and ev.hostname == "srv-web01"
    assert ev.os == "linux" and ev.rule_id == "5716" and ev.mitre_techniques == ["T1110.001"]
    assert ev.severity == 33  # level 5 / 15
    assert ev.raw_event["full_log"].startswith("Oct")  # raw evidence preserved


def test_wazuh_windows_events() -> None:
    recs = _lines(FIXTURES / "wazuh/alerts.json")
    fail = wazuh.parse(recs[1], T)
    assert (fail.event_type, fail.outcome, fail.username, fail.os) == ("authentication", "failure", "jdoe", "windows")
    proc = wazuh.parse(recs[2], T)
    assert proc.event_type == "process" and proc.process_name == "powershell.exe"
    assert proc.parent_process_name == "cmd.exe" and proc.username == "jdoe"
    assert proc.file_hash and proc.file_hash.startswith("abcdef")
    fim = wazuh.parse(recs[3], T)
    assert fim.event_type == "file" and fim.event_action == "modified" and fim.file_path.endswith("budget.xlsx")
    created = wazuh.parse(recs[4], T)
    assert created.event_type == "iam" and created.event_action == "user_created"
    added = wazuh.parse(recs[5], T)
    assert added.event_action == "group_member_added" and added.metadata["privileged_group"] is True


def test_suricata_event_types() -> None:
    evs = [suricata.parse(r, T) for r in _lines(FIXTURES / "suricata/eve.json")]
    alert, dns, http, tls, flow, fileinfo = evs
    assert alert.event_type == "alert" and alert.severity == 55 and alert.rule_id == "2027865"
    assert alert.mitre_techniques == ["T1571"]
    assert dns.event_type == "dns" and dns.domain == "sync-update.duckdns.org"  # EVE dns v3 queries[]
    assert http.domain == "sync-update.duckdns.org" and http.url == "/a.ps1" and http.metadata["method"] == "GET"
    assert tls.domain == "www.google.com"
    assert flow.event_action == "connection_attempt" and flow.outcome == "failure"
    assert fileinfo.file_hash and fileinfo.file_hash == fileinfo.file_hash.lower()


def test_zeek_tsv_and_json() -> None:
    recs = list(zeek.iter_tsv(iter((FIXTURES / "zeek/conn.log").read_text().splitlines())))
    rej, sf = (zeek.parse(r, T, "conn") for r in recs)
    assert rej.event_action == "connection_attempt" and rej.dest_port == 22
    assert sf.bytes_out == 2350000 and sf.outcome == "success"
    dns = [zeek.parse(r, T, "dns") for r in _lines(FIXTURES / "zeek/dns.json")]
    assert dns[0].domain == "xkqzvbtrwplmn8z2.info" and dns[0].metadata["rcode"] == "NXDOMAIN"
    ssh = zeek.parse(_lines(FIXTURES / "zeek/ssh.json")[0], T, "ssh")
    assert ssh.outcome == "failure" and ssh.metadata["auth_attempts"] == 6
    notice = zeek.parse(_lines(FIXTURES / "zeek/notice.json")[0], T, "notice")
    assert notice.event_type == "alert" and notice.rule_id == "Scan::Port_Scan" and notice.src_ip == "10.10.30.66"


def test_deterministic_ids_and_tenant_scoping() -> None:
    rec = _lines(FIXTURES / "suricata/eve.json")[0]
    a, b = suricata.parse(rec, T), suricata.parse(rec, T)
    assert a.event_id == b.event_id  # idempotent
    other = suricata.parse(rec, uuid.uuid4())
    assert other.event_id != a.event_id  # never collides across tenants
    assert deterministic_event_id(T, "x", "1") != deterministic_event_id(T, "y", "1")


def test_invalid_records_raise() -> None:
    with pytest.raises(ValueError):
        suricata.parse({"event_type": "alert"}, T)
    with pytest.raises(ValueError):
        suricata.parse({"event_type": "nonsense", "timestamp": "2026-01-01T00:00:00Z"}, T)
    with pytest.raises(ValueError):
        wazuh.parse({"foo": 1}, T)
    with pytest.raises(ValueError):
        zeek.parse({"ts": 1}, T, "unknown")
    with pytest.raises(ValueError):
        suricata.parse({"event_type": "dns", "timestamp": "2026-01-01T00:00:00Z", "src_ip": "999.1.1.1"}, T)


def test_timestamp_formats() -> None:
    assert parse_timestamp("2026-10-06T09:12:01.123+0000").utcoffset().total_seconds() == 0
    assert parse_timestamp(1791019800.5).year == 2026
    assert parse_timestamp("1791019800.5") == parse_timestamp(1791019800.5)
    assert parse_timestamp("2026-10-06T09:12:01Z").hour == 9


def test_indicator_extraction_skips_private_ips() -> None:
    ev = suricata.parse(_lines(FIXTURES / "suricata/eve.json")[0], T)
    assert ("ip", "198.51.100.23") in extract_indicators(ev)
    assert ("ip", "10.10.20.42") not in extract_indicators(ev)
