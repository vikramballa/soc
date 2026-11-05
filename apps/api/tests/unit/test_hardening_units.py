"""Pure functions behind the hardening and hunting features: TOTP, secret sealing, beacon scoring,
new parser mappings and Sigma field fallbacks."""

from __future__ import annotations

import random
import uuid

import pytest

from sentinelx.detection.builtin import honeytoken_matches, prevalence_keys
from sentinelx.detection.sigma.fields import get_value
from sentinelx.hunting.scoring import base_domain, beacon_score, bowley_skew
from sentinelx.ingestion.parsers import canarytokens, wazuh, zeek
from sentinelx.security import secretbox, totp
from sentinelx.threat_intel.service import classify_indicator

TID = uuid.uuid4()


def test_totp_matches_rfc6238_reference_vector() -> None:
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of the RFC test key "12345678901234567890"
    assert totp.code_at(secret, 59 // 30) == "287082"  # RFC 6238 SHA-1 vector 94287082, 6 digits
    assert totp.code_at(secret, 1111111109 // 30) == "081804"
    step = totp.verify(secret, totp.code_at(secret, totp.current_step()), None)
    assert step == totp.current_step()
    assert totp.verify(secret, totp.code_at(secret, step), last_step=step) is None  # no replay
    assert totp.verify(secret, "12345", None) is None


def test_recovery_codes_are_unique_and_hash_normalised() -> None:
    codes = totp.new_recovery_codes()
    assert len(set(codes)) == 8
    assert totp.recovery_hash(codes[0].upper()) == totp.recovery_hash(f" {codes[0]} ")


def test_secretbox_roundtrip_and_tamper_detection() -> None:
    sealed = secretbox.seal("JBSWY3DPEHPK3PXP", "totp")
    assert "JBSWY3DP" not in sealed
    assert secretbox.open_sealed(sealed, "totp") == "JBSWY3DPEHPK3PXP"
    with pytest.raises(Exception):  # noqa: B017 - any authentication failure is fine
        secretbox.open_sealed(sealed, "other-purpose")
    with pytest.raises(Exception):  # noqa: B017
        secretbox.open_sealed(sealed[:-4] + "AAAA", "totp")


def test_beacon_score_separates_timers_from_human_traffic() -> None:
    timer = [i * 60.0 for i in range(120)]
    sc = beacon_score(timer, [1830] * 120)
    assert sc is not None and sc.score > 0.95 and sc.median_interval_s == 60
    jittered = [i * 60.0 + random.Random(i).uniform(-3, 3) for i in range(120)]
    assert (beacon_score(jittered, [1830] * 120) or sc).score > 0.85  # small jitter is still a beacon
    rng = random.Random(7)
    human, t = [], 0.0
    for _ in range(120):
        t += rng.expovariate(1 / 300)
        human.append(t)
    sizes = [rng.randint(200, 90000) for _ in range(120)]
    hs = beacon_score(human, sizes)
    assert hs is not None and hs.score < 0.7
    assert beacon_score([1.0, 2.0], None) is None
    assert bowley_skew([1, 1, 1, 1]) == 0


def test_base_domain_handles_two_level_suffixes() -> None:
    assert base_domain("a.b.exfil-tunnel.example") == "exfil-tunnel.example"
    assert base_domain("x.service.co.uk") == "service.co.uk"


def test_ja4_fingerprints_are_classified() -> None:
    assert classify_indicator("t13d1516h2_8daaf6152771_02713d6af862") == "ja4"
    assert classify_indicator("e7d705a3286e19ea42f587b344ee6865") == "hash"


def _wazuh(eid: str, ed: dict, channel: str = "Security") -> dict:
    return {
        "timestamp": "2026-11-05T10:00:00.000+0000",
        "rule": {"id": "1", "level": 5, "description": "x", "groups": ["windows"]},
        "agent": {"id": "001", "name": "WS1"},
        "data": {"win": {"system": {"eventID": eid, "channel": channel}, "eventdata": ed}},
    }


def test_wazuh_maps_kerberos_directory_and_sysmon_events() -> None:
    ev = wazuh.parse(
        _wazuh("4769", {"targetUserName": "jdoe@CORP", "serviceName": "svc_sql", "ticketEncryptionType": "0x17"}),
        TID,
    )
    assert (ev.event_type, ev.event_action, ev.username) == ("authentication", "kerberos_service_ticket", "jdoe")
    assert ev.metadata["ticket_encryption"] == "0x17"
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    acc = wazuh.parse(_wazuh("10", {"sourceImage": "C:\\x\\a.exe", "targetImage": "C:\\W\\lsass.exe"}, sysmon), TID)
    assert (acc.event_type, acc.event_action, acc.process_name) == ("process", "process_access", "a.exe")
    # Sysmon 11/13 carry an image too, but they are file / registry events, not process starts
    fc = wazuh.parse(_wazuh("11", {"image": "C:\\x\\a.exe", "targetFilename": "C:\\t\\b.ps1"}, sysmon), TID)
    assert (fc.event_type, fc.file_path) == ("file", "C:\\t\\b.ps1")
    rg = wazuh.parse(_wazuh("13", {"image": "C:\\x\\a.exe", "targetObject": "HKLM\\...\\Run\\x"}, sysmon), TID)
    assert rg.event_type == "registry" and rg.metadata["registry_key"].endswith("Run\\x")
    svc = wazuh.parse(
        _wazuh("7045", {"serviceName": "PSEXESVC", "imagePath": "%SystemRoot%\\PSEXESVC.exe"}, "System"), TID
    )
    assert (svc.event_action, svc.process_name) == ("service_installed", "PSEXESVC.exe")
    # Sigma fields with no mapping fall back to the raw Windows EventData field
    as_dict = {**svc.model_dump(), "raw_event": svc.raw_event}
    assert get_value(as_dict, "ServiceType") is None
    assert get_value(as_dict, "ImagePath") == "%SystemRoot%\\PSEXESVC.exe"


def test_zeek_lateral_movement_logs() -> None:
    base = {"ts": 1762336800.0, "uid": "C1", "id.orig_h": "10.0.0.5", "id.orig_p": 1, "id.resp_h": "10.0.0.2"}
    k = zeek.parse(
        {**base, "request_type": "TGS", "client": "jdoe/CORP", "cipher": "rc4-hmac", "success": True}, TID, "kerberos"
    )
    assert (k.event_type, k.username, k.metadata["cipher"]) == ("authentication", "jdoe", "rc4-hmac")
    d = zeek.parse({**base, "endpoint": "drsuapi", "operation": "DRSGetNCChanges"}, TID, "dce_rpc")
    assert d.metadata["operation"] == "DRSGetNCChanges"
    f = zeek.parse(
        {**base, "action": "SMB::FILE_WRITE", "path": "\\\\10.0.0.2\\ADMIN$", "name": "x.exe"}, TID, "smb_files"
    )
    assert f.event_action == "smb_file_write" and f.file_path.endswith("ADMIN$\\x.exe")
    s = zeek.parse({**base, "server_name": "a.example", "ja4": "t13d1516h2_8daaf6152771_02713d6af862"}, TID, "ssl")
    assert s.metadata["ja4"].startswith("t13d")


def test_canarytokens_payload() -> None:
    ev = canarytokens.parse(
        {"memo": "decoy doc", "token": "t1", "src_ip": "198.51.100.9", "time": "2026-11-05 10:00:00 (UTC)"}, TID
    )
    assert ev.source_type == "canarytokens" and ev.severity == 95 and ev.timestamp.hour == 10
    with pytest.raises(ValueError):
        canarytokens.parse({"foo": "bar"}, TID)


def test_honeytoken_matching_is_exact_for_names_and_substring_for_paths() -> None:
    acct = {"kind": "account", "value": "svc_backup_legacy"}
    assert honeytoken_matches(acct, {"username": "svc_backup_legacy"}) == "username"
    assert honeytoken_matches(acct, {"username": "svc_backup_legacy2"}) is None
    f = {"kind": "file", "value": "passwords_2026.xlsx"}
    assert honeytoken_matches(f, {"file_path": "\\\\fs\\finance\\Passwords_2026.xlsx"}) == "file_path"
    ip = {"kind": "ip", "value": "10.20.30.99"}
    assert honeytoken_matches(ip, {"dest_ip": "10.20.30.99"}) == "dest_ip"
    dom = {"kind": "domain", "value": "vault.corp.example"}
    assert honeytoken_matches(dom, {"domain": "api.vault.corp.example"}) == "domain"


def test_prevalence_keys() -> None:
    ev = {
        "event_type": "process",
        "process_name": "cmd.exe",
        "parent_process_name": "WINWORD.EXE",
        "metadata": {"ja4": "T13D_ABC"},
    }
    assert prevalence_keys(ev) == [("process_lineage", "winword.exe > cmd.exe"), ("tls_fingerprint", "ja4:t13d_abc")]
