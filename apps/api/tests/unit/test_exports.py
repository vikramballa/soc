"""OCSF finding and ATT&CK Navigator layer exports."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sentinelx.export.navigator import build_layer
from sentinelx.export.ocsf import (
    DETECTION_FINDING,
    INCIDENT_FINDING,
    OCSF_VERSION,
    detection_finding,
    incident_finding,
    severity_id_from_score,
)
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import Alert, Incident

T0 = datetime(2026, 10, 6, 9, 30, tzinfo=UTC)
TENANT = uuid.uuid4()


def _alert(**kw: object) -> Alert:
    base: dict[str, object] = dict(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        rule_uid="ee71e69d-9a6d-45ba-b784-e94261bb0053",
        title="Suspicious PowerShell Command Line",
        description="Encoded PowerShell",
        source="sigma",
        severity=75,
        level="high",
        status="open",
        hostname="ws-017",
        username="CORP\\bob",
        src_ip="10.10.20.17",
        dest_ip=None,
        domain=None,
        process_name="powershell.exe",
        file_hash=None,
        mitre_techniques=["T1059.001", "T9999"],
        event_count=3,
        source_types=["wazuh"],
        details={},
        first_event_at=T0,
        last_event_at=T0 + timedelta(minutes=2),
        created_at=T0 + timedelta(minutes=2),
        incident_id=None,
    )
    base.update(kw)
    return Alert(**base)


def test_detection_finding_shape_and_mapping() -> None:
    f = detection_finding(_alert(), get_catalog())
    assert f["class_uid"] == DETECTION_FINDING and f["category_uid"] == 2
    assert f["type_uid"] == DETECTION_FINDING * 100 + f["activity_id"]
    assert f["metadata"]["version"] == OCSF_VERSION and f["metadata"]["product"]["name"] == "SentinelX"
    assert f["time"] == int((T0 + timedelta(minutes=2)).timestamp() * 1000)
    assert (f["severity_id"], f["severity"]) == (4, "High") and (f["status_id"], f["status"]) == (1, "New")
    info = f["finding_info"]
    assert info["analytic"] == {
        "uid": "ee71e69d-9a6d-45ba-b784-e94261bb0053",
        "name": "Suspicious PowerShell Command Line",
        "type_id": 1,
        "type": "Rule",
    }
    # unknown technique ids are dropped, sub-techniques nest under their parent
    assert len(info["attacks"]) == 1
    attack = info["attacks"][0]
    assert attack["technique"]["uid"] == "T1059" and attack["sub_technique"]["uid"] == "T1059.001"
    assert attack["tactic"]["name"] == "Execution" and attack["version"] == get_catalog().version
    kinds = {(o["name"], o["type_id"]) for o in f["observables"]}
    assert kinds == {("hostname", 1), ("src_ip", 2), ("username", 4), ("process_name", 9)}


def test_severity_scale() -> None:
    assert [severity_id_from_score(s) for s in (10, 30, 50, 75, 90)] == [1, 2, 3, 4, 5]


def test_incident_finding_shape_and_mapping() -> None:
    inc = Incident(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        number=7,
        title="Possible intrusion on ws-017",
        description="",
        category="intrusion",
        severity="critical",
        risk_score=92,
        risk_breakdown=[{"factor": "x", "points": 10}],
        confidence=0.8,
        status="investigating",
        promotion_reason="high severity",
        first_event_at=T0,
        last_event_at=T0 + timedelta(minutes=5),
        mitre_techniques=["T1059.001"],
        alert_count=1,
        event_count=3,
        source_types=["wazuh"],
        disposition="true_positive",
        assigned_to=None,
    )
    f = incident_finding(inc, [_alert()], get_catalog(), "https://soc.example.test/")
    assert f["class_uid"] == INCIDENT_FINDING and f["type_uid"] == 200501
    assert (f["severity_id"], f["status_id"], f["priority_id"]) == (5, 2, 4)
    assert (f["verdict_id"], f["verdict"]) == (2, "True Positive")
    assert f["src_url"] == f"https://soc.example.test/incidents/{inc.id}"
    assert len(f["finding_info_list"]) == 1 and f["unmapped"]["sentinelx"]["risk_score"] == 92
    assert "assignee" not in f


def test_navigator_layer() -> None:
    cat = get_catalog()
    layer = build_layer(
        cat,
        "coverage",
        {"T1059.001": 2, "T1110": 1, "T9999": 4, "T1685.005": 0},
        {"T1059.001": ["Rule A", "Rule B"]},
        "test",
    )
    assert layer["versions"] == {"attack": cat.version.split(".")[0], "navigator": "5.1.0", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert set(by_id) == {"T1059.001", "T1110", "T1059"}  # unknown and zero-score dropped, parent added
    assert by_id["T1059"]["showSubtechniques"] is True and "score" not in by_id["T1059"]
    assert by_id["T1059.001"]["score"] == 2 and by_id["T1059.001"]["comment"] == "2 rule(s)"
    assert [m["value"] for m in by_id["T1059.001"]["metadata"]] == ["Rule A", "Rule B"]
    assert layer["gradient"]["maxValue"] == 2
