"""Hunts and stateful detections that need history: telemetry silence, alert storms, first-seen
(rarity) signals, lateral first logons, and the deception / telemetry-health APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update

from sentinelx.config import get_settings
from sentinelx.detection.builtin import NEW_HOST_RULE, RARE_LINEAGE_RULE, SILENCE_RULE, STORM_RULE
from sentinelx.hunting.service import run_hunts
from sentinelx.ingestion.pipeline import ingest
from sentinelx.persistence.db import tenant_session
from sentinelx.persistence.models import Alert, TelemetrySource
from tests.helpers import make_tenant, signed_in


def _proc(host: str, parent: str, child: str, minutes_ago: int = 1) -> dict[str, Any]:
    return {
        "timestamp": (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat(),
        "event_type": "process",
        "event_action": "process_start",
        "hostname": host,
        "os": "windows",
        "process_name": child,
        "parent_process_name": parent,
        "process_command_line": f"{child} /c echo {uuid.uuid4().hex[:6]}",
    }


async def _ingest(tid: uuid.UUID, records: list[dict[str, Any]], source: str = "sentinelx") -> None:
    async with tenant_session(tid) as s:
        await ingest(s, tid, source, records, run_detection_inline=True)


async def _alerts(tid: uuid.UUID, rule_uid: str) -> list[Alert]:
    async with tenant_session(tid) as s:
        return list(
            (await s.execute(select(Alert).where(Alert.tenant_id == tid, Alert.rule_uid == rule_uid))).scalars()
        )


async def test_first_seen_process_lineage_only_after_a_baseline() -> None:
    s = get_settings()
    old = s.rarity_min_baseline_days
    s.rarity_min_baseline_days = 0
    try:
        tid = await make_tenant()
        await _ingest(tid, [_proc("ws1", "explorer.exe", "chrome.exe")])  # no baseline yet: learn quietly
        assert await _alerts(tid, RARE_LINEAGE_RULE) == []
        await _ingest(tid, [_proc("ws1", "explorer.exe", "chrome.exe"), _proc("ws2", "winword.exe", "mshta.exe")])
        [alert] = await _alerts(tid, RARE_LINEAGE_RULE)
        assert "winword.exe > mshta.exe" in alert.title and alert.severity < 50  # a weak signal, never alone
        await _ingest(tid, [_proc("ws3", "winword.exe", "mshta.exe")])  # seen before now
        assert len(await _alerts(tid, RARE_LINEAGE_RULE)) == 1
    finally:
        s.rarity_min_baseline_days = old


async def test_first_logon_to_a_new_host_from_inside_the_network() -> None:
    tid = await make_tenant()

    def logon(host: str, minutes_ago: int) -> dict[str, Any]:
        return {
            "timestamp": (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat(),
            "event_type": "authentication",
            "event_action": "logon",
            "outcome": "success",
            "username": "jdoe",
            "hostname": host,
            "src_ip": "10.20.30.17",
            "metadata": {"logon_type": "3"},
        }

    await _ingest(tid, [logon("FS01", 300 - i) for i in range(6)])
    assert await _alerts(tid, NEW_HOST_RULE) == []
    await _ingest(tid, [logon("DC01", 1)])
    [alert] = await _alerts(tid, NEW_HOST_RULE)
    assert alert.hostname == "DC01" and "first time" in alert.title


async def test_silent_sender_raises_alert_unless_muted() -> None:
    tid = await make_tenant()
    rec = {
        "timestamp": "2026-11-05T09:00:00.000+0000",
        "rule": {"id": "5501", "level": 3, "description": "Login session opened", "groups": ["pam"]},
        "agent": {"id": "021", "name": "linux-app-01", "ip": "10.20.30.21"},
        "full_log": "x",
    }
    await _ingest(tid, [{**rec, "id": f"e{i}"} for i in range(get_settings().silence_min_events)], source="wazuh")
    async with tenant_session(tid) as s:
        await s.execute(
            update(TelemetrySource)
            .where(TelemetrySource.tenant_id == tid)
            .values(
                first_seen=datetime.now(UTC) - timedelta(days=2),
                last_seen=datetime.now(UTC) - timedelta(hours=3),
                avg_gap_seconds=60,
            )
        )
    async with signed_in(tid, "TENANT_ADMIN") as c:
        src = (await c.get("/api/v1/telemetry/sources")).json()["items"]
        [agent] = [x for x in src if x["sender"] == "linux-app-01"]
        assert agent["status"] == "overdue"
        r = await c.post(f"/api/v1/telemetry/sources/{agent['id']}/mute", json={"minutes": 60, "reason": "patching"})
        assert r.status_code == 200 and r.json()["status"] == "muted"
        async with tenant_session(tid) as s:
            await run_hunts(s, tid)
        assert await _alerts(tid, SILENCE_RULE) == []
        assert (await c.delete(f"/api/v1/telemetry/sources/{agent['id']}/mute")).status_code == 200
    async with tenant_session(tid) as s:
        out = await run_hunts(s, tid)
    assert out["silent_sources"] == 1
    [alert] = await _alerts(tid, SILENCE_RULE)
    assert alert.hostname == "linux-app-01" and "stopped" in alert.title
    async with tenant_session(tid) as s:  # one alert per silence, not one per hunt run
        await run_hunts(s, tid)
    assert len(await _alerts(tid, SILENCE_RULE)) == 1
    await _ingest(tid, [{**rec, "id": "resumed"}], source="wazuh")  # it comes back
    async with tenant_session(tid) as s:
        row = (await s.execute(select(TelemetrySource).where(TelemetrySource.tenant_id == tid))).scalar_one()
    assert row.silent_since is None


async def test_one_off_bulk_import_is_never_reported_silent() -> None:
    tid = await make_tenant()
    rec = {
        "timestamp": "2026-11-05T09:00:00.000+0000",
        "rule": {"id": "5501", "level": 3, "description": "x", "groups": ["pam"]},
        "agent": {"id": "022", "name": "old-archive", "ip": "10.20.30.22"},
    }
    await _ingest(tid, [{**rec, "id": f"b{i}"} for i in range(50)], source="wazuh")
    async with tenant_session(tid) as s:  # imported long ago, in one go
        await s.execute(
            update(TelemetrySource)
            .where(TelemetrySource.tenant_id == tid)
            .values(first_seen=datetime.now(UTC) - timedelta(days=5), last_seen=datetime.now(UTC) - timedelta(days=5))
        )
    async with tenant_session(tid) as s:
        assert (await run_hunts(s, tid))["silent_sources"] == 0


async def test_alert_storm_needs_a_baseline_and_a_spike() -> None:
    s = get_settings()
    old = s.alert_storm_min_alerts
    s.alert_storm_min_alerts = 20
    try:
        tid = await make_tenant()
        now = datetime.now(UTC)

        def alert(created: datetime) -> Alert:
            return Alert(
                id=uuid.uuid4(),
                tenant_id=tid,
                rule_uid="noise",
                title="noise",
                source="sigma",
                severity=30,
                level="low",
                dedup_key=uuid.uuid4().hex,
                first_event_at=created,
                last_event_at=created,
                created_at=created,
                details={},
                mitre_techniques=[],
                source_types=[],
            )

        async with tenant_session(tid) as db:
            db.add(alert(now - timedelta(days=3)))
            for _ in range(30):
                db.add(alert(now - timedelta(minutes=2)))
        async with tenant_session(tid) as db:
            out = await run_hunts(db, tid)
        assert out["alert_storm"] == 1
        [storm] = await _alerts(tid, STORM_RULE)
        assert storm.details["alert_storm"]["alerts_last_10_min"] == 30
    finally:
        s.alert_storm_min_alerts = old


async def test_honeytoken_api_is_admin_only_and_validates_decoys() -> None:
    tid = await make_tenant()
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        assert (await c.get("/api/v1/deception/honeytokens")).status_code == 403
    async with signed_in(tid, "TENANT_ADMIN") as c:
        r = await c.post("/api/v1/deception/honeytokens", json={"kind": "file", "value": "a.txt"})
        assert r.status_code == 422  # too short: would match ordinary paths
        r = await c.post("/api/v1/deception/honeytokens", json={"kind": "ip", "value": "10.20.30.999"})
        assert r.status_code == 422
        r = await c.post(
            "/api/v1/deception/honeytokens",
            json={"kind": "account", "value": "SVC_Backup_Legacy", "description": "decoy service account"},
        )
        assert r.status_code == 201 and r.json()["value"] == "svc_backup_legacy"
        tok = r.json()["id"]
        dup = await c.post("/api/v1/deception/honeytokens", json={"kind": "account", "value": "svc_backup_legacy"})
        assert dup.status_code == 409
        listing = (await c.get("/api/v1/deception/honeytokens")).json()
        assert len(listing["items"]) == 1 and "account" in listing["kinds"]
    await _ingest(
        tid,
        [
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "event_type": "authentication",
                "event_action": "logon",
                "outcome": "failure",
                "username": "svc_backup_legacy",
                "hostname": "FS01",
                "src_ip": "10.20.30.17",
            }
        ],
    )
    async with tenant_session(tid) as s:
        [alert] = (
            await s.execute(select(Alert).where(Alert.tenant_id == tid, Alert.rule_uid == "sx-honeytoken"))
        ).scalars()
    assert alert.severity >= 90 and alert.level == "critical"
    async with signed_in(tid, "TENANT_ADMIN") as c:
        items = (await c.get("/api/v1/deception/honeytokens")).json()["items"]
        assert items[0]["trigger_count"] == 1
        assert (await c.delete(f"/api/v1/deception/honeytokens/{tok}")).status_code == 204
