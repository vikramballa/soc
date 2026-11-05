"""Adversary replay: prove that detections fire, instead of assuming it.

Each scenario in ``security/attack-replay/*.json`` holds synthetic telemetry for one technique in its
native format (Wazuh, Zeek, Suricata, Canarytokens or canonical) and the rule titles that must fire.
``sentinelx validate-detections`` and the test suite replay every scenario through the real ingestion
and detection pipeline (and the periodic hunts where needed) in a throw-away organization.

Scenario format::

    {"id": "...", "name": "...", "techniques": ["T1558.003"], "source": "wazuh", "log_type": null,
     "hunt": false, "setup": {"honeytokens": [{"kind": "account", "value": "..."}]},
     "events": [{"@offset": -300, ...native record...}],
     "repeat": {"count": 60, "every_seconds": 60, "template": {...}},
     "expect": ["Rule title", ...]}

``@offset`` is seconds relative to now; the runner writes it into the source's timestamp field.
Strings in a repeat template may contain ``{i}`` (index) and ``{hex}`` (16 pseudo-random hex chars).
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select

from sentinelx.config import REPO_ROOT

SCENARIO_DIR = REPO_ROOT / "security" / "attack-replay"


@dataclass
class ReplayResult:
    scenario: str
    name: str
    techniques: list[str]
    expected: list[str]
    fired: list[str]
    missing: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.missing

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "name": self.name,
            "techniques": self.techniques,
            "expected": self.expected,
            "fired": self.fired,
            "missing": self.missing,
            "passed": self.passed,
        }


def load_scenarios(directory: Path = SCENARIO_DIR) -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]


@lru_cache(maxsize=4)
def _replayed(directory: Path) -> frozenset[str]:
    return frozenset(t for sc in load_scenarios(directory) for t in sc.get("techniques", []))


def replayed_techniques(directory: Path = SCENARIO_DIR) -> set[str]:
    """ATT&CK techniques that have a replay scenario (and therefore a tested detection)."""
    return set(_replayed(directory))


def _fill(value: Any, i: int) -> Any:
    if isinstance(value, str):
        h = hashlib.sha256(f"{i}".encode()).hexdigest()[:16]
        return value.replace("{i}", str(i)).replace("{hex}", h)
    if isinstance(value, dict):
        return {k: _fill(v, i) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, i) for v in value]
    return value


def _stamp(rec: dict[str, Any], source: str, ts: datetime) -> dict[str, Any]:
    if source == "zeek":
        rec["ts"] = ts.timestamp()
    elif source == "canarytokens":
        rec["time"] = ts.strftime("%Y-%m-%d %H:%M:%S") + " (UTC)"
    else:
        rec["timestamp"] = ts.isoformat()
    return rec


def materialize(sc: dict[str, Any], now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(UTC)
    source = sc["source"]
    out: list[dict[str, Any]] = []
    for rec in sc.get("events", []):
        r = copy.deepcopy(rec)
        offset = float(r.pop("@offset", -60))
        out.append(_stamp(r, source, now + timedelta(seconds=offset)))
    rep = sc.get("repeat")
    if rep:
        start = float(rep.get("start_offset", -rep["count"] * rep["every_seconds"]))
        for i in range(int(rep["count"])):
            r = _fill(copy.deepcopy(rep["template"]), i)
            out.append(_stamp(r, source, now + timedelta(seconds=start + i * float(rep["every_seconds"]))))
    return out


async def run_scenario(tenant_id: uuid.UUID, sc: dict[str, Any]) -> ReplayResult:
    from sentinelx.detection.builtin import BUILTIN_RULES
    from sentinelx.detection.engine import get_rules
    from sentinelx.hunting.service import run_hunts
    from sentinelx.ingestion.pipeline import ingest
    from sentinelx.persistence.db import tenant_session
    from sentinelx.persistence.models import Alert, AlertEvent, Honeytoken

    rs = get_rules().ruleset
    titles: dict[str, str] = {r.uid: r.title for r in rs.rules}
    titles.update({c.uid: c.title for c in rs.correlations})
    titles.update({b["rule_uid"]: b["title"] for b in BUILTIN_RULES})

    async with tenant_session(tenant_id) as s:
        for ht in (sc.get("setup") or {}).get("honeytokens", []):
            s.add(
                Honeytoken(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    kind=ht["kind"],
                    value=ht["value"],
                    description="replay",
                    created_by="replay",
                )
            )
    started = datetime.now(UTC)
    records = materialize(sc)
    async with tenant_session(tenant_id) as s:
        res = await ingest(s, tenant_id, sc["source"], records, sc.get("log_type"), run_detection_inline=True)
    if sc.get("hunt"):
        async with tenant_session(tenant_id) as s:
            await run_hunts(s, tenant_id)
    async with tenant_session(tenant_id) as s:
        linked = set(
            (
                await s.execute(
                    select(Alert.rule_uid)
                    .join(AlertEvent, AlertEvent.alert_id == Alert.id)
                    .where(Alert.tenant_id == tenant_id, AlertEvent.event_id.in_(res.event_ids or [uuid.uuid4()]))
                )
            ).scalars()
        )
        recent = set(
            (
                await s.execute(
                    select(Alert.rule_uid).where(
                        Alert.tenant_id == tenant_id, Alert.created_at >= started - timedelta(seconds=5)
                    )
                )
            ).scalars()
        )
    fired = sorted({titles.get(uid, uid) for uid in linked | recent})
    expected = list(sc.get("expect", []))
    return ReplayResult(
        scenario=sc["id"],
        name=sc["name"],
        techniques=list(sc.get("techniques", [])),
        expected=expected,
        fired=fired,
        missing=[t for t in expected if t not in fired],
    )


async def run_all(scenarios: list[dict[str, Any]] | None = None) -> list[ReplayResult]:
    """Replay every scenario, each in its own fresh organization (so baselines never leak between them)."""
    from sentinelx.persistence.db import system_session
    from sentinelx.persistence.models import Tenant

    results: list[ReplayResult] = []
    for sc in scenarios if scenarios is not None else load_scenarios():
        tid = uuid.uuid4()
        async with system_session() as s:
            s.add(Tenant(id=tid, slug=f"replay-{tid.hex[:12]}", name=f"Replay {sc['id']}", settings={"replay": True}))
        try:
            results.append(await run_scenario(tid, sc))
        finally:
            async with system_session() as s:
                t = await s.get(Tenant, tid)
                if t is not None:
                    await s.delete(t)
    return results
