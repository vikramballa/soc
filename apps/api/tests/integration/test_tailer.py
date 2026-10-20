"""File tailing: checkpoints, appends, rotation and idempotent replays."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelx.config import get_settings
from sentinelx.ingestion.tailer import tail_configured_sources
from tests.helpers import FIXTURES


@pytest.fixture
def eve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    path = tmp_path / "eve.json"
    monkeypatch.setenv("SURICATA_EVE_PATH", str(path))
    get_settings.cache_clear()
    yield path
    monkeypatch.delenv("SURICATA_EVE_PATH")
    get_settings.cache_clear()


async def test_tailing_checkpoints_rotation_and_replay(eve: Path) -> None:
    lines = (FIXTURES / "suricata/eve.json").read_text().splitlines()
    shifted = [json.dumps({**json.loads(x), "flow_id": json.loads(x)["flow_id"] + 900000}) for x in lines]
    eve.write_text("\n".join(shifted[:2]) + "\n")
    assert (await tail_configured_sources())["suricata"] == 2
    assert (await tail_configured_sources())["suricata"] == 0  # nothing new
    with eve.open("a") as f:
        f.write(shifted[2] + "\n" + shifted[3][:40])  # one full line + a partial line
    assert (await tail_configured_sources())["suricata"] == 1  # the partial line waits
    with eve.open("a") as f:
        f.write(shifted[3][40:] + "\n")
    assert (await tail_configured_sources())["suricata"] == 1
    eve.unlink()  # rotation: new file with an already-seen record and a new one
    eve.write_text(shifted[0] + "\n" + shifted[4] + "\n")
    assert (await tail_configured_sources())["suricata"] == 1  # replayed record is deduplicated
