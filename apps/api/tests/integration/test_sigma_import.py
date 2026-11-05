"""Importing community (SigmaHQ-style) rules: compiled, filtered, attributed, idempotent."""

from __future__ import annotations

import uuid
from pathlib import Path

from sqlalchemy import select

from sentinelx.detection.sigma.importer import import_directory
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import DetectionRule

GOOD = """title: Suspicious Certutil Decode (community)
id: {id}
status: test
description: test rule
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\certutil.exe'
    CommandLine|contains: '-decode'
  condition: selection
level: high
tags:
  - attack.stealth
  - attack.t1140
  - attack.t9999
"""

UNSUPPORTED = """title: Needs an unknown modifier
id: {id}
status: stable
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|base64offset|contains: 'x'
  condition: selection
level: high
"""

EXPERIMENTAL = GOOD.replace("status: test", "status: experimental")
LOW = GOOD.replace("level: high", "level: low")


async def test_import_compiles_filters_and_attributes(tmp_path: Path) -> None:
    good_id = str(uuid.uuid4())
    (tmp_path / "windows").mkdir()
    (tmp_path / "windows" / "good.yml").write_text(GOOD.format(id=good_id))
    (tmp_path / "windows" / "bad.yml").write_text(UNSUPPORTED.format(id=uuid.uuid4()))
    (tmp_path / "windows" / "exp.yml").write_text(EXPERIMENTAL.format(id=uuid.uuid4()))
    (tmp_path / "windows" / "low.yml").write_text(LOW.format(id=uuid.uuid4()))

    async with system_session() as s:
        dry = await import_directory(s, tmp_path, min_status="test", min_level="medium", dry_run=True)
    assert dry.imported == 1
    async with system_session() as s:
        assert (await s.execute(select(DetectionRule).where(DetectionRule.rule_uid == good_id))).first() is None

    async with system_session() as s:
        rep = await import_directory(s, tmp_path, min_status="test", min_level="medium")
    assert rep.scanned == 4 and rep.imported == 1
    assert rep.unsupported["unsupported modifier"] == 1
    assert rep.skipped["status experimental"] == 1 and rep.skipped["below minimum level"] == 1
    assert rep.unknown_techniques["T9999"] == 1
    async with system_session() as s:
        row = (await s.execute(select(DetectionRule).where(DetectionRule.rule_uid == good_id))).scalar_one()
    assert row.content.startswith("# Imported from SigmaHQ: windows/good.yml")
    assert "Detection Rule License" in row.content
    assert row.mitre_techniques == ["T1140"] and "source.sigmahq" in row.tags and row.source_path is None

    async with system_session() as s:  # re-running is a no-op
        again = await import_directory(s, tmp_path, min_status="test", min_level="medium")
    assert again.imported == 0 and again.unchanged == 1
