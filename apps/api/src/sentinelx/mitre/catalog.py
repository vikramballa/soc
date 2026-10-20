"""In-memory MITRE ATT&CK catalog (loaded once from the compact dataset; mirrored into PostgreSQL)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from sentinelx.config import get_settings


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    description: str
    is_subtechnique: bool
    parent_id: str | None
    platforms: tuple[str, ...]
    detection: str


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str
    order: int
    url: str
    description: str


class MitreCatalog:
    def __init__(self, path: Path):
        data = json.loads(path.read_text(encoding="utf-8"))
        self.version: str = str(data.get("attack_version"))
        self.tactics = [
            Tactic(t["id"], t["shortname"], t["name"], t["order"], t.get("url") or "", t.get("description", ""))
            for t in data["tactics"]
        ]
        self.tactic_by_short = {t.shortname: t for t in self.tactics}
        self.techniques: dict[str, Technique] = {
            t["id"]: Technique(
                id=t["id"],
                name=t["name"],
                tactics=tuple(t["tactics"]),
                url=t.get("url") or "",
                description=t.get("description", ""),
                is_subtechnique=t["is_subtechnique"],
                parent_id=t.get("parent_id"),
                platforms=tuple(t.get("platforms", [])),
                detection=t.get("detection", ""),
            )
            for t in data["techniques"]
        }

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.upper())

    def exists(self, technique_id: str) -> bool:
        return technique_id.upper() in self.techniques

    def tactics_for(self, technique_ids: list[str]) -> list[str]:
        """Tactic shortnames covered by techniques, in kill-chain order."""
        found: set[str] = set()
        for tid in technique_ids:
            t = self.get(tid)
            if t:
                found.update(t.tactics)
        return sorted(found, key=lambda s: self.tactic_by_short[s].order if s in self.tactic_by_short else 99)

    def label(self, technique_id: str) -> str:
        t = self.get(technique_id)
        return f"{technique_id} {t.name}" if t else technique_id


@lru_cache
def get_catalog() -> MitreCatalog:
    return MitreCatalog(get_settings().mitre_data_file)
