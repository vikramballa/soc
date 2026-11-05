"""Import community Sigma rules (e.g. a local clone of github.com/SigmaHQ/sigma) as custom rules.

Every rule is compiled by the same in-process compiler as the bundled rules; rules that use features
it does not support (unknown log sources, field modifiers, aggregation syntax) are reported, not
silently half-imported. Imported rules keep their original content plus an attribution header, as the
SigmaHQ Detection Rule License (DRL 1.1) requires. Nothing is downloaded by SentinelX itself.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.detection.sigma.rules import LEVEL_SEVERITY, SigmaCorrelation, content_hash, load_rules
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.models import DetectionRule, RuleVersion

STATUS_ORDER = ["experimental", "test", "stable"]
SKIP_STATUSES = {"deprecated", "unsupported"}


@dataclass
class ImportReport:
    scanned: int = 0
    imported: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    unsupported: Counter[str] = field(default_factory=Counter)
    unknown_techniques: Counter[str] = field(default_factory=Counter)
    examples: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned,
            "imported": self.imported,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "skipped": dict(self.skipped.most_common()),
            "unsupported": dict(self.unsupported.most_common(15)),
            "unknown_techniques": dict(self.unknown_techniques.most_common(15)),
            "examples": self.examples,
        }


def _reason(err: str) -> str:
    """Group compiler errors into a few readable buckets."""
    for key in ("unsupported logsource category", "unsupported modifier", "aggregation", "correlation", "YAML"):
        if key in err:
            return key
    return err.split(":")[0][:80]


def _header(rel: str, source: str) -> str:
    return f"# Imported from {source}: {rel}\n# License: Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License\n"


def _read_tree(root: Path) -> list[tuple[str, str]]:
    paths = sorted([*root.rglob("*.yml"), *root.rglob("*.yaml")])
    return [(str(p.relative_to(root)), p.read_text(encoding="utf-8", errors="replace")) for p in paths]


async def import_directory(
    session: AsyncSession,
    root: Path,
    *,
    source: str = "SigmaHQ",
    min_status: str = "test",
    min_level: str = "low",
    enable: bool = True,
    actor: str = "sigma-import",
    dry_run: bool = False,
) -> ImportReport:
    rep = ImportReport()
    catalog = get_catalog()
    min_s = STATUS_ORDER.index(min_status)
    min_l = LEVEL_SEVERITY[min_level]
    existing = {r.rule_uid: r for r in (await session.execute(select(DetectionRule))).scalars()}
    files = _read_tree(root)  # small text files; read up-front so the loop below only does database work
    for rel, text in files:
        try:
            docs = [d for d in yaml.safe_load_all(text) if d]
        except yaml.YAMLError:
            rep.unsupported["YAML"] += 1
            continue
        if len(docs) != 1 or not isinstance(docs[0], dict):
            rep.skipped["multi-document file"] += 1
            continue
        rep.scanned += 1
        doc = docs[0]
        status = str(doc.get("status", "experimental"))
        if status in SKIP_STATUSES:
            rep.skipped[f"status {status}"] += 1
            continue
        if status in STATUS_ORDER and STATUS_ORDER.index(status) < min_s:
            rep.skipped[f"status {status}"] += 1
            continue
        if LEVEL_SEVERITY.get(str(doc.get("level", "medium")), 50) < min_l:
            rep.skipped["below minimum level"] += 1
            continue
        if "correlation" in doc:
            rep.skipped["correlation rule (import its base rules first)"] += 1
            continue
        uid = str(doc.get("id") or "")
        current = existing.get(uid)
        if not uid or (current is not None and current.source_path is not None):
            rep.skipped["id missing or clashes with a bundled rule"] += 1
            continue
        content = _header(rel, source) + text.strip() + "\n"
        rs = load_rules(None, [(f"import:{rel}", content)])
        if rs.errors or not rs.rules:
            err = rs.errors[0][1] if rs.errors else "not compiled"
            bucket = _reason(err)
            rep.unsupported[bucket] += 1
            rep.examples.setdefault(bucket, f"{rel}: {err}"[:300])
            continue
        rule = rs.rules[0]
        assert not isinstance(rule, SigmaCorrelation)
        for t in rule.techniques:
            if not catalog.exists(t):
                rep.unknown_techniques[t] += 1
        techniques = [t for t in rule.techniques if catalog.exists(t)]
        sha = content_hash(content)
        if current is not None and current.content_sha256 == sha:
            rep.unchanged += 1
            continue
        if dry_run:
            rep.imported += current is None
            rep.updated += current is not None
            continue
        if current is None:
            row = DetectionRule(
                id=uuid.uuid4(),
                rule_uid=uid,
                name=rule.name,
                title=rule.title[:300],
                description=rule.description,
                kind="sigma",
                status=rule.status,
                level=rule.level,
                severity=rule.severity,
                tags=[*rule.tags, f"source.{source.lower()}"],
                mitre_techniques=techniques,
                content=content,
                content_sha256=sha,
                version=1,
                enabled=enable,
                generates_alerts=True,
                source_path=None,
                falsepositives=rule.falsepositives,
            )
            session.add(row)
            await session.flush()
            existing[uid] = row
            rep.imported += 1
        else:
            row = current
            row.version += 1
            row.title, row.description, row.level, row.severity = (
                rule.title[:300],
                rule.description,
                rule.level,
                rule.severity,
            )
            row.status, row.tags, row.mitre_techniques = (
                rule.status,
                [*rule.tags, f"source.{source.lower()}"],
                techniques,
            )
            row.content, row.content_sha256, row.falsepositives = content, sha, rule.falsepositives
            row.updated_at = func.now()
            rep.updated += 1
        session.add(
            RuleVersion(
                id=uuid.uuid4(),
                rule_id=row.id,
                version=row.version,
                content=content,
                content_sha256=sha,
                created_by=actor,
            )
        )
    return rep
