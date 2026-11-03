"""Load and validate Sigma detection, correlation and filter rules from the versioned rules repository.

Filters (Sigma v2 meta rules) let an organization exclude known-benign activity from a shared rule without
editing it, so the bundled rules stay generic and upgradeable while local tuning lives in its own file."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinelx.detection.sigma.compiler import Predicate, SigmaCompileError, compile_detection
from sentinelx.detection.sigma.fields import MATCH_FIELDS, resolve_field

LEVEL_SEVERITY = {"informational": 10, "low": 30, "medium": 50, "high": 75, "critical": 90}
_TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TIMESPAN_RE = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# logsource.category -> canonical event types
CATEGORY_EVENT_TYPES: dict[str, set[str]] = {
    "process_creation": {"process"},
    "network_connection": {"network"},
    "firewall": {"network"},
    "dns": {"dns"},
    "dns_query": {"dns"},
    "file_event": {"file"},
    "file_change": {"file"},
    "file_modification": {"file"},
    "file_delete": {"file"},
    "authentication": {"authentication", "ssh"},
    "user_management": {"iam"},
    "proxy": {"http"},
    "webserver": {"http"},
    "tls": {"tls"},
    "ids_alert": {"alert"},
}
SOURCE_PRODUCTS = {"zeek", "suricata", "wazuh"}
OS_PRODUCTS = {"windows", "linux", "macos"}


def parse_timespan(v: str) -> int:
    m = _TIMESPAN_RE.match(str(v).strip())
    if not m:
        raise SigmaCompileError(f"invalid timespan {v!r}")
    return int(m.group(1)) * _UNITS[m.group(2)]


def techniques_from_tags(tags: list[str]) -> list[str]:
    out = []
    for t in tags:
        m = _TECH_RE.match(str(t))
        if m:
            out.append(m.group(1).upper())
    return sorted(set(out))


@dataclass
class SigmaRule:
    uid: str
    name: str | None
    title: str
    description: str
    status: str
    level: str
    logsource: dict[str, str]
    tags: list[str]
    falsepositives: list[str]
    references: list[str]
    content: str
    path: str
    predicate: Predicate
    event_types: set[str] | None
    techniques: list[str]
    generate: bool = True
    filters: list[SigmaFilter] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return LEVEL_SEVERITY.get(self.level, 50)

    def applies_to(self, ev: dict[str, Any]) -> bool:
        if self.event_types is not None and ev.get("event_type") not in self.event_types:
            return False
        product = self.logsource.get("product")
        if product in SOURCE_PRODUCTS and ev.get("source_type") != product:
            return False
        if product in OS_PRODUCTS and ev.get("os") not in (None, product):
            return False
        service = self.logsource.get("service")
        return not (product == "zeek" and service and (ev.get("metadata") or {}).get("zeek_log") != service)

    def matches(self, ev: dict[str, Any], enabled: set[str] | None = None) -> bool:
        """Rule logic AND every attached filter's condition. ``enabled`` limits which filters apply, so a
        filter switched off (globally or for one organization) stops excluding events immediately."""
        if not (self.applies_to(ev) and self.predicate(ev)):
            return False
        return all(f.predicate(ev) for f in self.filters if enabled is None or f.uid in enabled)


@dataclass
class SigmaFilter:
    """A Sigma v2 filter: a condition ANDed onto the referenced rules' own condition."""

    uid: str
    name: str | None
    title: str
    description: str
    status: str
    level: str
    logsource: dict[str, str]
    tags: list[str]
    falsepositives: list[str]
    content: str
    path: str
    predicate: Predicate
    rule_refs: list[str]
    techniques: list[str] = field(default_factory=list)
    generate: bool = False  # filters never raise alerts themselves
    resolved_refs: list[str] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return 0


@dataclass
class SigmaCorrelation:
    uid: str
    name: str | None
    title: str
    description: str
    status: str
    level: str
    type: str  # event_count | value_count | temporal | temporal_ordered
    rule_refs: list[str]
    group_by: list[str]
    timespan_s: int
    condition: dict[str, Any]
    tags: list[str]
    falsepositives: list[str]
    content: str
    path: str
    techniques: list[str]
    generate: bool = False
    resolved_refs: list[str] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return LEVEL_SEVERITY.get(self.level, 50)


@dataclass
class RuleSet:
    rules: list[SigmaRule]
    correlations: list[SigmaCorrelation]
    errors: list[tuple[str, str]]
    filters: list[SigmaFilter] = field(default_factory=list)

    def by_uid(self) -> dict[str, SigmaRule | SigmaCorrelation | SigmaFilter]:
        out: dict[str, SigmaRule | SigmaCorrelation | SigmaFilter] = {r.uid: r for r in self.rules}
        out.update({c.uid: c for c in self.correlations})
        out.update({f.uid: f for f in self.filters})
        return out


def _common(doc: dict[str, Any]) -> dict[str, Any]:
    for req in ("id", "title"):
        if req not in doc:
            raise SigmaCompileError(f"missing required field {req!r}")
    tags = [str(t) for t in doc.get("tags") or []]
    return {
        "uid": str(doc["id"]),
        "name": doc.get("name"),
        "title": str(doc["title"]),
        "description": str(doc.get("description", "")).strip(),
        "status": str(doc.get("status", "experimental")),
        "level": str(doc.get("level", "medium")),
        "tags": tags,
        "falsepositives": [str(x) for x in doc.get("falsepositives") or []],
        "techniques": techniques_from_tags(tags),
    }


def _load_rule(doc: dict[str, Any], content: str, path: str) -> SigmaRule:
    c = _common(doc)
    if c["level"] not in LEVEL_SEVERITY:
        raise SigmaCompileError(f"invalid level {c['level']!r}")
    logsource = {k: str(v).lower() for k, v in (doc.get("logsource") or {}).items()}
    if not logsource:
        raise SigmaCompileError("missing logsource")
    category = logsource.get("category")
    event_types = CATEGORY_EVENT_TYPES.get(category) if category else None
    if category and event_types is None:
        raise SigmaCompileError(f"unsupported logsource category {category!r}")
    return SigmaRule(
        **c,
        logsource=logsource,
        references=[str(x) for x in doc.get("references") or []],
        content=content,
        path=path,
        predicate=compile_detection(doc.get("detection") or {}),
        event_types=event_types,
    )


def _load_correlation(doc: dict[str, Any], content: str, path: str) -> SigmaCorrelation:
    c = _common(doc)
    corr = doc["correlation"]
    ctype = corr.get("type")
    if ctype not in ("event_count", "value_count", "temporal", "temporal_ordered"):
        raise SigmaCompileError(f"unsupported correlation type {ctype!r}")
    refs = corr.get("rules") or []
    if isinstance(refs, str):
        refs = [refs]
    if not refs:
        raise SigmaCompileError("correlation needs at least one referenced rule")
    group_by = [resolve_field(g) for g in corr.get("group-by") or []]
    bad = [g for g in group_by if g not in MATCH_FIELDS]
    if bad:
        raise SigmaCompileError(f"group-by fields not supported for correlation: {bad}")
    cond = corr.get("condition") or {}
    if ctype in ("event_count", "value_count") and not ({"gte", "gt", "lte", "lt", "eq"} & set(cond)):
        raise SigmaCompileError("event/value count correlation needs a numeric condition")
    if ctype == "value_count":
        if "field" not in cond:
            raise SigmaCompileError("value_count needs condition.field")
        cond = {**cond, "field": resolve_field(cond["field"])}
        if cond["field"] not in MATCH_FIELDS:
            raise SigmaCompileError(f"value_count field {cond['field']!r} not supported")
    return SigmaCorrelation(
        **c,
        type=ctype,
        rule_refs=[str(r) for r in refs],
        group_by=group_by,
        timespan_s=parse_timespan(corr.get("timespan", "5m")),
        condition=cond,
        content=content,
        path=path,
        generate=bool(corr.get("generate", False)),
    )


def _load_filter(doc: dict[str, Any], content: str, path: str) -> SigmaFilter:
    c = _common(doc)
    c["level"] = "informational"
    logsource = {k: str(v).lower() for k, v in (doc.get("logsource") or {}).items()}
    if not logsource:
        raise SigmaCompileError("missing logsource")
    spec = doc["filter"]
    if not isinstance(spec, dict):
        raise SigmaCompileError("filter must be a mapping")
    refs = spec.get("rules") or []
    if isinstance(refs, str):
        refs = [refs]
    if not refs:
        raise SigmaCompileError("filter needs at least one referenced rule in filter.rules")
    detection = {k: v for k, v in spec.items() if k != "rules"}
    return SigmaFilter(
        **c,
        logsource=logsource,
        content=content,
        path=path,
        predicate=compile_detection(detection),
        rule_refs=[str(r) for r in refs],
    )


def _logsource_conflict(a: dict[str, str], b: dict[str, str]) -> list[str]:
    return [k for k in ("product", "category", "service") if k in a and k in b and a[k] != b[k]]


def load_rules(directory: Path | None, extra: list[tuple[str, str]] | None = None) -> RuleSet:
    """Load rule files from ``directory`` plus ``extra`` (source label, YAML text) documents, e.g. custom
    rules stored in the database."""
    rules: list[SigmaRule] = []
    correlations: list[SigmaCorrelation] = []
    filters: list[SigmaFilter] = []
    errors: list[tuple[str, str]] = []
    seen: set[str] = set()
    sources: list[tuple[str, str]] = []
    if directory is not None:
        for file in sorted(directory.rglob("*.yml")) + sorted(directory.rglob("*.yaml")):
            sources.append((str(file), file.read_text(encoding="utf-8")))
    sources.extend(extra or [])
    for path, text in sources:
        try:
            docs = [d for d in yaml.safe_load_all(text) if d]
        except yaml.YAMLError as e:
            errors.append((str(path), f"YAML error: {e}"))
            continue
        raw_docs = [d for d in re.split(r"^---\s*$", text, flags=re.MULTILINE) if d.strip()]
        for i, doc in enumerate(docs):
            content = raw_docs[i].strip() if len(raw_docs) == len(docs) else text
            try:
                if not isinstance(doc, dict):
                    raise SigmaCompileError("rule document must be a mapping")
                item: SigmaRule | SigmaCorrelation | SigmaFilter
                if "correlation" in doc:
                    item = _load_correlation(doc, content, str(path))
                elif "filter" in doc:
                    item = _load_filter(doc, content, str(path))
                else:
                    item = _load_rule(doc, content, str(path))
            except (SigmaCompileError, KeyError, TypeError, ValueError, re.error) as e:
                errors.append((f"{path}#{i}", str(e)))
                continue
            if item.uid in seen:
                errors.append((f"{path}#{i}", f"duplicate rule id {item.uid}"))
                continue
            seen.add(item.uid)
            if isinstance(item, SigmaCorrelation):
                correlations.append(item)
            elif isinstance(item, SigmaFilter):
                filters.append(item)
            else:
                rules.append(item)

    # resolve references (by name or id) and apply `generate`
    index: dict[str, str] = {}
    named: list[SigmaRule | SigmaCorrelation] = [*rules, *correlations]
    for r in named:
        index[r.uid] = r.uid
        if r.name:
            index[str(r.name)] = r.uid
    valid: list[SigmaCorrelation] = []
    referenced_without_generate: set[str] = set()
    for c in correlations:
        missing = [ref for ref in c.rule_refs if ref not in index]
        if missing:
            errors.append((c.path, f"correlation {c.uid} references unknown rules {missing}"))
            continue
        c.resolved_refs = [index[ref] for ref in c.rule_refs]
        if not c.generate:
            referenced_without_generate.update(c.resolved_refs)
        valid.append(c)
    for r in rules:
        if r.uid in referenced_without_generate:
            r.generate = False
    return RuleSet(
        rules=rules,
        correlations=_toposort(valid, errors),
        errors=errors,
        filters=_attach_filters(filters, rules, index, errors),
    )


def _attach_filters(
    filters: list[SigmaFilter], rules: list[SigmaRule], index: dict[str, str], errors: list[tuple[str, str]]
) -> list[SigmaFilter]:
    """Resolve each filter's rule references and attach it to those detection rules. A filter that cannot
    be applied exactly as written is rejected as a whole rather than silently applied to only some rules."""
    by_uid = {r.uid: r for r in rules}
    valid: list[SigmaFilter] = []
    for f in filters:
        missing = [ref for ref in f.rule_refs if ref not in index]
        if missing:
            errors.append((f.path, f"filter {f.uid} references unknown rules {missing}"))
            continue
        targets = [by_uid.get(index[ref]) for ref in f.rule_refs]
        if any(t is None for t in targets):
            errors.append((f.path, f"filter {f.uid} can only reference detection rules, not correlations"))
            continue
        conflicts = [
            (t.uid, k) for t in targets if t is not None for k in _logsource_conflict(f.logsource, t.logsource)
        ]
        if conflicts:
            errors.append((f.path, f"filter {f.uid} logsource does not match rule(s): {conflicts}"))
            continue
        f.resolved_refs = sorted({t.uid for t in targets if t is not None})
        for t in targets:
            if t is not None and f not in t.filters:
                t.filters.append(f)
        valid.append(f)
    return valid


def _toposort(corrs: list[SigmaCorrelation], errors: list[tuple[str, str]]) -> list[SigmaCorrelation]:
    """Order correlations so chained ones (correlation referencing a correlation) evaluate after deps."""
    by_uid = {c.uid: c for c in corrs}
    out: list[SigmaCorrelation] = []
    state: dict[str, int] = {}

    def visit(c: SigmaCorrelation) -> bool:
        st = state.get(c.uid)
        if st == 2:
            return True
        if st == 1:
            errors.append((c.path, f"correlation cycle through {c.uid}"))
            return False
        state[c.uid] = 1
        for ref in c.resolved_refs:
            if ref in by_uid and not visit(by_uid[ref]):
                return False
        state[c.uid] = 2
        out.append(c)
        return True

    for c in corrs:
        visit(c)
    return out


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()
