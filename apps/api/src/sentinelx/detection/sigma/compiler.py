"""Compile Sigma detection logic into fast Python predicates.

Implements the parts of the Sigma specification (v2) that SentinelX rules use:

* search identifiers as maps (AND), lists of maps (OR) and keyword lists
* value lists (OR, or AND with ``|all``), ``null`` values, wildcards ``*``/``?`` with ``\\`` escaping
* modifiers: contains, startswith, endswith, all, re (+ i/m/s), cidr, gt/gte/lt/lte, exists,
  windash, cased
* conditions: and / or / not / parentheses / ``1 of x*`` / ``any of`` / ``all of x*`` / ``them``

Unsupported constructs raise ``SigmaCompileError`` so a rule is rejected loudly at load time
instead of silently never matching.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import itertools
import re
from collections.abc import Callable
from typing import Any

from sentinelx.detection.sigma.fields import get_value, resolve_field

Event = dict[str, Any]
Predicate = Callable[[Event], bool]

SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "re",
    "i",
    "m",
    "s",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "windash",
    "cased",
}
KEYWORD_FIELDS = ("process_command_line", "url", "domain", "rule_name", "summary", "file_path")


class SigmaCompileError(ValueError):
    pass


def _to_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _has_wildcard(s: str) -> bool:
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c in "*?":
            return True
        i += 1
    return False


def _wildcard_to_regex(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _unescape(s: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", s)


_WINDASH = "-/–—―"


def _windash_variants(s: str) -> list[str]:
    """Rule and event may each use any Windows switch-dash character independently at each
    switch position (``-foo -bar``, ``/foo /bar``, ``-foo/bar``, ...) - generate every combination."""
    positions = [i for i, c in enumerate(s) if c in _WINDASH]
    if not positions:
        return [s]
    if len(positions) > 6:  # cap combinatorial blowup; fall back to same-char variants
        return sorted({s.translate(str.maketrans({c: d for c in _WINDASH})) for d in _WINDASH})
    chars = list(s)
    out = set()
    for combo in itertools.product(_WINDASH, repeat=len(positions)):
        for pos, d in zip(positions, combo, strict=True):
            chars[pos] = d
        out.add("".join(chars))
    return sorted(out)


def _string_matcher(value: str, mods: set[str]) -> Callable[[str], bool]:
    cased = "cased" in mods
    if "contains" in mods:
        value = f"*{value}*" if not (value.startswith("*") and value.endswith("*")) else value
    elif "startswith" in mods:
        value = value if value.endswith("*") else f"{value}*"
    elif "endswith" in mods:
        value = value if value.startswith("*") else f"*{value}"

    if _has_wildcard(value):
        core = value
        # fast paths for the very common *x*, x*, *x shapes without inner wildcards
        inner = core.strip("*")
        if not _has_wildcard(inner):
            needle = _unescape(inner)
            if not cased:
                needle = needle.lower()
            if core.startswith("*") and core.endswith("*") and len(core) > 1:
                return (lambda h: needle in h) if cased else (lambda h: needle in h.lower())
            if core.endswith("*"):
                return (lambda h: h.startswith(needle)) if cased else (lambda h: h.lower().startswith(needle))
            if core.startswith("*"):
                return (lambda h: h.endswith(needle)) if cased else (lambda h: h.lower().endswith(needle))
        rx = re.compile("^" + _wildcard_to_regex(core) + "$", 0 if cased else re.IGNORECASE | re.DOTALL)
        return lambda h: rx.match(h) is not None
    exact = _unescape(value)
    if cased:
        return lambda h: h == exact
    exact_l = exact.lower()
    return lambda h: h.lower() == exact_l


def _value_matcher(raw: Any, mods: set[str]) -> Callable[[Any], bool]:
    """Matcher for a single Sigma value against a single event field value."""
    if raw is None:
        return lambda v: v is None or v == ""
    if "exists" in mods:
        want = bool(raw)
        return lambda v: (v is not None and v != "") == want
    if mods & {"gt", "gte", "lt", "lte"}:
        try:
            n = float(raw)
        except (TypeError, ValueError) as e:
            raise SigmaCompileError(f"numeric modifier needs a number, got {raw!r}") from e
        op = next(m for m in ("gte", "gt", "lte", "lt") if m in mods)

        def num(v: Any) -> bool:
            try:
                x = float(v)
            except (TypeError, ValueError):
                return False
            return {"gt": x > n, "gte": x >= n, "lt": x < n, "lte": x <= n}[op]

        return num
    if "cidr" in mods:
        net = ipaddress.ip_network(str(raw), strict=False)

        def in_net(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return in_net
    if "re" in mods:
        flags = (
            (re.IGNORECASE if "i" in mods else 0)
            | (re.MULTILINE if "m" in mods else 0)
            | (re.DOTALL if "s" in mods else 0)
        )
        rx = re.compile(str(raw), flags)
        return lambda v: v is not None and rx.search(_to_str(v)) is not None
    if isinstance(raw, bool | int | float) and not mods & {"contains", "startswith", "endswith"}:
        target = _to_str(raw).lower()
        return lambda v: v is not None and _to_str(v).lower() == target
    sval = _to_str(raw)
    variants = _windash_variants(sval) if "windash" in mods else [sval]
    matchers = [_string_matcher(x, mods) for x in variants]

    def m(v: Any) -> bool:
        if v is None:
            return False
        s = _to_str(v)
        return any(f(s) for f in matchers)

    return m


def _field_predicate(key: str, values: Any) -> Predicate:
    parts = key.split("|")
    field = resolve_field(parts[0]) if parts[0] else ""
    mods = set(parts[1:])
    unknown = mods - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaCompileError(f"unsupported modifier(s) {sorted(unknown)} on field {parts[0]!r}")
    vals = values if isinstance(values, list) else [values]
    if not vals:
        raise SigmaCompileError(f"empty value list for {key}")
    matchers = [_value_matcher(v, mods) for v in vals]
    need_all = "all" in mods

    if not field:  # keyword-style field-less value under a map

        def kw(ev: Event) -> bool:
            hay = [ev.get(f) for f in KEYWORD_FIELDS]
            res = [any(m(h) for h in hay if h is not None) for m in matchers]
            return all(res) if need_all else any(res)

        return kw

    def pred(ev: Event) -> bool:
        v = get_value(ev, field)
        cands = v if isinstance(v, list) else [v]
        if need_all:
            return all(any(m(c) for c in cands) for m in matchers)
        return any(m(c) for c in cands for m in matchers)

    return pred


def compile_search(definition: Any) -> Predicate:
    if isinstance(definition, dict):
        preds = [_field_predicate(k, v) for k, v in definition.items()]
        return lambda ev: all(p(ev) for p in preds)
    if isinstance(definition, list):
        if all(isinstance(x, dict) for x in definition):
            preds = [compile_search(x) for x in definition]
            return lambda ev: any(p(ev) for p in preds)
        if all(isinstance(x, str | int | float) for x in definition):
            kw = _field_predicate("|contains", [str(x) for x in definition])
            return kw
    raise SigmaCompileError(f"unsupported search identifier definition: {type(definition).__name__}")


# Condition grammar

_TOKEN_RE = re.compile(
    r"\s*(\(|\)|\b1\s+of\b|\bany\s+of\b|\ball\s+of\b|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*\-.]+)", re.IGNORECASE
)


def _tokenize(cond: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    while pos < len(cond):
        if cond[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(cond, pos)
        if not m or m.end() == pos:
            raise SigmaCompileError(f"cannot parse condition near: {cond[pos:]!r}")
        tok = re.sub(r"\s+", " ", m.group(1).strip())
        tokens.append(tok.lower() if tok.lower() in {"and", "or", "not", "1 of", "any of", "all of"} else tok)
        pos = m.end()
    return tokens


class _ConditionParser:
    def __init__(self, tokens: list[str], searches: dict[str, Predicate]):
        self.t = tokens
        self.i = 0
        self.searches = searches

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaCompileError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self) -> Predicate:
        p = self.or_expr()
        if self.peek() is not None:
            raise SigmaCompileError(f"unexpected token {self.peek()!r}")
        return p

    def or_expr(self) -> Predicate:
        left = self.and_expr()
        while self.peek() == "or":
            self.take()
            right = self.and_expr()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    def and_expr(self) -> Predicate:
        left = self.not_expr()
        while self.peek() == "and":
            self.take()
            right = self.not_expr()
            left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, right)
        return left

    def not_expr(self) -> Predicate:
        if self.peek() == "not":
            self.take()
            inner = self.not_expr()
            return lambda ev: not inner(ev)
        return self.atom()

    def _select(self, pattern: str) -> list[Predicate]:
        if pattern == "them":
            names = [n for n in self.searches if not n.startswith("_")]
        else:
            names = [n for n in self.searches if fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise SigmaCompileError(f"no search identifiers match {pattern!r}")
        return [self.searches[n] for n in names]

    def atom(self) -> Predicate:
        tok = self.take()
        if tok == "(":
            p = self.or_expr()
            if self.take() != ")":
                raise SigmaCompileError("missing closing parenthesis")
            return p
        if tok in ("1 of", "any of"):
            preds = self._select(self.take())
            return lambda ev: any(p(ev) for p in preds)
        if tok == "all of":
            preds = self._select(self.take())
            return lambda ev: all(p(ev) for p in preds)
        if tok in self.searches:
            return self.searches[tok]
        raise SigmaCompileError(f"unknown search identifier {tok!r}")


def compile_detection(detection: dict[str, Any]) -> Predicate:
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaCompileError("detection must be a mapping with a condition")
    cond = detection["condition"]
    if isinstance(cond, list):
        if len(cond) != 1:
            raise SigmaCompileError("multiple conditions are deprecated in Sigma v2; use 'or'")
        cond = cond[0]
    if "|" in str(cond):
        raise SigmaCompileError("aggregation expressions ('| count()') are deprecated; use correlation rules")
    searches = {k: compile_search(v) for k, v in detection.items() if k not in ("condition", "timeframe")}
    return _ConditionParser(_tokenize(str(cond)), searches).parse()
