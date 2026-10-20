"""Telemetry sanitization before anything reaches the LLM: secret redaction and prompt-injection flagging.

Security telemetry is attacker-influenced. We never *execute* anything the model says, but we also
(1) redact credentials so they can't leak into prompts or outputs, and (2) flag instruction-like text
so analysts can see that an event tried to talk to the AI.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "[REDACTED-PRIVATE-KEY]",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED-JWT]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-SLACK-TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 [REDACTED]"),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1=[REDACTED]",
    ),
    (re.compile(r"(?i)(-p(?:assword)?\s+)(\"[^\"]+\"|'[^']+'|\S+)(?=.*\b(-u|--user|user)\b)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)"), r"\1[REDACTED]\3"),
    (re.compile(r"(?i)\b(ConvertTo-SecureString\s+)(\"[^\"]+\"|'[^']+')"), r"\1[REDACTED]"),
]

_INJECTION_PATTERNS = [
    re.compile(p, re.I)
    for p in (
        r"ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts?|messages?)",
        r"disregard (all |the )?(previous|prior|above|system)",
        r"\b(you are|act as|pretend to be) (now )?(an?|the) ",
        r"\bsystem prompt\b",
        r"\bnew instructions?\b",
        r"<\|?(im_start|im_end|system|assistant|user)\|?>",
        r"\[/?(INST|SYS)\]",
        r"###\s*(instruction|system|assistant)",
        r"\b(reveal|print|show|output) (the |your )?(secrets?|system prompt|instructions|api key)",
        r"\bmark (this|the) (incident|event|alert) as (benign|false positive|resolved)",
        r"\b(set|change) (the )?(risk|severity|confidence) (score )?to\b",
    )
]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")


def redact(text: str) -> str:
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text


def clean_text(value: str, limit: int = 400) -> str:
    """Normalize unicode, drop control / bidi-override characters, redact secrets, truncate."""
    v = unicodedata.normalize("NFKC", value)
    v = _CONTROL.sub("", v)
    v = redact(v)
    if len(v) > limit:
        v = v[:limit] + "…[truncated]"
    return v


def injection_hits(value: str) -> list[str]:
    return [p.pattern for p in _INJECTION_PATTERNS if p.search(value)]


WITHHELD = "[withheld: this field contained instructions aimed at AI tools — possible prompt injection by the attacker]"


def sanitize_record(rec: dict[str, Any], ref: str, flags: list[dict[str, Any]], limit: int = 400) -> dict[str, Any]:
    """Clean one record for the model. Fields containing instruction-like text are withheld entirely (the
    analyst still sees the original in the UI): small models can be swayed even by quoted instructions."""
    out: dict[str, Any] = {}
    for k, v in rec.items():
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, str):
            hits = injection_hits(v)
            if hits:
                flags.append({"ref": ref, "field": k, "patterns": hits[:3]})
                out[k] = WITHHELD
                continue
            out[k] = clean_text(v, limit)
        elif isinstance(v, list):
            cleaned: list[Any] = []
            for x in v[:10]:
                if isinstance(x, str):
                    hits = injection_hits(x)
                    if hits:
                        flags.append({"ref": ref, "field": k, "patterns": hits[:3]})
                        cleaned.append(WITHHELD)
                        continue
                    cleaned.append(clean_text(x, 120))
                elif isinstance(x, dict):
                    cleaned.append(sanitize_record(x, ref, flags, limit=200))
                elif isinstance(x, list):
                    cleaned.append(sanitize_record({"_": x}, ref, flags, limit=200)["_"])
                else:
                    cleaned.append(x)
            out[k] = cleaned
        elif isinstance(v, dict):
            out[k] = sanitize_record(v, ref, flags, limit=200)
        else:
            out[k] = v
    return out
