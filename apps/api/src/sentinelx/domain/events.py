"""Canonical SentinelX event model, deterministic identifiers and helpers."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SourceType = Literal["wazuh", "suricata", "zeek", "sentinelx", "other"]
EventType = Literal[
    "authentication", "process", "network", "dns", "http", "tls", "file", "iam", "alert", "ssh", "other"
]

# Namespace for deterministic event ids: uuid5(NS, tenant|source|native-key)
EVENT_NAMESPACE = uuid.UUID("6f1c2f9e-7d0a-4f6e-9b8a-5e2b8c3d1a10")

MAX_TEXT = 8192


class CanonicalEvent(BaseModel):
    """The one normalized model all telemetry is converted into (ADR-004)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: uuid.UUID
    tenant_id: uuid.UUID
    timestamp: datetime
    source_type: SourceType
    event_type: EventType
    event_action: str | None = None
    outcome: Literal["success", "failure", "unknown"] | None = None
    severity: int = Field(0, ge=0, le=100)
    hostname: str | None = Field(None, max_length=255)
    host_ip: str | None = None
    os: str | None = Field(None, max_length=60)
    username: str | None = Field(None, max_length=255)
    src_ip: str | None = None
    src_port: int | None = Field(None, ge=0, le=65535)
    dest_ip: str | None = None
    dest_port: int | None = Field(None, ge=0, le=65535)
    protocol: str | None = Field(None, max_length=32)
    bytes_out: int | None = Field(None, ge=0)
    bytes_in: int | None = Field(None, ge=0)
    process_name: str | None = Field(None, max_length=255)
    process_path: str | None = Field(None, max_length=MAX_TEXT)
    process_command_line: str | None = Field(None, max_length=MAX_TEXT)
    parent_process_name: str | None = Field(None, max_length=255)
    parent_process_path: str | None = Field(None, max_length=MAX_TEXT)
    domain: str | None = Field(None, max_length=512)
    url: str | None = Field(None, max_length=MAX_TEXT)
    file_path: str | None = Field(None, max_length=MAX_TEXT)
    file_hash: str | None = Field(None, max_length=128)
    event_category: str | None = Field(None, max_length=120)
    rule_id: str | None = Field(None, max_length=64)
    rule_name: str | None = Field(None, max_length=1024)
    mitre_techniques: list[str] = Field(default_factory=list)
    summary: str = ""
    raw_event: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)

    @field_validator("src_ip", "dest_ip", "host_ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        if v in (None, "", "-"):
            return None
        return str(ipaddress.ip_address(v.strip().split("%")[0]))

    @field_validator("username")
    @classmethod
    def _user(cls, v: str | None) -> str | None:
        if v in (None, "", "-", "(unknown)"):
            return None
        return v.strip().lower()

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str | None) -> str | None:
        if not v:
            return None
        return v.strip().rstrip(".").lower()

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        return v.strip() if v else None

    @field_validator("file_hash")
    @classmethod
    def _hash(cls, v: str | None) -> str | None:
        return v.strip().lower() if v else None

    @field_validator("process_command_line", "process_path", "url", "file_path", "rule_name")
    @classmethod
    def _truncate(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return v[:MAX_TEXT]

    def to_row(self) -> dict[str, Any]:
        d = self.model_dump()
        d["id"] = d.pop("event_id")
        d["event_metadata"] = d.pop("metadata")
        return d


def deterministic_event_id(tenant_id: uuid.UUID, source: str, native_key: str) -> uuid.UUID:
    return uuid.uuid5(EVENT_NAMESPACE, f"{tenant_id}|{source}|{native_key}")


def parse_timestamp(value: Any) -> datetime:
    """Parse ISO-8601, Wazuh ``+0000`` offsets and epoch seconds (Zeek)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        s = value.strip()
        try:
            return datetime.fromtimestamp(float(s), tz=UTC)
        except ValueError:
            pass
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # Wazuh/Suricata emit +0000 (no colon)
        if len(s) > 5 and s[-5] in "+-" and s[-4:].isdigit() and s[-3] != ":":
            s = s[:-2] + ":" + s[-2:]
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    raise ValueError(f"unsupported timestamp: {value!r}")


# "Internal" = address space an organization uses for its own hosts. Deliberately explicit: Python's
# ``is_private`` also covers RFC 5737 documentation ranges, which would hide internet-facing activity.
_INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
]


@lru_cache(maxsize=65536)
def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL_NETS if n.version == a.version)


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1] or None


def extract_indicators(ev: CanonicalEvent | dict[str, Any]) -> list[tuple[str, str]]:
    """Observable indicators in an event worth checking against threat intel: (type, value)."""
    get = ev.get if isinstance(ev, dict) else lambda k: getattr(ev, k, None)
    out: list[tuple[str, str]] = []
    for f in ("src_ip", "dest_ip"):
        v = get(f)
        if v and not is_private_ip(v):
            out.append(("ip", v))
    if get("domain"):
        out.append(("domain", get("domain")))
    if get("file_hash"):
        out.append(("hash", get("file_hash")))
    if get("url") and str(get("url")).startswith(("http://", "https://")):
        out.append(("url", get("url")))
    return out


def summarize(ev: CanonicalEvent) -> str:
    """Deterministic human-readable one-line description used in timelines."""
    who = f" for {ev.username}" if ev.username else ""
    on = f" on {ev.hostname}" if ev.hostname else ""
    src = f" from {ev.src_ip}" if ev.src_ip else ""
    a = ev.event_action or ""
    if ev.event_type == "authentication" or ev.event_type == "ssh":
        if ev.outcome == "failure":
            return f"Failed login{who}{src}{on}"
        if ev.outcome == "success":
            return f"Successful login{who}{src}{on}"
        return f"Authentication event{who}{src}{on}"
    if ev.event_type == "process":
        cmd = (ev.process_command_line or ev.process_name or "process")[:160]
        by = f" by {ev.username}" if ev.username else ""
        return f"Process started{on}{by}: {cmd}"
    if ev.event_type == "dns":
        return f"DNS query for {ev.domain}{' from ' + ev.src_ip if ev.src_ip else ''}"
    if ev.event_type == "http":
        return f"HTTP {ev.metadata.get('method', 'request')} {ev.domain or ev.dest_ip or ''}{ev.url or ''}"[:200]
    if ev.event_type == "tls":
        return f"TLS connection to {ev.domain or ev.dest_ip}"
    if ev.event_type == "network":
        size = f" ({ev.bytes_out:,} bytes out)" if ev.bytes_out else ""
        return (
            f"Connection {ev.src_ip}:{ev.src_port or ''} → {ev.dest_ip}:{ev.dest_port or ''}/{ev.protocol or ''}{size}"
        )
    if ev.event_type == "file":
        return f"File {a or 'changed'}{on}: {ev.file_path}"
    if ev.event_type == "iam":
        target = ev.metadata.get("target_user") or ev.username or ""
        group = ev.metadata.get("group")
        if a == "group_member_added":
            return f"Account {target} added to group {group}{on}"
        if a == "user_created":
            return f"New account created: {target}{on}"
        return f"Account change ({a}){on}"
    if ev.event_type == "alert":
        return f"{ev.source_type.capitalize()} alert: {ev.rule_name or ev.event_category or 'alert'}"
    return ev.rule_name or ev.event_category or f"{ev.source_type} {ev.event_type} event"
